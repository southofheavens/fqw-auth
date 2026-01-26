#include <handlers/LoginHandler.h>
#include <Utils.h>

namespace FQW::Auth
{

void LoginHandler::handleRequest(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res)
try
{
    if (req.getContentType().find("application/json") == std::string::npos) {
        throw Auth::Utils::HandlersException("Content-Type must be application/json", 
            Poco::Net::HTTPResponse::HTTPStatus::HTTP_BAD_REQUEST);
    }

    if (req.getContentLength() == 0) {
        throw Auth::Utils::HandlersException("Empty request body", 
            Poco::Net::HTTPResponse::HTTPStatus::HTTP_BAD_REQUEST);
    }

    /* ua читаем только из заголовка */
    if (not req.has("User-Agent")) {
        throw Auth::Utils::HandlersException(std::format("User-Agent header was not received"), 
            Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
    }
    std::string userAgent = req.get("User-Agent");

    /* Если заголовок Fingerprint пуст, пытаемся считать fingerprint из тела запроса */
    Poco::JSON::Object::Ptr jsonObject = Auth::Utils::extractJsonObjectFromRequest(req);
    std::string fingerprint;
    if (not req.has("X-Fingerprint"))
    {
        if (not jsonObject->has("fingerprint")) {
            throw Auth::Utils::HandlersException(std::format("Expected fingerprint from json body or X-Fingerprint header"), 
                Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
        }
        fingerprint = (jsonObject->get("fingerprint")).extract<std::string>();
    }
    else {
        fingerprint = req.get("X-Fingerprint");
    }

    std::map<std::string, Poco::Dynamic::Var> clientContext = 
    {
        {"login", {}},
        {"password", {}}
    };
    Auth::Utils::fillRequiredFieldsFromJson(jsonObject, clientContext);

    /**
     * Смотрим, есть ли пользователь с таким логином && правильно ли введён пароль,
     * если пользователь с таким логином существует
     */
    Poco::Data::Session session = sessionPool_.get();
    Poco::Data::Statement stmt(session);
        
    std::string hashedPassword, userRole;
    uint64_t userId;
    stmt << "SELECT password, role, id FROM users WHERE login = $1",
        Poco::Data::Keywords::use(clientContext["login"]),
        Poco::Data::Keywords::into(hashedPassword),
        Poco::Data::Keywords::into(userRole),
        Poco::Data::Keywords::into(userId);

    if (stmt.execute() == 0) {
        throw Auth::Utils::HandlersException("Incorrect login or password", Poco::Net::HTTPResponse::HTTPStatus::HTTP_BAD_REQUEST);
    }

    if (not Auth::Utils::verifyPassword(clientContext["password"].toString(), hashedPassword)) {
        throw Auth::Utils::HandlersException("Incorrect login or password", Poco::Net::HTTPResponse::HTTPStatus::HTTP_BAD_REQUEST);
    }

    /* Проверяем, существует ли для данных UA и fingerprint refresh-токен */
    if (std::optional<std::string> potentionalRefreshHash
            = Auth::Utils::getHashRefreshTokenByUserData(redisClient_, userId, fingerprint, userAgent);
        potentionalRefreshHash.has_value()) 
    {
        // Удаляем хэш refresh-токена из Redis (т.к. дальше для данных UA и fingerprint
        // будет создан новый refresh-токен, а уже существующий мы не можем использовать
        // потому, что в Redis хранится хэш, а не сам токен)
        Auth::Utils::deleteRefreshFromRedis(redisClient_, potentionalRefreshHash.value(), userId);
    }

    /**
     * Формируем полезную нагрузку для access-токена
     */
    Devkit::Tokens::Payload jwtPayload =
    {
        .sub = userId,
        .role = userRole,
        .exp = std::chrono::duration_cast<std::chrono::seconds>((std::chrono::system_clock::now() + 
            Auth::Utils::access_token_validity_period).time_since_epoch())
    };

    /* Генерируем access и refresh токены */
    std::string accessToken = Auth::Utils::createAccessToken(jwtPayload);
    std::string refreshToken = Auth::Utils::createRefreshToken();

    Auth::Utils::addRefreshToRedis(redisClient_, refreshToken, userId, fingerprint, userAgent);

    Poco::JSON::Object resultJson;
    resultJson.set("access_token", accessToken);
    resultJson.set("refresh_token", refreshToken);

    Poco::Net::HTTPCookie cookie("X-Refresh-token", refreshToken);
    cookie.setHttpOnly(true);
    cookie.setSecure(true);
    cookie.setPath("/"); // TODO наверное не стоит делать /
    cookie.setSameSite(Poco::Net::HTTPCookie::SAME_SITE_STRICT);

    res.addCookie(cookie);

    resultJson.stringify(res.send());
}
catch (const Auth::Utils::HandlersException & e)
{
    res.setStatusAndReason(e.status());
    Auth::Utils::sendJsonResponse(res, "error", e.what());
}
catch (...)
{
    res.setStatusAndReason(Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
    Auth::Utils::sendJsonResponse(res, "error", "Internal server error");
}

} // namespace FQW::Auth 
