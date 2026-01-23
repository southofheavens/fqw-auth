#include <iostream>
#include <format>
#include <unordered_set>
#include <chrono>

#include <Handlers.h>
#include <Utils.h>
#include <fqw-devkit/lib/Tokens.h>

#include <sodium.h>
#include <Poco/Data/Session.h>
#include <Poco/Data/RecordSet.h>
#include <Poco/Data/Statement.h>
#include <Poco/StreamCopier.h>
#include <Poco/JSON/Parser.h>
#include <Poco/JSON/Object.h>
#include <Poco/URI.h>
#include <Poco/JWT/JWT.h>
#include <Poco/JWT/Signer.h>
#include <Poco/JWT/Token.h>
#include <Poco/Timestamp.h>
#include <Poco/UUID.h>
#include <Poco/UUIDGenerator.h>
#include <Poco/SHA2Engine.h>
#include <Poco/DigestStream.h>
#include <Poco/Redis/Command.h>

namespace FQW::Auth::Handlers
{

namespace
{

class HandlersException;

class HandlersException : public std::exception 
{
public:
    HandlersException(const std::string & errorMessage, Poco::Net::HTTPResponse::HTTPStatus httpStatus) 
        : errorMessage_{errorMessage}, httpStatus_{httpStatus} {}

    const char * what() const noexcept final 
    { return errorMessage_.c_str(); }

    Poco::Net::HTTPResponse::HTTPStatus status() const noexcept
    { return httpStatus_; }

private:
    std::string                         errorMessage_;
    Poco::Net::HTTPResponse::HTTPStatus httpStatus_;
};

constexpr uint8_t              refresh_tokens_limit          = 5;
constexpr std::chrono::seconds access_token_validity_period  = std::chrono::seconds(15 * 60);
constexpr std::chrono::seconds refresh_token_validity_period = std::chrono::seconds(30 * 24 * 60 * 60);
const     std::string          key_                          = "secret_key";

void sendJsonResponse(Poco::Net::HTTPServerResponse& res,
    const std::string& status, const std::string& message)
{
    Poco::JSON::Object json;
    json.set("status", status);
    json.set("message", message);

    std::ostream& out = res.send();
    json.stringify(out);
}

/**
 * @brief Хэширует пароль используя Argon2 алгоритм
 * @param password Пароль для хэширования
 * @return std::string Хэшированный пароль в формате libsodium
 * @throw std::runtime_error если хэширование не удалось
 */
std::string hashPassword(const std::string& password)
{
    char hashed[crypto_pwhash_STRBYTES];
    
    if (crypto_pwhash_str(hashed, password.c_str(), password.length(), 
        crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE) != 0) 
    { 
        throw std::runtime_error("Password hashing failed - possibly out of memory");
    }
    
    return std::string(hashed);
}

/**
 * @brief Сравнивает пароль с хэшем
 * @param password Пароль для проверки
 * @param hash Хэш из базы данных
 * @return bool true если пароль верный, false если неверный
 * @throw std::runtime_error если проверка не удалась (системная ошибка)
 */
bool verifyPassword(const std::string& password, const std::string& hash)
{    
    int result = crypto_pwhash_str_verify(hash.c_str(), password.c_str(), password.length());
    
    if (result == 0) {
        return true;
    } 
    else if (result == -1) {
        return false;
    } 
    else {
        throw std::runtime_error("Password verification system error");
    }
}

/**
 * @brief Генерирует access токен, который представляет из себя JWT
 * @param p Полезная нагрузка
 * @return Токен
 */
std::string createAccessToken(const FQW::Devkit::Tokens::Payload& p)
{
    Poco::JWT::Token token;

    token.setSubject(std::to_string(p.sub));

    token.payload().set("role", p.role);

    Poco::Timestamp expires = static_cast<Poco::Timestamp::TimeVal>(
        std::chrono::duration_cast<std::chrono::microseconds>(p.exp).count()
    );
    token.setExpiration(expires);
    
    Poco::JWT::Signer signer(key_);
    return signer.sign(token, Poco::JWT::Signer::ALGO_HS256);
}

/**
 * @brief Генерирует refresh токен, представляющий из себя UUID
 * @return Токен
 */
std::string createRefreshToken()
{
    Poco::UUID uuid = Poco::UUIDGenerator::defaultGenerator().createRandom();
    return uuid.toString();
}

std::string hashRefreshToken(const std::string & token)
{
    Poco::SHA2Engine sha256(Poco::SHA2Engine::SHA_256);

    sha256.update(token);

    const Poco::DigestEngine::Digest & digest = sha256.digest();

    return Poco::DigestEngine::digestToHex(digest);
}

bool verifyRefreshToken(const std::string & token, const std::string & hash)
{
    Poco::SHA2Engine sha256(Poco::SHA2Engine::SHA_256);

    sha256.update(token);

    const Poco::DigestEngine::Digest & digest = sha256.digest();

    std::string hex_token = Poco::DigestEngine::digestToHex(digest);

    return (hex_token == hash);
}

/**
 * Удаляет хэш рефреш-токена из Redis (из ZSET + из HSET)
 */
void deleteRefreshFromRedis(Poco::Redis::Client & redisClient, std::string & hashedRefreshToken, uint64_t userId)
{
    Poco::Redis::Array cmd;
    cmd << "ZREM" << std::format("user_rtk:{}", userId) << hashedRefreshToken;
    Poco::Int64 resultOfCmd = redisClient.execute<Poco::Int64>(cmd);

    cmd.clear();
    cmd << "DEL" << std::format("rtk:{}", hashedRefreshToken);
    resultOfCmd = redisClient.execute<Poco::Int64>(cmd);
}

/**
 * Хэширует рефреш-токен и добавляет хэш в Redis (в ZSET + в HSET). Если превышен лимит рефреш-токенов на
 * пользователя, то удаляет самый старый рефреш-токен 
 */
void addRefreshToRedis(Poco::Redis::Client & redisClient, std::string & refreshToken, uint64_t userId,
    std::string & fingerprint, std::string & userAgent)
{
    Poco::Redis::Array cmd;
    cmd << "ZCARD" << std::format("user_rtk:{}", userId);
    Poco::Int64 resultOfCmd = redisClient.execute<Poco::Int64>(cmd);
    if (resultOfCmd == refresh_tokens_limit)
    /* Удаляем самый старый refresh-токен */
    {
        /**
         * Достаем из ZSET значение с минимальным score. Им является хэш рефреш-токена, который
         * необходимо удалить из БД
         **/
        cmd.clear();
        cmd << "ZRANGE" << std::format("user_rtk:{}", userId) << "0" << "0";
        Poco::Redis::Array resultOfZrange = redisClient.execute<Poco::Redis::Array>(cmd);
        Poco::Redis::BulkString bulkStringResult = resultOfZrange.get<Poco::Redis::BulkString>(0);
        
        /* Удаляем HSET с хэшом самого старого рефреш-токена пользователя с id == userId */
        cmd.clear();
        cmd << "DEL" << std::format("rtk:{}", bulkStringResult.value());
        resultOfCmd = redisClient.execute<Poco::Int64>(cmd);

        /* Удаляем из ZSET значение с минимальным score */
        cmd.clear();
        cmd << "ZPOPMIN" << std::format("user_rtk:{}", userId);
        Poco::Redis::Array resultOfPop = redisClient.execute<Poco::Redis::Array>(cmd);
    }

    /* Добавляем хэш рефреш-токена в ZSET */
    std::string hashedRefresh = hashRefreshToken(refreshToken);
    cmd.clear();
    cmd << "ZADD" << std::format("user_rtk:{}", userId) 
        << std::to_string(std::chrono::system_clock::now().time_since_epoch().count())
        << hashedRefresh;
    resultOfCmd = redisClient.execute<Poco::Int64>(cmd);

    /* Обновляем TTL для ZSET */
    cmd.clear();
    cmd << "EXPIRE" << std::format("user_rtk:{}", userId) << std::to_string(refresh_token_validity_period.count());
    resultOfCmd = redisClient.execute<Poco::Int64>(cmd);

    /* Добавляем HSET с хэшом только что созданного рефреш-токена */
    cmd.clear();
    cmd << "HSET" << std::format("rtk:{}", hashedRefresh) << "ua" << userAgent
        << "fingerprint" << fingerprint << "user_id" << std::to_string(userId) /* << "ip" << ipAddress */;
    resultOfCmd = redisClient.execute<Poco::Int64>(cmd);

    /* Обновляем TTL для HSET */
    cmd.clear();
    cmd << "EXPIRE" << std::format("rtk:{}", hashedRefresh) << std::to_string(refresh_token_validity_period.count());
    resultOfCmd = redisClient.execute<Poco::Int64>(cmd);
}

void fillRequiredFieldsFromJson(Poco::JSON::Object::Ptr jsonObject, std::unordered_map<std::string, Poco::Dynamic::Var> & pairs)
{
    for (auto & [key, value] : pairs)
    {
        if (not jsonObject->has(key)) {
            throw HandlersException(std::format("Field {} was not received", key), 
                Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
        }
        value = jsonObject->get(key);
    }
}

void tryFillRequiredFieldsFromJson(Poco::JSON::Object::Ptr jsonObject, std::unordered_map<std::string, Poco::Dynamic::Var> & pairs)
{
    for (auto & [key, value] : pairs)
    {
        if (jsonObject->has(key)) {
            value = jsonObject->get(key);
        }
    }
}

void fillRequiredFieldsFromHeaders(Poco::Net::HTTPServerRequest & req, std::unordered_map<std::string, std::string> & pairs)
{
    for (auto & [key, value] : pairs)
    {
        if (not req.has(key)) {
            throw HandlersException(std::format("Header {} was not received", key), 
                Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
        }
        value = req.get(key);
    }
}

void tryFillRequiredFieldsFromHeaders(Poco::Net::HTTPServerRequest & req, std::unordered_map<std::string, std::string> & pairs)
{
    for (auto & [key, value] : pairs)
    {
        if (req.has(key)) {
            value = req.get(key);
        }
    }
}

Poco::JSON::Object::Ptr extractJsonObjectFromRequest(Poco::Net::HTTPServerRequest & req)
{    
    Poco::JSON::Parser parser;

    Poco::Dynamic::Var result;
    try {
        result = parser.parse(req.stream());
    }
    catch (...) {
        throw HandlersException("Received invalid json", 
            Poco::Net::HTTPResponse::HTTPStatus::HTTP_BAD_REQUEST);
    }

    if (result.type() != typeid(Poco::JSON::Object::Ptr)) {
        throw HandlersException("Expected JSON object, not array", 
            Poco::Net::HTTPResponse::HTTPStatus::HTTP_BAD_REQUEST);
    }

    return result.extract<Poco::JSON::Object::Ptr>();
}

} // namespace



LoginHandler::LoginHandler(Poco::Data::SessionPool & sessionPool, Poco::Redis::Client & redisClient) 
    : sessionPool_{sessionPool}, redisClient_{redisClient} {}

void LoginHandler::handleRequest(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res)
// нужна проверка. если у пользователя уже есть рефреш для данного ua и fingerprint, то надо вернуть его
try
{
    if (req.getContentType().find("application/json") == std::string::npos) {
        throw HandlersException("Content-Type must be application/json", 
            Poco::Net::HTTPResponse::HTTPStatus::HTTP_BAD_REQUEST);
    }

    if (req.getContentLength() == 0) {
        throw HandlersException("Empty request body", 
            Poco::Net::HTTPResponse::HTTPStatus::HTTP_BAD_REQUEST);
    }

    Poco::JSON::Object::Ptr jsonObject = Auth::Handlers::extractJsonObjectFromRequest(req);
    std::unordered_map<std::string, Poco::Dynamic::Var> clientContext = 
    {
        {"login", {}},
        {"password", {}}
    };

    Auth::Handlers::fillRequiredFieldsFromJson(jsonObject, clientContext);

    if (clientContext["login"].isEmpty() or clientContext["password"].isEmpty()) {
        throw HandlersException("Expected login and password fields in request body", 
            Poco::Net::HTTPResponse::HTTPStatus::HTTP_BAD_REQUEST);
    }

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
        throw HandlersException("Incorrect login or password", Poco::Net::HTTPResponse::HTTPStatus::HTTP_BAD_REQUEST);
    }

    if (not Auth::Handlers::verifyPassword(clientContext["password"].toString(), hashedPassword)) {
        throw HandlersException("Incorrect login or password", Poco::Net::HTTPResponse::HTTPStatus::HTTP_BAD_REQUEST);
    }

    /**
     * Формируем полезную нагрузку для access-токена
     */
    Devkit::Tokens::Payload jwtPayload =
    {
        .sub = userId,
        .role = userRole,
        .exp = std::chrono::duration_cast<std::chrono::seconds>((std::chrono::system_clock::now() + 
            Auth::Handlers::access_token_validity_period).time_since_epoch())
    };

    /* Генерируем access и refresh токены */
    std::string accessToken = Auth::Handlers::createAccessToken(jwtPayload);
    std::string refreshToken = Auth::Handlers::createRefreshToken();

    /* ua читаем только из заголовка */
    if (not req.has("User-Agent")) {
        throw HandlersException(std::format("User-Agent header was not received"), 
            Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
    }
    std::string userAgent = req.get("User-Agent");

    /* Если заголовок Fingerprint пуст, пытаемся считать fingerprint из тела запроса */
    std::string fingerprint;
    if (not req.has("X-Fingerprint"))
    {
        if (not jsonObject->has("fingerprint")) {
            throw HandlersException(std::format("Expected fingerprint from json body or X-Fingerprint header"), 
                Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
        }
        fingerprint = (jsonObject->get("fingerprint")).extract<std::string>();
    }
    else {
        fingerprint = req.get("X-Fingerprint");
    }

    Auth::Handlers::addRefreshToRedis(redisClient_, refreshToken, userId, fingerprint, userAgent);

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
catch (const HandlersException & e)
{
    res.setStatusAndReason(e.status());
    Auth::Handlers::sendJsonResponse(res, "error", e.what());
}
catch (...)
{
    res.setStatusAndReason(Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
    Auth::Handlers::sendJsonResponse(res, "error", "error");
}

RegisterHandler::RegisterHandler(Poco::Data::SessionPool& sessionPool) : sessionPool_{sessionPool} {}

void RegisterHandler::handleRequest(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res)
{
    try
    {
        if (req.getContentType().find("application/json") == std::string::npos) {
            throw Poco::Exception("Content-Type must be application/json");
        }

        if (req.getContentLength() == 0) {
            throw Poco::Exception("Empty request body");
        }

        std::string jsonBody;
        Poco::StreamCopier::copyToString(req.stream(), jsonBody);
        
        Poco::JSON::Parser parser;
        Poco::Dynamic::Var result = parser.parse(jsonBody);

        if (result.type() != typeid(Poco::JSON::Object::Ptr)) {
            throw Poco::Exception("Expected JSON object, not array");
        }

        Poco::JSON::Object::Ptr jsonObject = result.extract<Poco::JSON::Object::Ptr>();
        std::unordered_map<std::string, Poco::Dynamic::Var> pairs = 
        {
            {"name", {}},
            {"surname", {}},
            {"role", {}},
            {"login", {}},
            {"password", {}}
        };

        if (jsonObject->size() != pairs.size()) {
            throw Poco::Exception("The number of key-value pairs must be equal count of column - 1");
        } 

        for (auto& [key, value] : pairs)
        {
            if (not jsonObject->has(key)) {   
                throw Poco::Exception("Unknown name of field");
            }
            value = jsonObject->get(key);
        }

        Poco::Data::Session session = sessionPool_.get();

        Poco::Data::Statement stmt(session);

        // Проверим существует ли пользователь с переданным логином

        int userExists = 0;
        stmt << "SELECT COUNT(*) FROM users WHERE login = $1",
            Poco::Data::Keywords::use(pairs["login"]),
            Poco::Data::Keywords::into(userExists);
        stmt.execute();
        
        if (userExists != 0) {
            throw Poco::Exception("User already exists");
        }

        stmt.reset();

        // Добавляем данные пользователя в БД

        // Здесь можно автоматизировать. Тогда в случае изменения структуры бд необходимо будет
        // только в pairs добавить новый элемент и всё
        std::string hashedPassword = Auth::Handlers::hashPassword(pairs["password"].toString());
        stmt << "INSERT INTO users (name, surname, role, login, password)"
            << "VALUES ($1, $2, $3 , $4, $5)",
            Poco::Data::Keywords::use(pairs["name"]),
            Poco::Data::Keywords::use(pairs["surname"]),
            Poco::Data::Keywords::use(pairs["role"]),
            Poco::Data::Keywords::use(pairs["login"]),
            Poco::Data::Keywords::use(hashedPassword);
        stmt.execute();

        sendJsonResponse(res, "OK", "OK");
    }
    catch (const Poco::Exception& e)
    {
        res.setStatusAndReason(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
        sendJsonResponse(res, "error", e.displayText());
        return;
    }
    catch (const std::exception& e)
    {
        res.setStatusAndReason(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
        sendJsonResponse(res, "error", e.what());
        return;
    }
    catch (...)
    {
        res.setStatusAndReason(Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
        sendJsonResponse(res, "error", "Unknown internal server error");
        return;
    }
}

RefreshHandler::RefreshHandler(Poco::Data::SessionPool & sessionPool, Poco::Redis::Client & redisClient) 
    : sessionPool_{sessionPool}, redisClient_{redisClient} {}

void RefreshHandler::handleRequest(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res) 
{
    try
    {
        /**
         * Пробуем получить refresh token из куки
         */
        Poco::Net::NameValueCollection cookies;
        req.getCookies(cookies); 

        std::string refreshToken;
        try {
            refreshToken = cookies["X-Refresh-token"]; 
        }
        catch (Poco::Exception & e)
        {
            if (req.getContentType().find("application/json") == std::string::npos) {
                throw Poco::Exception("Content-Type must be application/json");
            }

            std::string jsonBody;
            Poco::StreamCopier::copyToString(req.stream(), jsonBody);
            
            Poco::JSON::Parser parser;
            Poco::Dynamic::Var result = parser.parse(jsonBody);
            Poco::JSON::Object::Ptr jsonObject = result.extract<Poco::JSON::Object::Ptr>();
            
            if (not jsonObject->has("refresh_token")) {
                throw Poco::Exception("There is no refresh token in the cookie/request body");
            }

            refreshToken = (jsonObject->get("refresh_token")).convert<std::string>();
        }

        /* ua читаем только из заголовка */
        std::string userAgent = req.get("User-Agent", "");
        if (userAgent.empty())
        {
            res.setStatusAndReason(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
            sendJsonResponse(res, "error", "User-Agent title is missing or empty");
            return;
        }

        /* Если заголовок Fingerprint пуст, пытаемся считать fingerprint из тела запроса */
        std::string fingerprint = req.get("X-Fingerprint", "");
        if (fingerprint.empty())
        {
            if (req.getContentType().find("application/json") == std::string::npos) {
                throw Poco::Exception("Content-Type must be application/json");
            }

            if (req.getContentLength() == 0) 
            {
                res.setStatusAndReason(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
                sendJsonResponse(res, "error", "The fingerprint was expected to be received via the 'X-Fingerprint' header "
                    "or in the request body as the 'fingerprint' parameter");
                return;
            }

            std::string jsonBody;
            Poco::StreamCopier::copyToString(req.stream(), jsonBody);
            
            Poco::JSON::Parser parser;
            Poco::Dynamic::Var result = parser.parse(jsonBody);

            if (result.type() != typeid(Poco::JSON::Object::Ptr)) 
            {
                res.setStatusAndReason(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
                sendJsonResponse(res, "error", "Expected JSON object, not array");
                return;
            }

            Poco::JSON::Object::Ptr jsonObject = result.extract<Poco::JSON::Object::Ptr>();

            if (jsonObject->has("fingerprint")) {
                fingerprint = (jsonObject->get("fingerprint")).extract<std::string>();
            }
            else
            {
                res.setStatusAndReason(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
                sendJsonResponse(res, "error", "The fingerprint was expected to be received via the 'X-Fingerprint' header "
                    "or in the request body as the 'fingerprint' parameter");
                return;
            }
        }
        
        std::string hashedRefreshToken = hashRefreshToken(refreshToken);

        Poco::Redis::Array cmd;
        cmd << "EXISTS" << std::format("rtk:{}", hashedRefreshToken);
        Poco::Int64 int64ResultOfCmd = redisClient_.execute<Poco::Int64>(cmd);

        if (int64ResultOfCmd == 0)
        {
            res.setStatusAndReason(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
            sendJsonResponse(res, "error", "Bad refresh-token");
            return;
        }

        // Сравниваем ua и fingerprint
        cmd.clear();
        cmd << "HMGET" << std::format("rtk:{}", hashedRefreshToken) << "fingerprint" << "ua" << "user_id";
        Poco::Redis::Array rtkFileds = redisClient_.execute<Poco::Redis::Array>(cmd);

        // Удаляем hash refresh-токена из ZSET и HSET
        Poco::UInt64 userId = std::stoull(rtkFileds.get<Poco::Redis::BulkString>(2).value());
        deleteRefreshFromRedis(redisClient_, hashedRefreshToken, userId);
        
        if (rtkFileds.get<Poco::Redis::BulkString>(0).value() != fingerprint
            or rtkFileds.get<Poco::Redis::BulkString>(1).value() != userAgent) 
        {
            res.setStatusAndReason(Poco::Net::HTTPResponse::HTTP_FORBIDDEN);
            sendJsonResponse(res, "error", "Refresh token used from unauthorized device");
            return;
        }

        Poco::Data::Session session = sessionPool_.get();
        Poco::Data::Statement stmt(session);
            
        std::string userRole;
        stmt << "SELECT role FROM users WHERE id = $1",
            Poco::Data::Keywords::use(userId),
            Poco::Data::Keywords::into(userRole);
        
        if (stmt.execute() == 0) 
        {
            res.setStatusAndReason(Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
            sendJsonResponse(res, "error", "Unknown internal server error");
            return;
        }

        /**
         * Формируем полезную нагрузку для access-токена
         */
        Devkit::Tokens::Payload jwtPayload =
        {
            .sub = userId,
            .role = userRole,
            .exp = std::chrono::duration_cast<std::chrono::seconds>((std::chrono::system_clock::now() + 
                Auth::Handlers::access_token_validity_period).time_since_epoch())
        };

        /**
         * Генерируем access и refresh токены
         */
        std::string accessToken = Auth::Handlers::createAccessToken(jwtPayload);
        refreshToken = Auth::Handlers::createRefreshToken();

        addRefreshToRedis(redisClient_, refreshToken, userId, fingerprint, userAgent);

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
    catch (const Poco::Exception& e)
    {
        res.setStatusAndReason(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
        sendJsonResponse(res, "error", e.displayText());
        return;
    }
    catch (const std::exception& e)
    {
        res.setStatusAndReason(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
        sendJsonResponse(res, "error", e.what());
        return;
    }
    catch (...)
    {
        res.setStatusAndReason(Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
        sendJsonResponse(res, "error", "Unknown internal server error");
        return;
    }
}

void ErrorHandler::handleRequest(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res)
{

}

} // namespace FQW::Auth::Handlers
