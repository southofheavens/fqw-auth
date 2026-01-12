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

const std::string key_ = "secret_key";
constexpr std::chrono::seconds access_token_validity_period = std::chrono::seconds(15 * 60);
constexpr std::chrono::seconds refresh_token_validity_period = std::chrono::seconds(30 * 24 * 60 * 60);

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

} // namespace



LoginHandler::LoginHandler(Poco::Data::SessionPool& sessionPool, Poco::Redis::Client & redisClient) 
    : sessionPool_{sessionPool}, redisClient_{redisClient} {}

void LoginHandler::handleRequest(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res)
// TODO Нужно проверять лимит рефреш токенов на пользователя. Пусть лимитом будет 5. Если лимит исчерпан, то
// мы удаляем самый старый токен (который создан раньше всех) и добавляем новый, который будем сейчас возвращать
// пользователю после его создания

/**
 * 
 */
{
    try
    {
        if (req.getContentType().find("application/json") == std::string::npos) 
        {
            res.setStatusAndReason(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
            sendJsonResponse(res, "error", "Content-Type must be application/json");
            return;
        }

        if (req.getContentLength() == 0) 
        {
            res.setStatusAndReason(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
            sendJsonResponse(res, "error", "Empty request body");
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
        std::unordered_map<std::string, Poco::Dynamic::Var> pairs = 
        {
            {"login", {}},
            {"password", {}}
        };

        for (auto & [key, value] : pairs)
        {
            if (not jsonObject->has(key)) 
            {
                res.setStatusAndReason(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
                sendJsonResponse(res, "error", std::format("Field {} was not received", key));
                return;
            }
            value = jsonObject->get(key);
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
            Poco::Data::Keywords::use(pairs["login"]),
            Poco::Data::Keywords::into(hashedPassword),
            Poco::Data::Keywords::into(userRole),
            Poco::Data::Keywords::into(userId);

        if (stmt.execute() == 0) {
            throw Poco::Exception("Incorrect login or password");
        }

        if (not Auth::Handlers::verifyPassword(pairs["password"].toString(), hashedPassword)) {
            throw Poco::Exception("Incorrect login or password"); 
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
        std::string refreshToken = Auth::Handlers::createRefreshToken();

        /**
         * Помещаем refresh в Redis
         */

        /* ua читаем только из заголовка */
        std::string userAgent = req.get("User-Agent", "");
        if (userAgent.empty())
        {
            res.setStatusAndReason(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
            sendJsonResponse(res, "error", "User-Agent title is missing or empty");
            return;
        }

        /* если заголовок Fingerprint пуст, пытаемся считать fingerprint из тела запроса */
        std::string fingerprint = req.get("X-Fingerprint", "");
        if (fingerprint.empty())
        {
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

        /* если заголовок X-Forwarded-For пуст, то берём IP напрямую из сокета */
        std::string ipAddress = req.get("X-Forwarded-For", "");
        if (not ipAddress.empty())
        {
            size_t comma = ipAddress.find(",");
            if (comma != std::string::npos) {
                ipAddress = ipAddress.substr(0, comma);
            }
        }
        else {
            ipAddress = req.clientAddress().host().toString();
        }

        // 1. если рефрешей стало 5, удаляем самый старый
        // 2. добавляем новый рефреш в rtk:
        // 3. добавляем новый рефреш в user_rtk:

        Poco::Redis::Array cmd;
        cmd << "ZCARD" << std::format("user_rtk:{}", userId);
        Poco::Int64 resultOfCmd = redisClient_.execute<Poco::Int64>(cmd);
        if (resultOfCmd == 5)
        /* Удаляем самый старый refresh-токен */
        {
            cmd.clear();
            cmd << "ZPOPMIN" << std::format("user_rtk:{}", userId);
            Poco::Redis::Array resultOfPop = redisClient_.execute<Poco::Redis::Array>(cmd);
        }

        std::string hashedRefresh = hashRefreshToken(refreshToken);
        cmd.clear();
        cmd << "HSET" << std::format("rtk:{}", hashedRefresh) << "ua" << userAgent
            << "fingerprint" << fingerprint << "ip" << ipAddress
            << "created" << std::to_string(
            std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now()
            .time_since_epoch()).count());
        resultOfCmd = redisClient_.execute<Poco::Int64>(cmd);

        /* задать время исчезновения объекта expired */
        

        Poco::JSON::Object resultJson;
        resultJson.set("access_token", accessToken);
        resultJson.set("refresh_token", refreshToken);

        Poco::Net::HTTPCookie cookie("refresh_token", refreshToken);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/"); // TODO наверное не стоит делать /
        cookie.setSameSite(Poco::Net::HTTPCookie::SAME_SITE_STRICT);

        res.addCookie(cookie);

        resultJson.stringify(res.send());
    }
    catch (...)
    {
        res.setStatusAndReason(Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
        sendJsonResponse(res, "error", "error");
    }
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
        if (req.getContentType().find("application/json") == std::string::npos) {
            throw Poco::Exception("Content-Type must be application/json");
        }

        /**
         * Пробуем получить refresh token из куки
         */
        Poco::Net::NameValueCollection cookies;
        req.getCookies(cookies); 

        std::string refreshToken = cookies["refreshToken"]; 

        if (refreshToken.empty())
        {
            std::string jsonBody;
            Poco::StreamCopier::copyToString(req.stream(), jsonBody);
            
            Poco::JSON::Parser parser;
            Poco::Dynamic::Var result = parser.parse(jsonBody);
            Poco::JSON::Object::Ptr jsonObject = result.extract<Poco::JSON::Object::Ptr>();
            
            if (not jsonObject->has("refreshToken")) {
                throw Poco::Exception("There is no refresh token in the cookie/request body");
            }

            refreshToken = (jsonObject->get("refreshToken")).convert<std::string>();
        }
        

        // Ищем в бд данный рефреш токен
        // Найдено - удаляем его из БД, берем из таблицы users роль пользователя и формируем новый access
        // Формируем новый refresh
        // Возвращаем access и refresh
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
