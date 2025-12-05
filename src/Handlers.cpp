#include <iostream>
#include <unordered_set>

#include <Handlers.h>
#include <Utils.h>

#include <Poco/Data/Session.h>
#include <Poco/Data/RecordSet.h>
#include <Poco/Data/Statement.h>
#include <Poco/StreamCopier.h>
#include <Poco/JSON/Parser.h>
#include <Poco/JSON/Object.h>
#include <Poco/URI.h>

namespace Auth::Handlers
{

namespace
{

void sendJsonResponse(Poco::Net::HTTPServerResponse& res,
    const std::string& status, const std::string& message)
{
    Poco::JSON::Object json;
    json.set("status", status);
    json.set("message", message);

    std::ostream& out = res.send();
    json.stringify(out);
}

} // namespace

LoginHandler::LoginHandler(Poco::Data::SessionPool& sessionPool) : sessionPool_{sessionPool} {}

void LoginHandler::handleRequest(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res)
// TODO Нужно проверять лимит рефреш токенов на пользователя. Пусть лимитом будет 5. Если лимит исчерпан, то
// мы удаляем самый старый токен (который создан раньше всех) и добавляем новый, который будем сейчас возвращать
// пользователю после его создания
{
    try
    {
        if (req.getContentType().find("application/json") == std::string::npos) 
        {
            res.setStatus(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
            sendJsonResponse(res, "error", "Content-Type must be application/json");
            return;
        }

        if (req.getContentLength() == 0) 
        {
            res.setStatus(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
            sendJsonResponse(res, "error", "Empty request body");
            return;
        }

        std::string jsonBody;
        Poco::StreamCopier::copyToString(req.stream(), jsonBody);
        
        Poco::JSON::Parser parser;
        Poco::Dynamic::Var result = parser.parse(jsonBody);

        if (result.type() != typeid(Poco::JSON::Object::Ptr)) 
        {
            res.setStatus(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
            sendJsonResponse(res, "error", "Expected JSON object, not array");
            return;
        }

        Poco::JSON::Object::Ptr jsonObject = result.extract<Poco::JSON::Object::Ptr>();
        std::unordered_map<std::string, Poco::Dynamic::Var> pairs = 
        {
            {"login", {}},
            {"password", {}}
        };

        if (jsonObject->size() != pairs.size())
        {
            res.setStatus(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
            sendJsonResponse(res, "error", "Expected to receive a login and password, but received more pairs");
            return;
        }

        for (auto& [key, value] : pairs)
        {
            if (not jsonObject->has(key)) 
            {
                res.setStatus(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
                sendJsonResponse(res, "error", "Unknown name of field");
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

        if (not Auth::Utils::verifyPassword(pairs["password"].toString(), hashedPassword)) {
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
                Auth::Utils::access_token_validity_period).time_since_epoch())
        };

        /**
         * Генерируем access и refresh токены
         */
        std::string accessToken = Auth::Utils::createAccessToken(jwtPayload);
        std::string refreshToken = Auth::Utils::createRefreshToken();

        /**
         * Формируем lookup_key 
         */
        std::string lookup_key = refreshToken.substr(0,Auth::Utils::lookup_key_length);

        stmt.reset();

        uint64_t expires = std::chrono::duration_cast<std::chrono::seconds>((std::chrono::system_clock::now() + 
            Auth::Utils::refresh_token_validity_period).time_since_epoch()).count();
        std::string hashedRefreshToken = Auth::Utils::hashPassword(refreshToken);
        stmt << "INSERT INTO refresh_tokens (user_id, lookup_key, token, expires)"
            << "VALUES ($1, $2, $3, $4)",
            Poco::Data::Keywords::use(userId),
            Poco::Data::Keywords::use(lookup_key),
            Poco::Data::Keywords::use(hashedRefreshToken),
            Poco::Data::Keywords::use(expires);
        
        stmt.execute();

        Poco::JSON::Object resultJson;
        resultJson.set("access_token", accessToken);
        resultJson.set("refresh_token", refreshToken);
        resultJson.stringify(res.send());
    }
    catch (const Poco::Exception& e)
    {
        res.setStatus(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
        sendJsonResponse(res, "error", e.displayText());
        return;
    }
    catch (const std::exception& e)
    {
        res.setStatus(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
        sendJsonResponse(res, "error", e.what());
        return;
    }
    catch (...)
    {
        res.setStatus(Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
        sendJsonResponse(res, "error", "Unknown internal server error");
        return;
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
        std::string hashedPassword = Auth::Utils::hashPassword(pairs["password"].toString());
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
        res.setStatus(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
        sendJsonResponse(res, "error", e.displayText());
        return;
    }
    catch (const std::exception& e)
    {
        res.setStatus(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
        sendJsonResponse(res, "error", e.what());
        return;
    }
    catch (...)
    {
        res.setStatus(Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
        sendJsonResponse(res, "error", "Unknown internal server error");
        return;
    }
}

void ErrorHandler::handleRequest(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res)
{

}

} // namespace AuthHandlers
