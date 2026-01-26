#include <handlers/RegisterHandler.h>
#include <Utils.h>

namespace FQW::Auth
{

void RegisterHandler::handleRequest(Poco::Net::HTTPServerRequest & req, Poco::Net::HTTPServerResponse & res)
try
{
    if (req.getContentType().find("application/json") == std::string::npos) {
        throw Auth::Utils::HandlersException(std::format("Content-Type must be application/json"), 
            Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
    }

    if (req.getContentLength() == 0) {
        throw Auth::Utils::HandlersException(std::format("Empty request body"), 
            Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
    }

    Poco::JSON::Object::Ptr jsonObject = Auth::Utils::extractJsonObjectFromRequest(req);

    std::map<std::string, Poco::Dynamic::Var> clientContext = 
    {
        {"name", {}},
        {"surname", {}},
        {"role", {}},
        {"login", {}},
        {"password", {}}
    };

    Auth::Utils::fillRequiredFieldsFromJson(jsonObject, clientContext);

    std::string stringRole = clientContext["role"].extract<std::string>();
    if (stringRole != Auth::Utils::userRoles[0] or stringRole != Auth::Utils::userRoles[1]) {
        throw Auth::Utils::HandlersException(std::format("Invalid role. Correct roles is 'Participant' and 'Judge'"), 
            Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
    }

    Poco::Data::Session session = sessionPool_.get();

    Poco::Data::Statement stmt(session);

    // Проверим существует ли пользователь с переданным логином

    int userExists = 0;
    stmt << "SELECT COUNT(*) FROM users WHERE login = $1",
        Poco::Data::Keywords::use(clientContext["login"]),
        Poco::Data::Keywords::into(userExists);
    stmt.execute();
    
    if (userExists != 0) {
        throw Poco::Exception("User already exists");
    }

    // Добавляем данные пользователя в БД
    std::string hashedPassword = Auth::Utils::hashPassword(clientContext["password"].toString());
    stmt.reset();
    stmt << "INSERT INTO users (name, surname, role, login, password)"
        << "VALUES ($1, $2, $3 , $4, $5)",
        Poco::Data::Keywords::use(clientContext["name"]),
        Poco::Data::Keywords::use(clientContext["surname"]),
        Poco::Data::Keywords::use(clientContext["role"]),
        Poco::Data::Keywords::use(clientContext["login"]),
        Poco::Data::Keywords::use(hashedPassword);
    stmt.execute();

    Auth::Utils::sendJsonResponse(res, "OK", "OK");
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
