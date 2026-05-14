#include <Handlers/RegisterHandler.h>
#include <Utils.h>
#include <cctype>

namespace
{

/// @brief Проверка удовлетворяет ли логин требованиям
/// @param login логин
/// @note Требования к логину:
/// @note - только буквы латинского алфавита и цифры; первый символ — буква
/// @note - минимально допустимая длина - 3 символа
/// @throw RGT::Devkit::RGTException если логин не удовлетворяет требованиям
/// @details Логин чувствителен к регистру
void validateLogin(const std::string & login)
{
    /// Минимально допустимая длина логина
    static constexpr uint8_t minimum_login_length = 3;

    if (login.length() < minimum_login_length) {
        throw RGT::Devkit::RGTException(std::format("The minimum login length is {} characters", minimum_login_length),
            Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
    }

    if (not std::isalpha(static_cast<unsigned char>(login[0]))) {
        throw RGT::Devkit::RGTException("The login must start with a letter",
            Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
    }

    for (const char & c : login)
    {
        if (not std::isalnum(static_cast<unsigned char>(c))) {
            throw RGT::Devkit::RGTException("The login contains an invalid character",
                Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
        }
    }
}

/// @brief Проверка удовлетворяет ли пароль требованиям 
/// @param password пароль
/// @note Требования к паролю:
/// @note - может состоять из букв латинского алфавита, цифр и спецсимволов (~, !, @, #, $, &, *, -, _)
/// @note - обязан содержать хотя бы одну заглавную букву и хотя бы один спецсимвол
/// @note - минимально допустимая длина - 8 символов
/// @throw RGT::Devkit::RGTException если пароль не удовлетворяет требованиям
void validatePassword(const std::string & password)
{
    /// Минимально допустимая длина пароля
    static constexpr uint8_t minimum_password_length = 8;

    static std::unordered_set<char> specialCharacters = 
    {
        '~', '!', '@', '#', '$', '&', '*', '-', '_'
    };
    
    if (password.length() < minimum_password_length) {
        throw RGT::Devkit::RGTException(std::format("The minimum password length is {} characters", 
            minimum_password_length), Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
    }

    bool hasCapital = false;
    bool hasSpecialChar = false;
    for (const char & c : password)
    {
        unsigned char unsig_c = static_cast<unsigned char>(c);
        if (isalpha(unsig_c))
        {
            if (isupper(unsig_c)) {
                hasCapital = true;
            }
        }
        else if (isdigit(unsig_c)) {
            continue;
        }
        else 
        {
            if (specialCharacters.find(unsig_c) != specialCharacters.end()) {
                hasSpecialChar = true;
            }
            else {
                throw RGT::Devkit::RGTException("The password contains an invalid character",
                    Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
            }
        }
    }

    if (not hasCapital) {
        throw RGT::Devkit::RGTException("The password is missing a capital letter",
            Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
    }
    if (not hasSpecialChar) {
        throw RGT::Devkit::RGTException("The password is missing a special character",
            Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
    }
}

} // namespace

namespace RGT::Auth::Handlers
{

void RegisterHandler::requestPreprocessing(Poco::Net::HTTPServerRequest & request)
{
    HTTPRequestHandler::checkContentLength(request, cfg_.getUInt32("max_request_body_size"));
    HTTPRequestHandler::checkContentLengthIsNull(request);
    HTTPRequestHandler::checkContentType(request, "application/json");
}

void RegisterHandler::extractPayloadFromRequest(Poco::Net::HTTPServerRequest & request)
{
    Poco::JSON::Object::Ptr jsonObject = HTTPRequestHandler::extractJsonObjectFromRequest(request);

    std::map<std::string, Poco::Dynamic::Var> expectedKeysAndPotentialValues = 
    {
        {"name", {}},
        {"surname", {}},
        {"role", {}},
        {"login", {}},
        {"password", {}}
    };
    RGT::Auth::fillRequiredFieldsFromJson(jsonObject, expectedKeysAndPotentialValues);

    auto extractString = [](const std::map<std::string, Poco::Dynamic::Var> & map)
    {
        std::map<std::string, std::string> result;
        for (const auto & [key, value] : map)
        {
            try {
                result[key] = value.extract<std::string>();
            }
            catch (...) {
                throw RGT::Devkit::RGTException(std::format("Field {} must be presented in string format", key),
                    Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
            }
        }

        return result;
    };

    std::map<std::string, std::string> keysAndStringValues = extractString(expectedKeysAndPotentialValues);

    requestPayload_.name = keysAndStringValues["name"];
    requestPayload_.surname = keysAndStringValues["surname"];
    requestPayload_.login = keysAndStringValues["login"];
    requestPayload_.password = keysAndStringValues["password"];
    try {
        requestPayload_.role = RGT::Devkit::mapStringToUserRole(keysAndStringValues["role"]);
    }
    catch (const std::runtime_error & e) 
    {
        throw RGT::Devkit::RGTException("Invalid role. Correct roles is 'participant' and 'judge'", 
            Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
    }
}
 
void RegisterHandler::requestProcessing(Poco::Net::HTTPServerRequest & request, Poco::Net::HTTPServerResponse & response)
{
    // Валидация данных, полученных от пользователя
    validateLogin(requestPayload_.login);
    validatePassword(requestPayload_.password);

    Poco::Data::Session session = sessionPool_.get();

    // Проверим существует ли пользователь с переданным логином

    int userExists = 0;
    session << "SELECT COUNT(*) FROM users WHERE login = $1",
        Poco::Data::Keywords::use(requestPayload_.login),
        Poco::Data::Keywords::into(userExists),
        Poco::Data::Keywords::now;
    
    if (userExists != 0) {
        throw RGT::Devkit::RGTException(std::format("User with login '{}' already exists", requestPayload_.login), 
            Poco::Net::HTTPResponse::HTTP_CONFLICT);
    }

    // Добавляем данные пользователя в БД
    std::string hashedPassword = Auth::hashPassword(requestPayload_.password);
    uint64_t userId;
    session << "INSERT INTO users (name, surname, role, login, password_hash)"
        << "VALUES ($1, $2, $3 , $4, $5)"
        << "RETURNING id",
        Poco::Data::Keywords::use(requestPayload_.name),
        Poco::Data::Keywords::use(requestPayload_.surname),
        Poco::Data::Keywords::bind(RGT::Devkit::mapUserRoleToString(requestPayload_.role).data()),
        Poco::Data::Keywords::use(requestPayload_.login),
        Poco::Data::Keywords::use(hashedPassword),
        Poco::Data::Keywords::into(userId),
        Poco::Data::Keywords::now;

    Poco::JSON::Object json;
    json.set("id", userId);

    response.setStatusAndReason(Poco::Net::HTTPResponse::HTTP_CREATED);
    json.stringify(response.send());
}

} // namespace RGT::Auth::Handlers
