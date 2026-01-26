#include <iostream>
#include <format>
#include <unordered_set>
#include <chrono>
#include <fstream>

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

// Лимит refresh-токенов на одного пользователя
constexpr uint8_t                refresh_tokens_limit          = 5;
// Время действия access-токена
constexpr std::chrono::seconds   access_token_validity_period  = std::chrono::seconds(15 * 60);
// Время действия refresh-токена
constexpr std::chrono::seconds   refresh_token_validity_period = std::chrono::seconds(30 * 24 * 60 * 60);
// Секретный ключ для подписи 
const     std::string            key                           = "secret_key";
// 
const std::array<std::string, 2> userRoles = {"Participant", "Judge"};
 


// Declarations

/**
 * В библиотеке Poco у методов и функций отсутствует квалификатор noexcept, поэтому очень тяжело
 * отследить самому выбрасывает ли функция исключения или нет. Для перестраховки в методах handleRequest
 * присутствует блок try - catch, который перехватывает два типа исключений: HandlersException - 
 * исключение выбрасывается для предусмотренных ошибок (например, от пользователя ожидается логин 
 * и пароль в теле json, а что-то из этого отсутствует) и ... для непредусмотренных исключений, 
 * которые могут вылететь из "недр" других функций. Конструктор HandlersException принимает 
 * std::string errorMessage - сообщение об ошибке и Poco::Net::HTTPResponse::HTTPStatus - код
 * http-ответа, эти данные будут отправлены клиенту. Если исключение перехватит блок catch (...),
 * то клиент получит код 500 - HTTP_INTERNAL_SERVER_ERROR и сообщение "Internal server error."
 */
class HandlersException;

/**
 * Отправляет клиенту ответ со статусом status и сообщением message 
 */
void sendJsonResponse(Poco::Net::HTTPServerResponse & res,
    const std::string & status, const std::string & message);

/**
 * @brief Хэширует пароль используя Argon2 алгоритм
 * @param password Пароль для хэширования
 * @return std::string Хэшированный пароль в формате libsodium
 * @throw std::runtime_error если хэширование не удалось
 */
std::string hashPassword(const std::string & password);

/**
 * @brief Верификация пароля
 * @param password Пароль для проверки
 * @param hash Хэш из базы данных
 * @return bool true если пароль корректный, false в противном случае
 * @throw std::runtime_error если проверка не удалась (системная ошибка)
 */
bool verifyPassword(const std::string & password, const std::string & hash);

/**
 * @brief Генерирует access токен, который представляет из себя JWT
 * @param p Полезная нагрузка
 * @return Токен
 */
std::string createAccessToken(const FQW::Devkit::Tokens::Payload & p);

/**
 * @brief Генерирует refresh токен, представляющий из себя UUID
 * @return Токен
 */
std::string createRefreshToken();

/**
 * Хэширует refresh-токен используя алгоритм SHA256 и возвращает хэш
 */
std::string hashRefreshToken(const std::string & token);

/**
 * Верификация refresh-токена
 */
bool verifyRefreshToken(const std::string & token, const std::string & hash);

/**
 * Удаляет хэш рефреш-токена из Redis (из ZSET + из HSET)
 */
void deleteRefreshFromRedis(Poco::Redis::Client & redisClient, const std::string & hashedRefreshToken, uint64_t userId);

/**
 * Хэширует рефреш-токен и добавляет хэш в Redis (в ZSET + в HSET). Если превышен лимит рефреш-токенов на
 * пользователя, то удаляет самый старый рефреш-токен 
 */
void addRefreshToRedis(Poco::Redis::Client & redisClient, std::string & refreshToken, uint64_t userId,
    std::string & fingerprint, std::string & userAgent);

/**
 * Извлекает из json'а значения для всех ключей, перечисленных в контейнере pairs, который хранит пары, и
 * присваивает каждому ключу соответствующее значение. Если хотя бы одно поле отсутствует в json, 
 * будет выброшено исключение HandlersException.
 */
void fillRequiredFieldsFromJson(Poco::JSON::Object::Ptr jsonObject, auto & pairs);

/** 
 * Пытается извлечь из JSON-объекта значения для ключей, перечисленных в контейнере pairs.
 * Для каждого ключа из pairs, присутствующего в JSON, соответствующее значение обновляется.
 * Если ключ отсутствует в JSON, значение, соответствующее данному ключу, не обновляется.
 * Исключение не выбрасывается.
 */
void tryFillRequiredFieldsFromJson(Poco::JSON::Object::Ptr jsonObject, auto & pairs);

/** 
 * Извлекает из запроса значения для всех ключей (имён заголовков), перечисленных в контейнере
 * pairs, который хранит пары, и присваивает каждому ключу соответствующее значение. Если хотя бы один
 * заголовок отсутствует - выбрасывается исключение HandlersException.
 */
void fillRequiredFieldsFromHeaders(Poco::Net::HTTPServerRequest & req, auto & pairs);

/**
 * Пытается извлечь из запроса значения для ключей (имён заголовков), перечисленных в контейнере pairs.
 * Для каждого ключа из pairs, присутствующего в заголовках запроса, соответствующее значение обновляется.
 * Если ключ (имя заголовка) отсутствует в запросе, значение, соответствующее данному ключу, 
 * не обновляется. Исключение не выбрасывается.
 */
void tryFillRequiredFieldsFromHeaders(Poco::Net::HTTPServerRequest & req, auto & pairs);

/**
 * Извлекает из запроса JSON object и возвращает указатель на него
 */
Poco::JSON::Object::Ptr extractJsonObjectFromRequest(Poco::Net::HTTPServerRequest & req);

// Считывает lua-script из файла с именем filename и возвращает его
std::string readLuaScript(const std::string & filename);

// Проверяет, есть ли для данных fingerprint и UA refresh-токен. Если да, то возвращает его хэш.
// В противном случае возвращает std::nullopt 
std::optional<std::string> getHashRefreshTokenByUserData(Poco::Redis::Client & redisClient, uint64_t userId,
    std::string & fingerprint, std::string & userAgent);



// Definitions

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

void sendJsonResponse(Poco::Net::HTTPServerResponse& res,
    const std::string& status, const std::string& message)
{
    Poco::JSON::Object json;
    json.set("status", status);
    json.set("message", message);

    std::ostream& out = res.send();
    json.stringify(out);
}

std::string hashPassword(const std::string& password)
{
    char hashed[crypto_pwhash_STRBYTES];
    
    if (crypto_pwhash_str(hashed, password.c_str(), password.length(), 
        crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE) != 0) { 
        throw std::runtime_error("Password hashing failed - possibly out of memory");
    }
    
    return std::string(hashed);
}

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

std::string createAccessToken(const FQW::Devkit::Tokens::Payload& p)
{
    Poco::JWT::Token token;

    token.setSubject(std::to_string(p.sub));

    token.payload().set("role", p.role);

    Poco::Timestamp expires = static_cast<Poco::Timestamp::TimeVal>(
        std::chrono::duration_cast<std::chrono::microseconds>(p.exp).count()
    );
    token.setExpiration(expires);
    
    Poco::JWT::Signer signer(key);
    return signer.sign(token, Poco::JWT::Signer::ALGO_HS256);
}

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

void deleteRefreshFromRedis(Poco::Redis::Client & redisClient, 
                            const std::string & hashedRefreshToken, 
                            uint64_t userId)
{
    static const std::string script = readLuaScript("lua_scripts/delete_refresh.lua");

    Poco::Redis::Array cmd;
    cmd << "EVAL"
        << script
        << "2" 
        << std::format("user_rtk:{}", userId)        // KEYS[1]
        << std::format("rtk:{}", hashedRefreshToken) // KEYS[2]
        << hashedRefreshToken;                       // ARGV[1]

    try {
        Poco::Int64 result = redisClient.execute<Poco::Int64>(cmd);
    } 
    catch (...) {
        throw HandlersException("Internal server error. Try repeating the request.",
            Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
    }
}

void addRefreshToRedis(Poco::Redis::Client & redisClient, std::string & refreshToken, uint64_t userId,
    std::string & fingerprint, std::string & userAgent)
{
    static const std::string script = readLuaScript("lua_scripts/add_refresh.lua");

    Poco::Redis::Array cmd;
    std::string hashedRefresh = hashRefreshToken(refreshToken);

    cmd << "EVAL"
        << script
        << "2"  
        << std::format("user_rtk:{}", userId)      // KEYS[1]
        << std::format("rtk:{}", hashedRefresh)    // KEYS[2]
        << std::to_string(refresh_tokens_limit)    // ARGV[1]
        << std::to_string(refresh_token_validity_period.count())                          // ARGV[2]
        << std::to_string(std::chrono::system_clock::now().time_since_epoch().count())    // ARGV[3]
        << hashedRefresh              // ARGV[4]
        << userAgent                  // ARGV[5]
        << fingerprint                // ARGV[6]
        << std::to_string(userId);    // ARGV[7]

    try {
        redisClient.execute<Poco::Int64>(cmd);
    } 
    catch (...) {
        throw HandlersException("Internal server error. Try repeating the request.",
            Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
    }
}

void fillRequiredFieldsFromJson(Poco::JSON::Object::Ptr jsonObject, auto & pairs)
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

void tryFillRequiredFieldsFromJson(Poco::JSON::Object::Ptr jsonObject, auto & pairs)
{
    for (auto & [key, value] : pairs)
    {
        if (jsonObject->has(key)) {
            value = jsonObject->get(key);
        }
    }
}

void fillRequiredFieldsFromHeaders(Poco::Net::HTTPServerRequest & req, auto & pairs)
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

void tryFillRequiredFieldsFromHeaders(Poco::Net::HTTPServerRequest & req, auto & pairs)
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

std::string readLuaScript(const std::string & filename) 
{
    std::ifstream file(filename);
    
    if (not file.is_open()) {
        throw std::runtime_error("Cannot open Lua script: " + filename);
    }
    return std::string
    (
        std::istreambuf_iterator<char>(file),
        std::istreambuf_iterator<char>()
    );
}

std::optional<std::string> getHashRefreshTokenByUserData(Poco::Redis::Client & redisClient, uint64_t userId,
    std::string & fingerprint, std::string & userAgent)
{
    static const std::string script = readLuaScript("lua_scripts/get_refresh_token_hash.lua");

    Poco::Redis::Array cmd;

    cmd << "EVAL"
        << script
        << "1"  
        << std::format("user_rtk:{}", userId)    // KEYS[1]
        << fingerprint    // ARGV[1]
        << userAgent;     // ARGV[2]

    try 
    {
        Poco::Redis::BulkString result = redisClient.execute<Poco::Redis::BulkString>(cmd);
        if (result.isNull()) {
            return std::nullopt;
        }
        return result.value();
    } 
    catch (...) {
        throw HandlersException("Internal server error. Try repeating the request.",
            Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
    }
}

} // namespace



LoginHandler::LoginHandler(Poco::Data::SessionPool & sessionPool, Poco::Redis::Client & redisClient) 
    : sessionPool_{sessionPool}, redisClient_{redisClient} {}

void LoginHandler::handleRequest(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res)
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

    /* ua читаем только из заголовка */
    if (not req.has("User-Agent")) {
        throw HandlersException(std::format("User-Agent header was not received"), 
            Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
    }
    std::string userAgent = req.get("User-Agent");

    /* Если заголовок Fingerprint пуст, пытаемся считать fingerprint из тела запроса */
    Poco::JSON::Object::Ptr jsonObject = Auth::Handlers::extractJsonObjectFromRequest(req);
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

    std::map<std::string, Poco::Dynamic::Var> clientContext = 
    {
        {"login", {}},
        {"password", {}}
    };
    Auth::Handlers::fillRequiredFieldsFromJson(jsonObject, clientContext);

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

    /* Проверяем, существует ли для данных UA и fingerprint refresh-токен */
    if (std::optional<std::string> potentionalRefreshHash
            = getHashRefreshTokenByUserData(redisClient_, userId, fingerprint, userAgent);
        potentionalRefreshHash.has_value()) 
    {
        // Удаляем хэш refresh-токена из Redis (т.к. дальше для данных UA и fingerprint
        // будет создан новый refresh-токен, а уже существующий мы не можем использовать
        // потому, что в Redis хранится хэш, а не сам токен)
        deleteRefreshFromRedis(redisClient_, potentionalRefreshHash.value(), userId);
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
catch (const Auth::Handlers::HandlersException & e)
{
    res.setStatusAndReason(e.status());
    Auth::Handlers::sendJsonResponse(res, "error", e.what());
}
catch (...)
{
    res.setStatusAndReason(Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
    Auth::Handlers::sendJsonResponse(res, "error", "Internal server error");
}

RegisterHandler::RegisterHandler(Poco::Data::SessionPool & sessionPool) : sessionPool_{sessionPool} {}

void RegisterHandler::handleRequest(Poco::Net::HTTPServerRequest & req, Poco::Net::HTTPServerResponse & res)
try
{
    if (req.getContentType().find("application/json") == std::string::npos) {
        throw HandlersException(std::format("Content-Type must be application/json"), 
            Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
    }

    if (req.getContentLength() == 0) {
        throw HandlersException(std::format("Empty request body"), 
            Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
    }

    Poco::JSON::Object::Ptr jsonObject = extractJsonObjectFromRequest(req);

    std::map<std::string, Poco::Dynamic::Var> clientContext = 
    {
        {"name", {}},
        {"surname", {}},
        {"role", {}},
        {"login", {}},
        {"password", {}}
    };

    fillRequiredFieldsFromJson(jsonObject, clientContext);

    std::string stringRole = clientContext["role"].extract<std::string>();
    if (stringRole != userRoles[0] or stringRole != userRoles[1]) {
        throw HandlersException(std::format("Invalid role. Correct roles is 'Participant' and 'Judge'"), 
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
    std::string hashedPassword = Auth::Handlers::hashPassword(clientContext["password"].toString());
    stmt.reset();
    stmt << "INSERT INTO users (name, surname, role, login, password)"
        << "VALUES ($1, $2, $3 , $4, $5)",
        Poco::Data::Keywords::use(clientContext["name"]),
        Poco::Data::Keywords::use(clientContext["surname"]),
        Poco::Data::Keywords::use(clientContext["role"]),
        Poco::Data::Keywords::use(clientContext["login"]),
        Poco::Data::Keywords::use(hashedPassword);
    stmt.execute();

    sendJsonResponse(res, "OK", "OK");
}
catch (const Auth::Handlers::HandlersException & e)
{
    res.setStatusAndReason(e.status());
    sendJsonResponse(res, "error", e.what());
}
catch (...)
{
    res.setStatusAndReason(Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
    sendJsonResponse(res, "error", "Internal server error");
}

RefreshHandler::RefreshHandler(Poco::Data::SessionPool & sessionPool, Poco::Redis::Client & redisClient) 
    : sessionPool_{sessionPool}, redisClient_{redisClient} {}

void RefreshHandler::handleRequest(Poco::Net::HTTPServerRequest & req, Poco::Net::HTTPServerResponse & res) 
try
{
    // Пробуем получить refresh token из куки
    Poco::Net::NameValueCollection cookies;
    req.getCookies(cookies); 

    std::string refreshToken;
    try {
        refreshToken = cookies["X-Refresh-token"]; 
    }
    catch (Poco::Exception & e)
    {
        if (req.getContentType().find("application/json") == std::string::npos) {
            throw Auth::Handlers::HandlersException("Content-Type must be application/json",
                Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
        }

        std::string jsonBody;
        Poco::StreamCopier::copyToString(req.stream(), jsonBody);
        
        Poco::JSON::Parser parser;
        Poco::Dynamic::Var result = parser.parse(jsonBody);
        Poco::JSON::Object::Ptr jsonObject = result.extract<Poco::JSON::Object::Ptr>();
        
        if (not jsonObject->has("refresh_token")) {
            throw Auth::Handlers::HandlersException("Expected to receive refresh token "
                "in the cookie/request body",
                Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
        }

        refreshToken = (jsonObject->get("refresh_token")).convert<std::string>();
    }

    /* ua читаем только из заголовка */
    if (not req.has("User-Agent")) {
        throw HandlersException(std::format("User-Agent header was not received"), 
            Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
    }
    std::string userAgent = req.get("User-Agent");

    /* Если заголовок Fingerprint пуст, пытаемся считать fingerprint из тела запроса */
    Poco::JSON::Object::Ptr jsonObject = Auth::Handlers::extractJsonObjectFromRequest(req);
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
    
    std::string hashedRefreshToken = Auth::Handlers::hashRefreshToken(refreshToken);

    Poco::Redis::Array cmd;
    cmd << "EXISTS" << std::format("rtk:{}", hashedRefreshToken);
    Poco::Int64 int64ResultOfCmd = redisClient_.execute<Poco::Int64>(cmd);

    if (int64ResultOfCmd == 0) {
        throw HandlersException(std::format("Bad refresh token"), 
            Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
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
        throw HandlersException(std::format("Refresh token used from unauthorized device"), 
            Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
    }

    Poco::Data::Session session = sessionPool_.get();
    Poco::Data::Statement stmt(session);
        
    std::string userRole;
    stmt << "SELECT role FROM users WHERE id = $1",
        Poco::Data::Keywords::use(userId),
        Poco::Data::Keywords::into(userRole);
    
    if (stmt.execute() == 0) {
        throw HandlersException(std::format("Internal server error. Try repeating the request"), 
            Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
    }

    // Формируем полезную нагрузку для access-токена
    Devkit::Tokens::Payload jwtPayload =
    {
        .sub = userId,
        .role = userRole,
        .exp = std::chrono::duration_cast<std::chrono::seconds>((std::chrono::system_clock::now() + 
            Auth::Handlers::access_token_validity_period).time_since_epoch())
    };

    // Генерируем access и refresh токены
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
catch (const Auth::Handlers::HandlersException & e)
{
    res.setStatusAndReason(e.status());
    sendJsonResponse(res, "error", e.what());
}
catch (...)
{
    res.setStatusAndReason(Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
    sendJsonResponse(res, "error", "Internal server error");
}

void ErrorHandler::handleRequest(Poco::Net::HTTPServerRequest & req, Poco::Net::HTTPServerResponse & res)
{
    res.setStatusAndReason(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
    sendJsonResponse(res, "error", "Non-existent URL");
}

} // namespace FQW::Auth::Handlers
