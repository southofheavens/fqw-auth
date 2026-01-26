#include <iostream>
#include <format>
#include <unordered_set>
#include <chrono>
#include <fstream>

#include <Utils.h>

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

namespace FQW::Auth::Utils
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

} // namespace FQW::Auth::Utils
