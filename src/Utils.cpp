#include <stdexcept>

#include <sodium.h>
#include <jwt-cpp/jwt.h>

#include <Utils.h>

namespace Auth::Utils
{

void libsodiumInitialize()
{
    if (sodium_init() < 0) {
        throw std::runtime_error("Failed to initialize libsodium");
    }
}

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



namespace
{

const std::string key_ = "secret1";
const std::string_view letters_ = 
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

} // namespace

std::string createAccessToken(const Devkit::Tokens::Payload& p) noexcept
{
    return jwt::create()
        .set_subject(std::to_string(p.sub))
        .set_payload_claim("role", jwt::claim(p.role))
        .set_expires_at(std::chrono::system_clock::now() + p.exp)
        .sign(jwt::algorithm::hs256{key_});
}

std::string createRefreshToken() noexcept
{
    std::string token;

    for (size_t i = 0; i < refresh_token_size; ++i) 
    {
        size_t index = rand() % letters_.size();
        token += letters_[index];
    }

    return token; 
}

} // namespace Auth::Utils
