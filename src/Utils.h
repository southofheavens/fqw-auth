#ifndef __UTILS_H__
#define __UTILS_H__

#include <string>
#include <chrono>

#include <fqw-devkit/lib/Tokens.h>

namespace Auth::Utils
{

constexpr uint8_t refresh_token_size = 64;
constexpr uint8_t lookup_key_length = 6;

constexpr std::chrono::seconds access_token_validity_period = std::chrono::seconds(15 * 60);
constexpr std::chrono::seconds refresh_token_validity_period = std::chrono::seconds(30 * 24 * 60 * 60);

/**
 * @brief Инициализирует библиотеку libsodium
 * @throw std::runtime_error если инициализация не удалась
 */
void libsodiumInitialize();

/**
 * @brief Хэширует пароль используя Argon2 алгоритм
 * @param password Пароль для хэширования
 * @return std::string Хэшированный пароль в формате libsodium
 * @throw std::runtime_error если хэширование не удалось
 */
std::string hashPassword(const std::string& password);

/**
 * @brief Сравнивает пароль с хэшем
 * @param password Пароль для проверки
 * @param hash Хэш из базы данных
 * @return bool true если пароль верный, false если неверный
 * @throw std::runtime_error если проверка не удалась (системная ошибка)
 */
bool verifyPassword(const std::string& password, const std::string& hash);



/**
 * @brief Генерирует access токен, который представляет из себя JWT
 * @param p Полезная нагрузка
 * @return Токен
 */
std::string createAccessToken(const Devkit::Tokens::Payload& p) noexcept;

/**
 * @brief Генерирует refresh токен, который представляет из себя
 *        рандомно-сгенерированную строку из символов английского
 *        алфавита и цифр
 * @return Токен
 */
std::string createRefreshToken() noexcept;

} // namespace Auth::Utils

#endif // __UTILS_H__
