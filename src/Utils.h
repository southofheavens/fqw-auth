#ifndef __UTILS_H__
#define __UTILS_H__

#include <chrono>

namespace FQW::Auth::Utils
{

constexpr uint8_t refresh_token_size = 64; // TODO delete
constexpr uint8_t lookup_key_length = 6; 

constexpr std::chrono::seconds access_token_validity_period = std::chrono::seconds(15 * 60);
constexpr std::chrono::seconds refresh_token_validity_period = std::chrono::seconds(30 * 24 * 60 * 60);

} // namespace FQW::Auth::Utils

#endif // __UTILS_H__
