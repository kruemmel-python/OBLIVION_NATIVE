#pragma once
#include <cstddef>
#include <span>
namespace oblivion {
bool try_fill_secure_random(std::span<std::byte>) noexcept;
void fill_secure_random(std::span<std::byte>);
}
