#include "oblivion/random.hpp"
#include <Windows.h>
#include <algorithm>
#include <bcrypt.h>
#include <limits>
#include <stdexcept>
#ifdef OBLIVION_TESTING
#include "oblivion/test_hooks.hpp"
#endif
namespace oblivion {
bool try_fill_secure_random(std::span<std::byte> buffer) noexcept {
#ifdef OBLIVION_TESTING
  if (const auto provider = testing::hooks().random)
    return provider(buffer);
#endif
  std::size_t off = 0;
  while (off < buffer.size()) {
    const auto chunk = static_cast<ULONG>((std::min)(
        buffer.size() - off,
        static_cast<std::size_t>((std::numeric_limits<ULONG>::max)())));
    if (BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(buffer.data() + off),
                        chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
      return false;
    off += chunk;
  }
  return true;
}
void fill_secure_random(std::span<std::byte> buffer) {
  if (!try_fill_secure_random(buffer))
    throw std::runtime_error("BCryptGenRandom failed");
}
} // namespace oblivion
