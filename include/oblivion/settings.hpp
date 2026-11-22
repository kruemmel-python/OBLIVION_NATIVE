#pragma once
#include "oblivion/types.hpp"
namespace oblivion {
[[nodiscard]] erase_options load_default_erase_options();
void apply_security_policy(erase_options &) noexcept;
[[nodiscard]] bool shared_hardlink_overwrite_allowed() noexcept;
[[nodiscard]] bool save_default_erase_options(const erase_options &);
[[nodiscard]] bool reset_default_erase_options();
}
