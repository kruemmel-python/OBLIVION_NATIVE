#pragma once

#include <string>

namespace oblivion {

struct runtime_hardening_status {
  bool safe_dll_search{false};
  bool heap_corruption_termination{false};
  bool dynamic_code_prohibited{false};
  bool strict_handle_checks{false};
  bool legacy_extension_points_disabled{false};
  bool unsafe_images_blocked{false};
  bool microsoft_signed_binaries_only{false};

  [[nodiscard]] bool complete() const noexcept {
    return safe_dll_search && heap_corruption_termination &&
           dynamic_code_prohibited && strict_handle_checks &&
           legacy_extension_points_disabled && unsafe_images_blocked &&
           microsoft_signed_binaries_only;
  }
};

[[nodiscard]] runtime_hardening_status harden_current_process() noexcept;
[[nodiscard]] std::wstring
format_runtime_hardening(const runtime_hardening_status &status);

} // namespace oblivion
