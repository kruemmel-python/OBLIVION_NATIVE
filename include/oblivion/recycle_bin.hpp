#pragma once

#include "oblivion/erase_engine.hpp"
#include "oblivion/types.hpp"
#include <cstdint>
#include <filesystem>
#include <vector>

namespace oblivion {

struct recycle_bin_scan_result {
  std::vector<std::filesystem::path> items;
  bool complete{true};
  std::uint32_t win32_error{0};
  std::vector<std::filesystem::path> scanned_roots;
  std::vector<std::filesystem::path> scanned_volumes;
};

// Enumerates every supported local recycle-bin location.  A failed directory
// query makes the result incomplete; callers must then stop without deleting
// entries that have not been securely overwritten.
[[nodiscard]] recycle_bin_scan_result scan_recycle_bin_items() noexcept;

[[nodiscard]] std::vector<std::filesystem::path>
find_recycle_bin_items() noexcept;

[[nodiscard]] erase_result secure_empty_recycle_bin(
    const erase_options &options,
    const progress_callback &callback) noexcept;

} // namespace oblivion
