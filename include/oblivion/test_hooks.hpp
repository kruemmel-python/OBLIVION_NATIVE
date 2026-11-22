#pragma once

// This header is intentionally available only to the dedicated test build.
// Production targets do not compile OBLIVION_TESTING and therefore contain no
// injectable platform behaviour.
#ifndef OBLIVION_TESTING
#error "oblivion/test_hooks.hpp is restricted to the test build"
#endif

#include "oblivion/random.hpp"
#include "oblivion/recycle_bin.hpp"

#include <Windows.h>
#include <shellapi.h>

#include <cstdint>
#include <system_error>

namespace oblivion::testing {

using random_provider = bool (*)(std::span<std::byte>) noexcept;
using flush_provider = BOOL(WINAPI *)(HANDLE);
using audit_directory_provider = std::filesystem::path (*)();
using recycle_scan_provider = recycle_bin_scan_result (*)();
using recycle_query_provider = HRESULT(WINAPI *)(LPCWSTR, LPSHQUERYRBINFO);
using recycle_erase_provider = erase_result (*)(const std::filesystem::path &,
                                                 const erase_options &,
                                                 const progress_callback &);
using recycle_exists_provider = bool (*)(const std::filesystem::path &,
                                         std::error_code &);

struct platform_hooks {
  random_provider random{};
  flush_provider flush{};
  audit_directory_provider audit_directory{};
  std::size_t analysis_max_entries{};
  std::uint64_t wipe_max_chunk_bytes{};
  recycle_scan_provider recycle_scan{};
  recycle_query_provider recycle_query{};
  recycle_erase_provider recycle_erase{};
  recycle_exists_provider recycle_exists{};
};

platform_hooks &hooks() noexcept;
void reset_hooks() noexcept;

} // namespace oblivion::testing
