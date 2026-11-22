#pragma once
#include "oblivion/types.hpp"
#include <Windows.h>
#include <functional>
#include <string>
#include <vector>
namespace oblivion {
struct gui_run_result {
  bool completed{false}, cancelled{false};
  int exit_code{0};
  std::wstring summary;
  std::vector<std::filesystem::path> elevation_retry_targets;
};
using gui_worker = std::function<gui_run_result(const progress_callback&, const std::function<bool()>&)>;
[[nodiscard]] gui_run_result run_progress_window(const std::wstring&,
                                                 const gui_worker&,
                                                 HWND owner = nullptr);
[[nodiscard]] bool typed_confirmation(const std::wstring&, const std::wstring&, const std::wstring& = L"OBLIVION");
}
