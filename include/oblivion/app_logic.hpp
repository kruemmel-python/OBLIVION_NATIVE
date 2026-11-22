#pragma once
#include "oblivion/progress_window.hpp"
#include "oblivion/types.hpp"
#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>
namespace oblivion {
inline constexpr std::size_t max_operation_targets = 4096;
struct prepared_operation { std::vector<std::filesystem::path> targets; file_analysis analysis; std::vector<storage_info> storage; std::vector<std::wstring> warnings; bool valid{false}; std::wstring error; };
[[nodiscard]] prepared_operation prepare_operation(const std::vector<std::filesystem::path>&);
[[nodiscard]] std::wstring format_prepared_analysis(const prepared_operation&);
[[nodiscard]] std::wstring confirmation_text(const prepared_operation&, const erase_options&);
[[nodiscard]] bool requires_typed_confirmation(const file_analysis&);
[[nodiscard]] bool requires_hardlink_confirmation(const erase_options&);
[[nodiscard]] std::vector<std::wstring> build_elevation_arguments(
    const erase_options&, const std::vector<std::filesystem::path>&);
[[nodiscard]] gui_run_result execute_prepared_operation(const prepared_operation&, const erase_options&, const progress_callback&, const std::function<bool()>&);
}
