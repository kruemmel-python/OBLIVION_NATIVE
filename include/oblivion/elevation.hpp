#pragma once
#include <filesystem>
#include <string>
#include <vector>
namespace oblivion { [[nodiscard]] bool is_process_elevated(); [[nodiscard]] bool relaunch_elevated(const std::filesystem::path&, const std::vector<std::wstring>&); }
