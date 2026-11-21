#pragma once
#include "oblivion/types.hpp"
#include <filesystem>
#include <vector>
namespace oblivion { class analyzer final { public: [[nodiscard]] file_analysis analyze(const std::filesystem::path&) const; [[nodiscard]] file_analysis analyze(const std::vector<std::filesystem::path>&) const; }; [[nodiscard]] std::wstring format_analysis_report(const file_analysis&, const storage_info* = nullptr); }
