#pragma once
#include <filesystem>
#include <string>
namespace oblivion { struct shell_result{ bool success{false}; std::wstring message; }; [[nodiscard]] shell_result install_context_menu(const std::filesystem::path&, const std::filesystem::path& = {}); [[nodiscard]] shell_result uninstall_context_menu(); }
