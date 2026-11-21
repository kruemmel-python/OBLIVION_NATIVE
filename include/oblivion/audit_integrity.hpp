#pragma once

#include <filesystem>
#include <string>
#include <string_view>

namespace oblivion {

[[nodiscard]] std::wstring audit_reference(std::wstring_view value);
[[nodiscard]] bool seal_audit_file(const std::filesystem::path &file);
[[nodiscard]] bool verify_audit_file(const std::filesystem::path &file);
[[nodiscard]] bool verify_audit_chain(const std::filesystem::path &audit_dir);

} // namespace oblivion
