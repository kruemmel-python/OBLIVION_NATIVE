#pragma once

#include <filesystem>
#include <string>
#include <string_view>

namespace oblivion {

[[nodiscard]] std::wstring audit_reference(std::wstring_view value) noexcept;
[[nodiscard]] bool seal_audit_file(const std::filesystem::path &file) noexcept;
[[nodiscard]] bool seal_audit_file_contents(const std::filesystem::path &file,
                                            std::string_view contents) noexcept;
[[nodiscard]] bool verify_audit_file(const std::filesystem::path &file) noexcept;
[[nodiscard]] bool
verify_audit_chain(const std::filesystem::path &audit_dir) noexcept;

} // namespace oblivion
