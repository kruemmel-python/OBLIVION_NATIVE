#pragma once
#include "oblivion/types.hpp"
#include <filesystem>
#include <string_view>
namespace oblivion {
[[nodiscard]] std::filesystem::path audit_directory();
[[nodiscard]] bool
prepare_audit_directory(std::filesystem::path &directory) noexcept;
[[nodiscard]] bool write_new_audit_file(const std::filesystem::path &file,
                                        std::string_view contents) noexcept;
[[nodiscard]] bool write_new_audit_file(const std::filesystem::path &file,
                                        std::wstring_view contents) noexcept;
[[nodiscard]] bool
write_sealed_audit_file(const std::filesystem::path &file,
                        std::wstring_view contents) noexcept;
[[nodiscard]] std::filesystem::path
write_audit_record(const operation_audit &) noexcept;
[[nodiscard]] std::wstring create_operation_id() noexcept;
} // namespace oblivion
