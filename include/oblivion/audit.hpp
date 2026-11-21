#pragma once
#include "oblivion/types.hpp"
#include <filesystem>
namespace oblivion {
[[nodiscard]] std::filesystem::path audit_directory();
[[nodiscard]] std::filesystem::path write_audit_record(const operation_audit &);
[[nodiscard]] std::wstring create_operation_id();
} // namespace oblivion
