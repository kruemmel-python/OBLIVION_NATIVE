#pragma once

#include <filesystem>
#include <string>

namespace oblivion {

[[nodiscard]] bool generate_certificate_from_audit(
    const std::filesystem::path &audit_file,
    const std::filesystem::path &output_html_file);

} // namespace oblivion
