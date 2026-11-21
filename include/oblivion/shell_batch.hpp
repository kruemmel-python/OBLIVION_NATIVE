#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace oblivion {

enum class shell_batch_action { erase, analyze };

struct shell_batch_result {
  bool owner{false};
  bool success{false};
  std::vector<std::filesystem::path> targets;
  std::wstring error;
};

[[nodiscard]] shell_batch_result
collect_shell_batch(shell_batch_action action,
                    const std::filesystem::path &target,
                    std::uint32_t quiet_timeout_ms = 750,
                    std::uint32_t client_timeout_ms = 2000);

} // namespace oblivion
