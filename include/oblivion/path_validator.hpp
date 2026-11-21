#pragma once
#include "oblivion/types.hpp"
namespace oblivion {
class path_validator final {
public:
  explicit path_validator(bool allow_remote = false,
                          bool allow_recycle_bin_items = false)
      : allow_remote_(allow_remote),
        allow_recycle_bin_items_(allow_recycle_bin_items) {}
  [[nodiscard]] validation_result validate(const std::filesystem::path &) const;

private:
  bool allow_remote_{false};
  bool allow_recycle_bin_items_{false};
};
} // namespace oblivion
