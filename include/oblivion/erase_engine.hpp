#pragma once
#include "oblivion/types.hpp"
namespace oblivion {
[[nodiscard]] bool valid_erase_options(const erase_options &) noexcept;
class erase_engine final {
public:
  [[nodiscard]] erase_result erase(const std::filesystem::path &,
                                   const erase_options &,
                                   const progress_callback & = {}) const noexcept;
  [[nodiscard]] erase_result
  erase_recycle_bin_item(const std::filesystem::path &, const erase_options &,
                         const progress_callback & = {}) const noexcept;

private:
  [[nodiscard]] erase_result erase_impl(const std::filesystem::path &,
                                        const erase_options &,
                                        const progress_callback &,
                                        bool allow_recycle_bin_items) const
      noexcept;
};
} // namespace oblivion
