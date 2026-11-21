#pragma once
#include "oblivion/types.hpp"
namespace oblivion {
class erase_engine final {
public:
  [[nodiscard]] erase_result erase(const std::filesystem::path &,
                                   const erase_options &,
                                   const progress_callback & = {}) const;
  [[nodiscard]] erase_result
  erase_recycle_bin_item(const std::filesystem::path &, const erase_options &,
                         const progress_callback & = {}) const;

private:
  [[nodiscard]] erase_result erase_impl(const std::filesystem::path &,
                                        const erase_options &,
                                        const progress_callback &,
                                        bool allow_recycle_bin_items) const;
};
} // namespace oblivion
