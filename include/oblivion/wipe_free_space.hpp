#pragma once

#include "oblivion/types.hpp"
#include <filesystem>

namespace oblivion {

[[nodiscard]] erase_result wipe_volume_free_space(
    const std::filesystem::path &target_volume_or_path,
    const erase_options &options,
    const progress_callback &callback);

} // namespace oblivion
