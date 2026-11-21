#pragma once
#include "oblivion/types.hpp"
namespace oblivion { [[nodiscard]] erase_options load_default_erase_options(); [[nodiscard]] bool save_default_erase_options(const erase_options&); [[nodiscard]] bool reset_default_erase_options(); }
