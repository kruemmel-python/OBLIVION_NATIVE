#pragma once
#include "oblivion/types.hpp"
namespace oblivion { class storage_inspector final { public: [[nodiscard]] storage_info inspect(const std::filesystem::path&) const; }; }
