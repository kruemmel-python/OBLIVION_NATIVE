#pragma once
#include "oblivion/types.hpp"
#include <filesystem>
#include <vector>
namespace oblivion { [[nodiscard]] std::vector<lock_owner> diagnose_lock_owners(const std::filesystem::path&); [[nodiscard]] std::wstring format_lock_owners(const std::vector<lock_owner>&); }
