#include "oblivion/test_hooks.hpp"

namespace oblivion::testing {
namespace {
platform_hooks active_hooks;
}

platform_hooks &hooks() noexcept { return active_hooks; }

void reset_hooks() noexcept { active_hooks = {}; }

} // namespace oblivion::testing
