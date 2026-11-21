#pragma once

namespace oblivion {

/// Launches the interactive Oblivion Native Control Center window and returns
/// the process exit code once the window closes.
[[nodiscard]] int show_main_window();

} // namespace oblivion
