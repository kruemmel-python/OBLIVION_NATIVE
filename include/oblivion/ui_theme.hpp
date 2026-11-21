#pragma once

#include <Windows.h>

namespace oblivion {

[[nodiscard]] bool is_dark_theme();
void apply_window_theme(HWND hwnd);
[[nodiscard]] HBRUSH get_dark_background_brush();
[[nodiscard]] HBRUSH get_dark_control_brush();
bool handle_theme_colors(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam, LRESULT &result);

} // namespace oblivion
