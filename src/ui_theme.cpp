#include "oblivion/ui_theme.hpp"

#include <dwmapi.h>
#include <uxtheme.h>

namespace oblivion {

bool is_dark_theme() {
  HKEY key = nullptr;
  if (RegOpenKeyExW(
          HKEY_CURRENT_USER,
          L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
          0, KEY_READ, &key) != ERROR_SUCCESS) {
    return false;
  }
  DWORD val = 1;
  DWORD size = sizeof(val);
  DWORD type = 0;
  bool is_dark = false;
  if (RegQueryValueExW(key, L"AppsUseLightTheme", nullptr, &type,
                       reinterpret_cast<LPBYTE>(&val), &size) == ERROR_SUCCESS) {
    is_dark = (val == 0);
  }
  RegCloseKey(key);
  return is_dark;
}

void apply_window_theme(HWND hwnd) {
  if (!hwnd)
    return;
  const BOOL dark = is_dark_theme() ? TRUE : FALSE;

  // DWMWA_USE_IMMERSIVE_DARK_MODE is 20 in Win11 / Win10 2004+, 19 in 1809/1903
  constexpr DWORD DWMWA_USE_IMMERSIVE_DARK_MODE_NEW = 20;
  constexpr DWORD DWMWA_USE_IMMERSIVE_DARK_MODE_OLD = 19;
  if (FAILED(DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE_NEW,
                                   &dark, sizeof(dark)))) {
    DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE_OLD, &dark,
                          sizeof(dark));
  }

  if (dark) {
    SetWindowTheme(hwnd, L"DarkMode_Explorer", nullptr);
  }
}

HBRUSH get_dark_background_brush() {
  static HBRUSH brush = CreateSolidBrush(RGB(32, 32, 32));
  return brush;
}

HBRUSH get_dark_control_brush() {
  static HBRUSH brush = CreateSolidBrush(RGB(48, 48, 48));
  return brush;
}

bool handle_theme_colors(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam,
                         LRESULT &result) {
  (void)hwnd;
  (void)lparam;
  if (!is_dark_theme())
    return false;

  const auto hdc = reinterpret_cast<HDC>(wparam);
  switch (msg) {
  case WM_CTLCOLORDLG:
    result = reinterpret_cast<LRESULT>(get_dark_background_brush());
    return true;

  case WM_CTLCOLORSTATIC:
    SetTextColor(hdc, RGB(240, 240, 240));
    SetBkColor(hdc, RGB(32, 32, 32));
    result = reinterpret_cast<LRESULT>(get_dark_background_brush());
    return true;

  case WM_CTLCOLORBTN:
    SetTextColor(hdc, RGB(240, 240, 240));
    SetBkColor(hdc, RGB(48, 48, 48));
    result = reinterpret_cast<LRESULT>(get_dark_control_brush());
    return true;

  case WM_CTLCOLORLISTBOX:
  case WM_CTLCOLOREDIT:
    SetTextColor(hdc, RGB(255, 255, 255));
    SetBkColor(hdc, RGB(48, 48, 48));
    result = reinterpret_cast<LRESULT>(get_dark_control_brush());
    return true;

  default:
    return false;
  }
}

} // namespace oblivion
