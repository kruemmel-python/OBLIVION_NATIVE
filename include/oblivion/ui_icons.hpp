#pragma once

#include "oblivion/resource_ids.h"
#include <Windows.h>

namespace oblivion {
inline HICON load_ui_icon(const int resource_id, const int width, const int height) {
    return static_cast<HICON>(LoadImageW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(resource_id), IMAGE_ICON, width, height, LR_SHARED));
}

inline void set_window_icons(const HWND window, const int resource_id) {
    if (!window) return;
    if (const HICON large = load_ui_icon(resource_id, GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON)))
        SendMessageW(window, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(large));
    if (const HICON small = load_ui_icon(resource_id, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON)))
        SendMessageW(window, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(small));
}
}
