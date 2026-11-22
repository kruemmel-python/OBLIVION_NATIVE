#include "oblivion/settings_window.hpp"
#include "oblivion/settings.hpp"
#include "oblivion/ui_icons.hpp"
#include "oblivion/ui_theme.hpp"
#include <Windows.h>
#include <cstdlib>
#include <cwchar>
#include <initializer_list>
#include <iterator>
#include <string>
#include <tuple>
namespace oblivion {
namespace {
constexpr int MODE = 3101, VERIFY = 3102, ADS = 3103, RENAME = 3104,
              ROUNDS = 3105, HARD = 3106, SAVE = 3107, DEFAULTS = 3108,
              CANCEL = 3109;
struct st {
  HWND mode{}, verify{}, ads{}, rename{}, rounds{}, hard{};
  erase_options o{load_default_erase_options()};
  bool done{false}, saved{false};
};
void font(HWND h) {
  SendMessageW(h, WM_SETFONT,
               reinterpret_cast<WPARAM>(GetStockObject(DEFAULT_GUI_FONT)),
               TRUE);
}
HWND label(HWND p, const wchar_t *t, int x, int y, int w, int h) {
  auto c = CreateWindowExW(0, L"STATIC", t, WS_CHILD | WS_VISIBLE, x, y, w, h,
                           p, nullptr, GetModuleHandleW(nullptr), nullptr);
  font(c);
  return c;
}
void set(st &s) {
  SendMessageW(s.mode, CB_SETCURSEL, static_cast<WPARAM>(s.o.mode), 0);
  SendMessageW(s.verify, BM_SETCHECK, s.o.verify ? BST_CHECKED : BST_UNCHECKED,
               0);
  SendMessageW(s.ads, BM_SETCHECK,
               s.o.erase_alternate_streams ? BST_CHECKED : BST_UNCHECKED, 0);
  SendMessageW(s.rename, BM_SETCHECK,
               s.o.rename_before_delete ? BST_CHECKED : BST_UNCHECKED, 0);
  SetWindowTextW(s.rounds, std::to_wstring(s.o.rename_rounds).c_str());
  SendMessageW(s.hard, CB_SETCURSEL,
               s.o.hardlinks == hardlink_policy::delete_link_only ? 1 : 0, 0);
  EnableWindow(s.rounds, s.o.rename_before_delete);
}
bool read(HWND h, st &s) {
  LRESULT m = SendMessageW(s.mode, CB_GETCURSEL, 0, 0);
  if (m < 0 || m > 6)
    return false;
  wchar_t b[16]{};
  GetWindowTextW(s.rounds, b, 16);
  wchar_t *e = nullptr;
  unsigned long r = std::wcstoul(b, &e, 10);
  if (e == b || *e || r > 32) {
    MessageBoxW(h, L"Rename-Runden müssen 0..32 sein.", L"Oblivion",
                MB_OK | MB_ICONWARNING);
    return false;
  }
  s.o.mode = static_cast<erase_mode>(m);
  s.o.verify = SendMessageW(s.verify, BM_GETCHECK, 0, 0) == BST_CHECKED;
  s.o.erase_alternate_streams =
      SendMessageW(s.ads, BM_GETCHECK, 0, 0) == BST_CHECKED;
  s.o.rename_before_delete =
      SendMessageW(s.rename, BM_GETCHECK, 0, 0) == BST_CHECKED;
  s.o.rename_rounds = static_cast<unsigned>(r);
  s.o.hardlinks = SendMessageW(s.hard, CB_GETCURSEL, 0, 0) == 1
                      ? hardlink_policy::delete_link_only
                      : hardlink_policy::block;
  return true;
}
LRESULT CALLBACK proc(HWND h, UINT m, WPARAM w, LPARAM l) noexcept try {
  auto *s = reinterpret_cast<st *>(GetWindowLongPtrW(h, GWLP_USERDATA));
  switch (m) {
  case WM_NCCREATE: {
    auto *c = reinterpret_cast<CREATESTRUCTW *>(l);
    s = static_cast<st *>(c->lpCreateParams);
    SetWindowLongPtrW(h, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(s));
    return TRUE;
  }
  case WM_CREATE: {
    if (!s)
      return -1;
    set_window_icons(h, IDI_OBLIVION_SETTINGS);
    apply_window_theme(h);
    label(h, L"Standard-Löschmodus", 24, 24, 185, 24);
    s->mode = CreateWindowExW(
        0, L"COMBOBOX", L"", WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST, 224, 20,
        260, 140, h, reinterpret_cast<HMENU>(static_cast<INT_PTR>(MODE)),
        nullptr, nullptr);
    font(s->mode);
    for (auto *t : {L"FAST · Random (1 Pass)",
                    L"STANDARD · Random + Zero (2 Passes)",
                    L"STRONG · Random + Zero + Random (3 Passes)",
                    L"DoD 5220.22-M · Zero + Ones + Random (3 Passes)",
                    L"NIST SP 800-88 · Zero Clear + Readback (1 Pass)",
                    L"BSI IT-Grundschutz · Random + Ones + Random (3 Passes)",
                    L"Gutmann · 35 Passes (Legacy Magnetic)"})
      SendMessageW(s->mode, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(t));
    s->verify = CreateWindowExW(
        0, L"BUTTON", L"Readback-Verifikation",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 24, 68, 460, 26, h,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(VERIFY)), nullptr,
        nullptr);
    s->ads = CreateWindowExW(
        0, L"BUTTON", L"NTFS Alternate Data Streams mitbearbeiten",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 24, 102, 460, 26, h,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(ADS)), nullptr, nullptr);
    s->rename = CreateWindowExW(
        0, L"BUTTON", L"Metadaten-Umbenennung vor Löschen",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 24, 136, 460, 26, h,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(RENAME)), nullptr,
        nullptr);
    font(s->verify);
    font(s->ads);
    font(s->rename);
    label(h, L"Rename-Runden (0–32)", 48, 174, 176, 24);
    s->rounds = CreateWindowExW(
        WS_EX_CLIENTEDGE, L"EDIT", L"3", WS_CHILD | WS_VISIBLE | ES_NUMBER, 224,
        170, 72, 28, h, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ROUNDS)),
        nullptr, nullptr);
    font(s->rounds);
    label(h, L"Hardlinks standardmäßig", 24, 216, 185, 24);
    s->hard = CreateWindowExW(
        0, L"COMBOBOX", L"", WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST, 224, 212,
        300, 100, h, reinterpret_cast<HMENU>(static_cast<INT_PTR>(HARD)),
        nullptr, nullptr);
    font(s->hard);
    SendMessageW(s->hard, CB_ADDSTRING, 0,
                 reinterpret_cast<LPARAM>(L"Inhaltsüberschreibung blockieren"));
    SendMessageW(s->hard, CB_ADDSTRING, 0,
                 reinterpret_cast<LPARAM>(L"Nur Linknamen entfernen"));
    label(h, L"Shared-Content-Overwrite wird nie als Standard gespeichert.", 24,
          252, 560, 30);
    for (auto z : std::initializer_list<std::tuple<const wchar_t *, int, int>>{
             {L"Standardwerte", DEFAULTS, 24},
             {L"Speichern", SAVE, 336},
             {L"Abbrechen", CANCEL, 456}}) {
      auto b = CreateWindowExW(
          0, L"BUTTON", std::get<0>(z), WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
          std::get<2>(z), 308, 112, 32, h,
          reinterpret_cast<HMENU>(static_cast<INT_PTR>(std::get<1>(z))),
          nullptr, nullptr);
      font(b);
    }
    set(*s);
    return 0;
  }
  case WM_ERASEBKGND:
    if (w) {
      RECT rc{};
      GetClientRect(h, &rc);
      FillRect(reinterpret_cast<HDC>(w), &rc,
               is_dark_theme() ? get_dark_background_brush()
                               : GetSysColorBrush(COLOR_BTNFACE));
      return 1;
    }
    break;
  case WM_CTLCOLORDLG:
  case WM_CTLCOLORSTATIC:
  case WM_CTLCOLORBTN:
  case WM_CTLCOLOREDIT:
  case WM_CTLCOLORLISTBOX: {
    LRESULT themed = 0;
    if (handle_theme_colors(h, m, w, l, themed))
      return themed;
    break;
  }
  case WM_COMMAND:
    if (!s)
      break;
    if (LOWORD(w) == RENAME) {
      EnableWindow(s->rounds,
                   SendMessageW(s->rename, BM_GETCHECK, 0, 0) == BST_CHECKED);
      return 0;
    }
    if (LOWORD(w) == DEFAULTS) {
      s->o = erase_options{};
      set(*s);
      return 0;
    }
    if (LOWORD(w) == SAVE) {
      if (!read(h, *s))
        return 0;
      if (!save_default_erase_options(s->o)) {
        MessageBoxW(h, L"Speichern fehlgeschlagen.", L"Oblivion",
                    MB_OK | MB_ICONERROR);
        return 0;
      }
      s->saved = true;
      s->done = true;
      DestroyWindow(h);
      return 0;
    }
    if (LOWORD(w) == CANCEL) {
      s->done = true;
      DestroyWindow(h);
      return 0;
    }
    break;
  case WM_CLOSE:
    if (s)
      s->done = true;
    DestroyWindow(h);
    return 0;
  }
  return DefWindowProcW(h, m, w, l);
} catch (...) {
  auto *failed =
      reinterpret_cast<st *>(GetWindowLongPtrW(h, GWLP_USERDATA));
  if (failed) {
    failed->saved = false;
    failed->done = true;
  }
  SetWindowLongPtrW(h, GWLP_USERDATA, 0);
  if (IsWindow(h))
    DestroyWindow(h);
  return 0;
}
ATOM reg() {
  constexpr wchar_t n[] = L"OblivionSettingsV2";
  WNDCLASSEXW c{};
  c.cbSize = sizeof(c);
  c.lpfnWndProc = proc;
  c.hInstance = GetModuleHandleW(nullptr);
  c.hCursor = LoadCursorW(nullptr, IDC_ARROW);
  c.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
  c.lpszClassName = n;
  ATOM a = RegisterClassExW(&c);
  return !a && GetLastError() == ERROR_CLASS_ALREADY_EXISTS ? 1 : a;
}
} // namespace
bool show_settings_window(HWND owner) {
  if (!reg())
    return false;
  st s;
  constexpr wchar_t n[] = L"OblivionSettingsV2";
  HWND h = CreateWindowExW(WS_EX_DLGMODALFRAME | WS_EX_CONTROLPARENT, n,
                           L"OBLIVION · Optionen", WS_CAPTION | WS_SYSMENU,
                           CW_USEDEFAULT, CW_USEDEFAULT, 610, 400, owner,
                           nullptr, GetModuleHandleW(nullptr), &s);
  if (!h)
    return false;
  if (owner)
    EnableWindow(owner, FALSE);
  ShowWindow(h, SW_SHOW);
  MSG msg{};
  bool repost_quit = false;
  int quit_code = 0;
  while (!s.done) {
    const BOOL message_result = GetMessageW(&msg, nullptr, 0, 0);
    if (message_result <= 0) {
      if (message_result == 0) {
        repost_quit = true;
        quit_code = static_cast<int>(msg.wParam);
      }
      break;
    }
    if (!IsDialogMessageW(h, &msg)) {
      TranslateMessage(&msg);
      DispatchMessageW(&msg);
    }
  }
  if (IsWindow(h)) {
    s.done = true;
    DestroyWindow(h);
  }
  if (owner) {
    EnableWindow(owner, TRUE);
    SetForegroundWindow(owner);
  }
  if (repost_quit)
    PostQuitMessage(quit_code);
  return s.saved;
}
} // namespace oblivion
