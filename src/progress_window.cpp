#include "oblivion/progress_window.hpp"
#include "oblivion/ui_icons.hpp"
#include "oblivion/ui_theme.hpp"
#include <CommCtrl.h>
#include <Windows.h>
#include <shobjidl.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cwchar>
#include <exception>
#include <mutex>
#include <sstream>
#include <thread>
namespace oblivion {
namespace {
constexpr UINT WM_P = WM_APP + 41, WM_D = WM_APP + 42;
constexpr int ID_CANCEL = 1001, ID_EDIT = 2001, ID_OK = 2002, ID_NO = 2003;
void font(HWND h) {
  SendMessageW(h, WM_SETFONT,
               reinterpret_cast<WPARAM>(GetStockObject(DEFAULT_GUI_FONT)),
               TRUE);
}
HBRUSH window_brush() noexcept { return GetSysColorBrush(COLOR_WINDOW); }
LRESULT paint_static(HDC dc) noexcept {
  SetBkMode(dc, OPAQUE);
  SetBkColor(dc, GetSysColor(COLOR_WINDOW));
  SetTextColor(dc, GetSysColor(COLOR_WINDOWTEXT));
  return reinterpret_cast<LRESULT>(window_brush());
}
std::wstring rate(double v) {
  wchar_t b[64]{};
  double m = v / (1024.0 * 1024.0);
  if (m >= 1024)
    swprintf_s(b, L"%.2f GiB/s", m / 1024.0);
  else
    swprintf_s(b, L"%.1f MiB/s", m);
  return b;
}
struct state {
  HWND wnd{}, file{}, phase{}, stats{}, bar{}, cancel{};
  ITaskbarList3 *taskbar{nullptr};
  std::atomic_bool stop{false};
  std::mutex m;
  progress_info latest;
  gui_run_result result;
  bool done{false};
  std::chrono::steady_clock::time_point start{std::chrono::steady_clock::now()};
};
void update(state &s) {
  progress_info i;
  {
    std::scoped_lock l(s.m);
    i = s.latest;
  }
  SetWindowTextW(s.file, i.current.wstring().c_str());
  std::wstring p = i.phase;
  if (!i.pass_name.empty())
    p += L" · Pass " + std::to_wstring(i.pass_index) + L"/" +
         std::to_wstring(i.pass_count) + L" · " + i.pass_name;
  SetWindowTextW(s.phase, p.c_str());
  auto d = i.overall_total ? i.overall_completed : i.completed,
       t = i.overall_total ? i.overall_total : i.total;
  unsigned pc = t ? static_cast<unsigned>((std::min)(
                        100.0L, static_cast<long double>(d) * 100.0L /
                                    static_cast<long double>(t)))
                  : 0;
  SendMessageW(s.bar, PBM_SETPOS, pc, 0);
  if (s.taskbar) {
    s.taskbar->SetProgressValue(s.wnd, pc, 100);
  }
  double elapsed = std::chrono::duration<double>(
                       std::chrono::steady_clock::now() - s.start)
                       .count(),
         through = elapsed > .05
                       ? static_cast<double>(i.overall_total
                                                 ? i.overall_completed
                                                 : i.bytes_written_total) /
                             elapsed
                       : 0;
  std::wostringstream x;
  x << (i.overall_total ? L"Gesamt " : L"") << pc << L" %";
  if (through > 0)
    x << L" · " << rate(through);
  if (d && t > d && elapsed > .05)
    x << L" · ETA ~ "
      << static_cast<unsigned long long>(elapsed * static_cast<double>(t - d) /
                                         static_cast<double>(d))
      << L" s";
  SetWindowTextW(s.stats, x.str().c_str());
}
LRESULT CALLBACK proc(HWND h, UINT m, WPARAM w, LPARAM l) {
  auto *s = reinterpret_cast<state *>(GetWindowLongPtrW(h, GWLP_USERDATA));
  switch (m) {
  case WM_NCCREATE: {
    auto *c = reinterpret_cast<CREATESTRUCTW *>(l);
    s = static_cast<state *>(c->lpCreateParams);
    SetWindowLongPtrW(h, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(s));
    s->wnd = h;
    return TRUE;
  }
  case WM_CREATE:
    if (!s)
      return -1;
    set_window_icons(h, IDI_OBLIVION_PROGRESS);
    apply_window_theme(h);
    CoCreateInstance(CLSID_TaskbarList, nullptr, CLSCTX_INPROC_SERVER,
                     IID_ITaskbarList3,
                     reinterpret_cast<void **>(&s->taskbar));
    if (s->taskbar) {
      s->taskbar->HrInit();
      s->taskbar->SetProgressState(h, TBPF_NORMAL);
    }
    s->file =
        CreateWindowExW(0, L"STATIC", L"Vorbereitung …", WS_CHILD | WS_VISIBLE,
                        18, 18, 684, 44, h, nullptr, nullptr, nullptr);
    s->phase = CreateWindowExW(0, L"STATIC", L"Analyse", WS_CHILD | WS_VISIBLE,
                               18, 66, 684, 24, h, nullptr, nullptr, nullptr);
    s->bar = CreateWindowExW(0, PROGRESS_CLASSW, nullptr,
                             WS_CHILD | WS_VISIBLE | PBS_SMOOTH, 18, 98, 684,
                             24, h, nullptr, nullptr, nullptr);
    SendMessageW(s->bar, PBM_SETRANGE32, 0, 100);
    s->stats = CreateWindowExW(0, L"STATIC", L"0 %", WS_CHILD | WS_VISIBLE, 18,
                               132, 520, 24, h, nullptr, nullptr, nullptr);
    s->cancel = CreateWindowExW(
        0, L"BUTTON", L"Abbrechen", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 568,
        164, 134, 32, h,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_CANCEL)), nullptr,
        nullptr);
    font(s->file);
    font(s->phase);
    font(s->stats);
    font(s->cancel);
    return 0;
  case WM_ERASEBKGND:
    if (w) {
      RECT rc{};
      GetClientRect(h, &rc);
      FillRect(reinterpret_cast<HDC>(w), &rc,
               is_dark_theme() ? get_dark_background_brush() : window_brush());
      return 1;
    }
    break;
  case WM_CTLCOLORDLG:
  case WM_CTLCOLORSTATIC:
  case WM_CTLCOLORBTN: {
    LRESULT themed = 0;
    if (handle_theme_colors(h, m, w, l, themed))
      return themed;
    if (m == WM_CTLCOLORSTATIC)
      return paint_static(reinterpret_cast<HDC>(w));
    break;
  }
  case WM_COMMAND:
    if (s && LOWORD(w) == ID_CANCEL) {
      s->stop = true;
      if (s->taskbar) {
        s->taskbar->SetProgressState(h, TBPF_PAUSED);
      }
      EnableWindow(s->cancel, FALSE);
      SetWindowTextW(s->phase, L"Abbruch angefordert …");
      return 0;
    }
    break;
  case WM_P:
    if (s) {
      update(*s);
      return 0;
    }
    break;
  case WM_D:
    if (s) {
      s->done = true;
      DestroyWindow(h);
      return 0;
    }
    break;
  case WM_CLOSE:
    if (s && !s->done) {
      s->stop = true;
      EnableWindow(s->cancel, FALSE);
      return 0;
    }
    DestroyWindow(h);
    return 0;
  case WM_DESTROY:
    if (s && s->taskbar) {
      s->taskbar->SetProgressState(h, TBPF_NOPROGRESS);
      s->taskbar->Release();
      s->taskbar = nullptr;
    }
    PostQuitMessage(0);
    return 0;
  }
  return DefWindowProcW(h, m, w, l);
}
struct cstate {
  std::wstring msg, req;
  HWND edit{};
  bool yes{false}, done{false};
};
LRESULT CALLBACK cproc(HWND h, UINT m, WPARAM w, LPARAM l) {
  auto *s = reinterpret_cast<cstate *>(GetWindowLongPtrW(h, GWLP_USERDATA));
  switch (m) {
  case WM_NCCREATE: {
    auto *c = reinterpret_cast<CREATESTRUCTW *>(l);
    s = static_cast<cstate *>(c->lpCreateParams);
    SetWindowLongPtrW(h, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(s));
    return TRUE;
  }
  case WM_CREATE: {
    if (!s)
      return -1;
    set_window_icons(h, IDI_OBLIVION_WARNING);
    apply_window_theme(h);
    auto t =
        CreateWindowExW(0, L"STATIC", s->msg.c_str(), WS_CHILD | WS_VISIBLE, 18,
                        16, 584, 116, h, nullptr, nullptr, nullptr);
    auto ins = L"Zum Bestätigen exakt eingeben: " + s->req;
    auto i = CreateWindowExW(0, L"STATIC", ins.c_str(), WS_CHILD | WS_VISIBLE,
                             18, 138, 584, 24, h, nullptr, nullptr, nullptr);
    s->edit = CreateWindowExW(
        WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, 18, 166, 584, 30,
        h, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_EDIT)), nullptr,
        nullptr);
    auto ok = CreateWindowExW(
        0, L"BUTTON", L"Endgültig löschen",
        WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 338, 212, 128, 32, h,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_OK)), nullptr, nullptr);
    auto no = CreateWindowExW(
        0, L"BUTTON", L"Abbrechen", WS_CHILD | WS_VISIBLE, 474, 212, 128, 32, h,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_NO)), nullptr, nullptr);
    font(t);
    font(i);
    font(s->edit);
    font(ok);
    font(no);
    SetFocus(s->edit);
    return 0;
  }
  case WM_ERASEBKGND:
    if (w) {
      RECT rc{};
      GetClientRect(h, &rc);
      FillRect(reinterpret_cast<HDC>(w), &rc,
               is_dark_theme() ? get_dark_background_brush() : window_brush());
      return 1;
    }
    break;
  case WM_CTLCOLORDLG:
  case WM_CTLCOLORSTATIC:
  case WM_CTLCOLORBTN:
  case WM_CTLCOLOREDIT: {
    LRESULT themed = 0;
    if (handle_theme_colors(h, m, w, l, themed))
      return themed;
    if (m == WM_CTLCOLORSTATIC)
      return paint_static(reinterpret_cast<HDC>(w));
    break;
  }
  case WM_COMMAND:
    if (s && LOWORD(w) == ID_OK) {
      std::wstring v(
          static_cast<std::size_t>(GetWindowTextLengthW(s->edit)) + 1, L'\0');
      GetWindowTextW(s->edit, v.data(), static_cast<int>(v.size()));
      v.resize(wcslen(v.c_str()));
      if (v != s->req) {
        MessageBoxW(h, L"Bestätigungstext stimmt nicht.", L"Oblivion",
                    MB_OK | MB_ICONWARNING);
        return 0;
      }
      s->yes = true;
      s->done = true;
      DestroyWindow(h);
      return 0;
    }
    if (s && LOWORD(w) == ID_NO) {
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
}
ATOM reg(const wchar_t *n, WNDPROC p) {
  WNDCLASSEXW c{};
  c.cbSize = sizeof(c);
  c.style = CS_HREDRAW | CS_VREDRAW;
  c.lpfnWndProc = p;
  c.hInstance = GetModuleHandleW(nullptr);
  c.hCursor = LoadCursorW(nullptr, IDC_ARROW);
  c.hbrBackground = window_brush();
  c.lpszClassName = n;
  ATOM a = RegisterClassExW(&c);
  return !a && GetLastError() == ERROR_CLASS_ALREADY_EXISTS ? 1 : a;
}
} // namespace
gui_run_result run_progress_window(const std::wstring &title,
                                   const gui_worker &work) {
  INITCOMMONCONTROLSEX cc{sizeof(cc), ICC_PROGRESS_CLASS};
  InitCommonControlsEx(&cc);
  constexpr wchar_t cls[] = L"OblivionProgressV2";
  state s;
  if (!reg(cls, proc))
    return {false, false, 1,
            L"Fortschrittsfenster konnte nicht registriert werden."};
  HWND h = CreateWindowExW(WS_EX_APPWINDOW, cls, title.c_str(),
                           WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU |
                               WS_CLIPCHILDREN,
                           CW_USEDEFAULT, CW_USEDEFAULT, 738, 248, nullptr,
                           nullptr, GetModuleHandleW(nullptr), &s);
  if (!h)
    return {false, false, 1,
            L"Fortschrittsfenster konnte nicht erstellt werden."};
  ShowWindow(h, SW_SHOW);
  UpdateWindow(h);
  RedrawWindow(h, nullptr, nullptr,
               RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_UPDATENOW);
  std::thread th([&] {
    try {
      auto cb = [&](const progress_info &i) {
        {
          std::scoped_lock l(s.m);
          s.latest = i;
        }
        PostMessageW(s.wnd, WM_P, 0, 0);
        return !s.stop.load();
      };
      auto cancel = [&] { return s.stop.load(); };
      auto r = work(cb, cancel);
      {
        std::scoped_lock l(s.m);
        s.result = std::move(r);
      }
    } catch (...) {
      std::scoped_lock l(s.m);
      s.result = {false, false, 1, L"Interner Fehler."};
    }
    PostMessageW(s.wnd, WM_D, 0, 0);
  });
  MSG msg{};
  while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
    TranslateMessage(&msg);
    DispatchMessageW(&msg);
  }
  th.join();
  std::scoped_lock l(s.m);
  return s.result;
}
bool typed_confirmation(const std::wstring &t, const std::wstring &m,
                        const std::wstring &r) {
  constexpr wchar_t cls[] = L"OblivionConfirmV2";
  if (!reg(cls, cproc))
    return false;
  cstate s{m, r};
  HWND h = CreateWindowExW(WS_EX_TOPMOST | WS_EX_DLGMODALFRAME, cls, t.c_str(),
                           WS_CAPTION | WS_SYSMENU | WS_CLIPCHILDREN,
                           CW_USEDEFAULT,
                           CW_USEDEFAULT, 638, 296, nullptr, nullptr,
                           GetModuleHandleW(nullptr), &s);
  if (!h)
    return false;
  ShowWindow(h, SW_SHOW);
  UpdateWindow(h);
  RedrawWindow(h, nullptr, nullptr,
               RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_UPDATENOW);
  MSG msg{};
  while (!s.done && GetMessageW(&msg, nullptr, 0, 0) > 0) {
    if (!IsDialogMessageW(h, &msg)) {
      TranslateMessage(&msg);
      DispatchMessageW(&msg);
    }
  }
  return s.yes;
}
} // namespace oblivion
