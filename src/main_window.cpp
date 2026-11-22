#include "oblivion/main_window.hpp"

#include "oblivion/app_logic.hpp"
#include "oblivion/audit.hpp"
#include "oblivion/certificate.hpp"
#include "oblivion/cotaskmem_string.hpp"
#include "oblivion/elevation.hpp"
#include "oblivion/progress_window.hpp"
#include "oblivion/recycle_bin.hpp"
#include "oblivion/resource_ids.h"
#include "oblivion/runtime_guard.hpp"
#include "oblivion/settings.hpp"
#include "oblivion/settings_window.hpp"
#include "oblivion/shell_integration.hpp"
#include "oblivion/ui_icons.hpp"
#include "oblivion/ui_theme.hpp"
#include "oblivion/wipe_free_space.hpp"

#include <CommCtrl.h>
#include <ShObjIdl.h>
#include <Windows.h>
#include <commdlg.h>
#include <shellapi.h>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace oblivion {
namespace {

template <typename T> class com_ptr {
  T *value_{};

public:
  com_ptr() = default;
  ~com_ptr() {
    if (value_)
      value_->Release();
  }
  com_ptr(const com_ptr &) = delete;
  com_ptr &operator=(const com_ptr &) = delete;
  T *operator->() const noexcept { return value_; }
  T **put() noexcept { return &value_; }
  explicit operator bool() const noexcept { return value_ != nullptr; }
};

class drop_handle_guard {
  HDROP value_{};

public:
  explicit drop_handle_guard(HDROP value) noexcept : value_(value) {}
  ~drop_handle_guard() {
    if (value_)
      DragFinish(value_);
  }
};

constexpr int ID_LIST_TARGETS = 5101;
constexpr int ID_BTN_ADD_FILES = 5102;
constexpr int ID_BTN_ADD_FOLDER = 5103;
constexpr int ID_BTN_REMOVE = 5104;
constexpr int ID_BTN_CLEAR = 5105;
constexpr int ID_BTN_ANALYZE = 5106;
constexpr int ID_BTN_ERASE = 5107;
constexpr int ID_BTN_RECYCLE = 5108;
constexpr int ID_COMBO_DRIVES = 5109;
constexpr int ID_BTN_WIPE_FREE = 5110;
constexpr int ID_BTN_SETTINGS = 5111;
constexpr int ID_BTN_CERTIFICATE = 5112;
constexpr int ID_BTN_INSTALL_SHELL = 5113;
constexpr int ID_BTN_REMOVE_SHELL = 5114;
constexpr int ID_BTN_DIAGNOSTICS = 5115;

struct main_state {
  HWND hwnd{};
  HWND icon_ctrl{};
  HWND title_lbl{};
  HWND subtitle_lbl{};
  HWND badge_lbl{};
  HWND list_targets{};
  HWND combo_drives{};
  HWND status_lbl{};
  HFONT font_title{};
  HFONT font_section{};
  HFONT font_body{};
  HFONT font_small{};
  std::vector<std::filesystem::path> targets;
  std::vector<std::wstring> drive_roots;
};

std::filesystem::path current_exe_path() {
  std::wstring buf(32768, L'\0');
  const DWORD n =
      GetModuleFileNameW(nullptr, buf.data(), static_cast<DWORD>(buf.size()));
  if (!n || static_cast<std::size_t>(n) >= buf.size())
    return {};
  buf.resize(n);
  return buf;
}

std::wstring mode_label(const erase_mode mode) {
  switch (mode) {
  case erase_mode::fast:
    return L"Schnell (1 Pass)";
  case erase_mode::standard:
    return L"Standard (2 Passes)";
  case erase_mode::strong:
    return L"Stark (3 Passes)";
  case erase_mode::dod_5220_22_m:
    return L"DoD 5220.22-M";
  case erase_mode::nist_800_88:
    return L"NIST SP 800-88";
  case erase_mode::bsi_gs:
    return L"BSI IT-Grundschutz";
  case erase_mode::gutmann:
    return L"Gutmann (35 Passes)";
  }
  return L"Standard";
}

std::wstring format_gb(const std::uint64_t bytes) {
  std::wostringstream out;
  out << std::fixed << std::setprecision(1)
      << (static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0)) << L" GB";
  return out.str();
}

void apply_font_and_theme(HWND ctrl, HFONT font, const bool dark) {
  if (!ctrl)
    return;
  SendMessageW(ctrl, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
  if (dark)
    apply_window_theme(ctrl);
}

HWND make_label(HWND parent, const wchar_t *text, int x, int y, int w, int h,
                HFONT font, const bool dark) {
  HWND ctrl = CreateWindowExW(0, L"STATIC", text, WS_CHILD | WS_VISIBLE, x, y,
                              w, h, parent, nullptr, GetModuleHandleW(nullptr),
                              nullptr);
  apply_font_and_theme(ctrl, font, dark);
  return ctrl;
}

HWND make_group(HWND parent, const wchar_t *text, int x, int y, int w, int h,
                HFONT font, const bool dark) {
  HWND ctrl = CreateWindowExW(
      0, L"BUTTON", text, WS_CHILD | WS_VISIBLE | BS_GROUPBOX, x, y, w, h,
      parent, nullptr, GetModuleHandleW(nullptr), nullptr);
  apply_font_and_theme(ctrl, font, dark);
  return ctrl;
}

HWND make_button(HWND parent, int id, const wchar_t *text, int x, int y, int w,
                 int h, HFONT font, const bool dark,
                 const bool primary = false) {
  const DWORD style = WS_CHILD | WS_VISIBLE | WS_TABSTOP |
                      (primary ? BS_DEFPUSHBUTTON : BS_PUSHBUTTON);
  HWND ctrl = CreateWindowExW(
      0, L"BUTTON", text, style, x, y, w, h, parent,
      reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
      GetModuleHandleW(nullptr), nullptr);
  apply_font_and_theme(ctrl, font, dark);
  return ctrl;
}

void set_status(main_state &s, const std::wstring &text) {
  if (s.status_lbl)
    SetWindowTextW(s.status_lbl, text.c_str());
}

void refresh_settings_badge(main_state &s) {
  const erase_options o = load_default_erase_options();
  const std::wstring badge =
      L"Aktives Profil: " + mode_label(o.mode) + L"  ·  Verifikation: " +
      (o.verify ? L"Ein" : L"Aus") + L"  ·  ADS: " +
      (o.erase_alternate_streams ? L"Ein" : L"Aus") + L"  ·  Rename: " +
      (o.rename_before_delete ? std::to_wstring(o.rename_rounds) + L"×"
                              : L"Aus");
  if (s.badge_lbl)
    SetWindowTextW(s.badge_lbl, badge.c_str());
}

void refresh_target_list(main_state &s) {
  SendMessageW(s.list_targets, LB_RESETCONTENT, 0, 0);
  for (const auto &p : s.targets) {
    SendMessageW(s.list_targets, LB_ADDSTRING, 0,
                 reinterpret_cast<LPARAM>(p.c_str()));
  }
  if (s.targets.empty()) {
    set_status(s, L"Bereit – Dateien oder Ordner per Drag && Drop oder über "
                  L"die Schaltflächen hinzufügen.");
  } else {
    set_status(s, std::to_wstring(s.targets.size()) +
                      (s.targets.size() == 1 ? L" Ziel ausgewählt."
                                             : L" Ziele ausgewählt."));
  }
}

void add_unique_target(main_state &s, const std::filesystem::path &path) {
  if (path.empty() || s.targets.size() >= max_operation_targets)
    return;
  for (const auto &existing : s.targets) {
    if (_wcsicmp(existing.c_str(), path.c_str()) == 0)
      return;
  }
  s.targets.push_back(path);
}

void populate_drives(main_state &s) {
  SendMessageW(s.combo_drives, CB_RESETCONTENT, 0, 0);
  s.drive_roots.clear();

  wchar_t drives[512]{};
  const DWORD len = GetLogicalDriveStringsW(
      static_cast<DWORD>(std::size(drives)), drives);
  if (!len || len >= std::size(drives))
    return;

  for (const wchar_t *p = drives; *p; p += wcslen(p) + 1) {
    const UINT type = GetDriveTypeW(p);
    if (type != DRIVE_FIXED && type != DRIVE_REMOVABLE)
      continue;

    ULARGE_INTEGER free_bytes{}, total_bytes{}, avail_bytes{};
    std::wstring label = p;
    if (GetDiskFreeSpaceExW(p, &avail_bytes, &total_bytes, &free_bytes)) {
      label += L"  (" + format_gb(avail_bytes.QuadPart) + L" frei / " +
               format_gb(total_bytes.QuadPart) + L" gesamt)";
    }
    s.drive_roots.emplace_back(p);
    SendMessageW(s.combo_drives, CB_ADDSTRING, 0,
                 reinterpret_cast<LPARAM>(label.c_str()));
  }
  if (!s.drive_roots.empty())
    SendMessageW(s.combo_drives, CB_SETCURSEL, 0, 0);
}

void browse_files(main_state &s) {
  std::wstring buffer(65536, L'\0');
  OPENFILENAMEW ofn{};
  ofn.lStructSize = sizeof(ofn);
  ofn.hwndOwner = s.hwnd;
  ofn.lpstrFilter = L"Alle Dateien (*.*)\0*.*\0";
  ofn.lpstrFile = buffer.data();
  ofn.nMaxFile = static_cast<DWORD>(buffer.size());
  ofn.lpstrTitle = L"Dateien für Oblivion auswählen";
  ofn.Flags = OFN_EXPLORER | OFN_ALLOWMULTISELECT | OFN_FILEMUSTEXIST |
              OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;

  if (!GetOpenFileNameW(&ofn))
    return;

  const wchar_t *first = buffer.c_str();
  const wchar_t *next = first + wcslen(first) + 1;
  if (*next == L'\0') {
    add_unique_target(s, std::filesystem::path{first});
  } else {
    const std::filesystem::path dir{first};
    for (const wchar_t *p = next; *p; p += wcslen(p) + 1) {
      add_unique_target(s, dir / p);
    }
  }
  refresh_target_list(s);
}

void browse_folders(main_state &s) {
  com_ptr<IFileOpenDialog> dialog;
  if (FAILED(CoCreateInstance(CLSID_FileOpenDialog, nullptr,
                              CLSCTX_INPROC_SERVER,
                              IID_PPV_ARGS(dialog.put()))) ||
      !dialog) {
    return;
  }
  DWORD options = 0;
  if (SUCCEEDED(dialog->GetOptions(&options))) {
    dialog->SetOptions(options | FOS_PICKFOLDERS | FOS_ALLOWMULTISELECT |
                       FOS_FORCEFILESYSTEM);
  }
  dialog->SetTitle(L"Ordner für Oblivion auswählen");

  if (SUCCEEDED(dialog->Show(s.hwnd))) {
    com_ptr<IShellItemArray> items;
    if (SUCCEEDED(dialog->GetResults(items.put())) && items) {
      DWORD count = 0;
      if (SUCCEEDED(items->GetCount(&count))) {
        const auto limit = static_cast<DWORD>((std::min)(
            static_cast<std::uint64_t>(count),
            static_cast<std::uint64_t>(max_operation_targets)));
        for (DWORD i = 0; i < limit; ++i) {
          com_ptr<IShellItem> item;
          if (SUCCEEDED(items->GetItemAt(i, item.put())) && item) {
            PWSTR path = nullptr;
            if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &path)) &&
                path) {
              unique_cotaskmem_string path_owner{path};
              add_unique_target(s, std::filesystem::path{path_owner.get()});
            }
          }
        }
      }
    }
  }
  refresh_target_list(s);
}

void remove_selected_target(main_state &s) {
  const LRESULT idx = SendMessageW(s.list_targets, LB_GETCURSEL, 0, 0);
  if (idx == LB_ERR || static_cast<std::size_t>(idx) >= s.targets.size())
    return;
  s.targets.erase(s.targets.begin() + idx);
  refresh_target_list(s);
}

bool confirm_hardlink_policy(HWND owner, erase_options &o,
                             const file_analysis &a) {
  if (!a.hardlinked_files && !requires_hardlink_confirmation(o))
    return true;
  if (!a.hardlinked_files)
    return typed_confirmation(
        L"Hardlink Shared Content",
        L"Die gefährliche Shared-Hardlink-Strategie bleibt auch dann aktiv, "
        L"wenn Hardlinks erst nach der Voranalyse entstehen.",
        L"HARDLINK");
  constexpr int BLOCK = 4201, DEL = 4202, OVER = 4203;
  TASKDIALOG_BUTTON bs[] = {
      {BLOCK, L"Blockieren"},
      {DEL, L"Nur ausgewählte Linknamen entfernen"},
      {OVER, L"GEFÄHRLICH · gemeinsamen Inhalt überschreiben"}};
  TASKDIALOGCONFIG c{};
  c.cbSize = sizeof(c);
  c.hwndParent = owner;
  c.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION | TDF_SIZE_TO_CONTENT |
              TDF_USE_HICON_MAIN;
  c.dwCommonButtons = TDCBF_CANCEL_BUTTON;
  c.pszWindowTitle = L"Oblivion - Hardlinks";
  c.hMainIcon = load_ui_icon(IDI_OBLIVION_WARNING, 48, 48);
  c.pszMainInstruction = L"Hardlink-Strategie wählen";
  c.pszContent =
      L"Mehrere Namen können denselben Dateidatensatz referenzieren.";
  c.cButtons = shared_hardlink_overwrite_allowed() ? 3u : 2u;
  c.pButtons = bs;
  c.nDefaultButton =
      o.hardlinks == hardlink_policy::delete_link_only ? DEL : BLOCK;
  int sel = IDCANCEL;
  if (FAILED(TaskDialogIndirect(&c, &sel, nullptr, nullptr)))
    return false;
  if (sel == BLOCK) {
    o.hardlinks = hardlink_policy::block;
    return true;
  }
  if (sel == DEL) {
    o.hardlinks = hardlink_policy::delete_link_only;
    return true;
  }
  if (sel == OVER) {
    o.hardlinks = hardlink_policy::overwrite_shared_content;
    return typed_confirmation(
        L"Hardlink Shared Content",
        L"Der gemeinsam referenzierte Inhalt aller Hardlinks wird verändert. "
        L"Alle bekannten Namen werden vorher gegen Schutzpfade validiert.",
        L"HARDLINK");
  }
  return false;
}

std::vector<std::wstring> build_elevation_args(
    const erase_options &options,
    const std::vector<std::filesystem::path> &targets) {
  return build_elevation_arguments(options, targets);
}

void run_targets_action(main_state &s, const bool analyze_only) {
  if (s.targets.empty()) {
    MessageBoxW(s.hwnd, L"Bitte zuerst mindestens eine Datei oder einen Ordner auswählen.",
                L"Oblivion", MB_OK | MB_ICONINFORMATION);
    return;
  }

  const auto p = prepare_operation(s.targets);
  if (!p.valid) {
    MessageBoxW(s.hwnd, p.error.c_str(), L"Oblivion - blockiert",
                MB_OK | MB_ICONERROR);
    return;
  }

  if (analyze_only) {
    const auto report = format_prepared_analysis(p);
    MessageBoxW(s.hwnd, report.c_str(), L"Oblivion - Analyse (Dry Run)",
                MB_OK | MB_ICONINFORMATION);
    set_status(s, L"Analyse abgeschlossen.");
    return;
  }

  erase_options o = load_default_erase_options();
  if (!confirm_hardlink_policy(s.hwnd, o, p.analysis))
    return;

  const auto ct = confirmation_text(p, o);
  bool confirmed = false;
  if (requires_typed_confirmation(p.analysis)) {
    if (MessageBoxW(s.hwnd, ct.c_str(), L"Oblivion - große Operation",
                    MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) == IDYES) {
      confirmed = typed_confirmation(L"Oblivion - endgültige Bestätigung",
                                     L"Große Löschoperation wurde geprüft. "
                                     L"Diese Aktion ist unwiderruflich.");
    }
  } else {
    confirmed =
        MessageBoxW(s.hwnd, ct.c_str(), L"Oblivion - endgültig löschen?",
                    MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) == IDYES;
  }
  if (!confirmed)
    return;

  const auto r = run_progress_window(
      L"OBLIVION - Sicheres Löschen",
      [&](const progress_callback &cb, const std::function<bool()> &stop) {
        return execute_prepared_operation(p, o, cb, stop);
      },
      s.hwnd);

  MessageBoxW(s.hwnd, r.summary.c_str(), L"Oblivion",
              MB_OK | (r.exit_code == 0 ? MB_ICONINFORMATION : MB_ICONWARNING));

  if (r.exit_code == 5 && !r.elevation_retry_targets.empty() &&
      !is_process_elevated() &&
      MessageBoxW(
          s.hwnd,
          L"Zugriff verweigert. Mit Administratorrechten erneut versuchen?",
          L"Oblivion", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) == IDYES) {
    if (!relaunch_elevated(current_exe_path(),
                            build_elevation_args(
                                o, r.elevation_retry_targets)))
      MessageBoxW(s.hwnd,
                  L"Der Neustart mit Administratorrechten ist fehlgeschlagen "
                  L"oder wurde abgebrochen.",
                  L"Oblivion", MB_OK | MB_ICONERROR);
  }

  if (r.exit_code == 0) {
    s.targets.clear();
    refresh_target_list(s);
    populate_drives(s);
    set_status(s, L"Löschvorgang erfolgreich abgeschlossen.");
  } else {
    set_status(s, L"Löschvorgang beendet (Code " +
                      std::to_wstring(r.exit_code) + L").");
  }
}

void run_recycle_bin_action(main_state &s) {
  const int btn = MessageBoxW(
      s.hwnd,
      L"Möchten Sie alle Dateien im Windows-Papierkorb aller unterstützten "
      L"lokalen Laufwerke "
      L"unwiderruflich und sicher überschreiben?",
      L"Oblivion · Papierkorb sicher leeren",
      MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2);
  if (btn != IDYES)
    return;

  const erase_options o = load_default_erase_options();
  const auto res = run_progress_window(
      L"Papierkorb sicher leeren",
      [&](const progress_callback &cb, const std::function<bool()> &stop) {
        (void)stop;
        const auto r = secure_empty_recycle_bin(o, cb);
        return gui_run_result{r.success, r.cancelled, r.success ? 0 : 1,
                              r.message};
      },
      s.hwnd);
  MessageBoxW(s.hwnd, res.summary.c_str(), L"Oblivion · Papierkorb",
              MB_OK | (res.exit_code == 0 ? MB_ICONINFORMATION : MB_ICONERROR));
  populate_drives(s);
  set_status(s, res.exit_code == 0 ? L"Papierkorb sicher geleert."
                                   : L"Papierkorb-Leerung abgebrochen/fehlerhaft.");
}

void run_wipe_free_space_action(main_state &s) {
  const LRESULT idx = SendMessageW(s.combo_drives, CB_GETCURSEL, 0, 0);
  if (idx == CB_ERR || static_cast<std::size_t>(idx) >= s.drive_roots.size()) {
    MessageBoxW(s.hwnd, L"Kein gültiges Laufwerk ausgewählt.", L"Oblivion",
                MB_OK | MB_ICONWARNING);
    return;
  }
  const std::filesystem::path target = s.drive_roots[static_cast<std::size_t>(idx)];
  const std::wstring prompt =
      L"Möchten Sie den gesamten freien Speicherplatz auf " + target.wstring() +
      L" sicher überschreiben?\n\n(Bestehende Dateien bleiben unberührt.)";
  if (MessageBoxW(s.hwnd, prompt.c_str(),
                  L"Oblivion · Freien Speicherplatz bereinigen",
                  MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES) {
    return;
  }

  const erase_options o = load_default_erase_options();
  const auto res = run_progress_window(
      L"Freien Speicherplatz bereinigen",
      [&](const progress_callback &cb, const std::function<bool()> &stop) {
        (void)stop;
        const auto r = wipe_volume_free_space(target, o, cb);
        return gui_run_result{r.success, r.cancelled, r.success ? 0 : 1,
                              r.message};
      },
      s.hwnd);
  MessageBoxW(s.hwnd, res.summary.c_str(), L"Oblivion · Freispeicher",
              MB_OK | (res.exit_code == 0 ? MB_ICONINFORMATION : MB_ICONERROR));
  populate_drives(s);
  set_status(s, res.exit_code == 0
                    ? L"Freier Speicherplatz auf " + target.wstring() + L" bereinigt."
                    : L"Freispeicher-Bereinigung abgebrochen/fehlerhaft.");
}

void export_certificate_action(main_state &s) {
  const std::filesystem::path audit_dir = audit_directory();
  std::wstring audit_dir_str = audit_dir.wstring();
  std::wstring file_buf(4096, L'\0');

  OPENFILENAMEW ofn{};
  ofn.lStructSize = sizeof(ofn);
  ofn.hwndOwner = s.hwnd;
  ofn.lpstrFilter =
      L"Oblivion Audit-Logs (*.jsonl;*.log)\0*.jsonl;*.log\0Alle Dateien (*.*)\0*.*\0";
  ofn.lpstrFile = file_buf.data();
  ofn.nMaxFile = static_cast<DWORD>(file_buf.size());
  ofn.lpstrInitialDir = audit_dir_str.empty() ? nullptr : audit_dir_str.c_str();
  ofn.lpstrTitle = L"Audit-Log für Löschzertifikat auswählen";
  ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST |
              OFN_HIDEREADONLY;

  if (!GetOpenFileNameW(&ofn))
    return;

  const std::filesystem::path audit_file{file_buf.c_str()};
  std::filesystem::path out_file = audit_file;
  out_file.replace_extension(L".html");

  if (generate_certificate_from_audit(audit_file, out_file)) {
    const auto opened = ShellExecuteW(nullptr, L"open", out_file.c_str(),
                                      nullptr, nullptr, SW_SHOWNORMAL);
    if (reinterpret_cast<INT_PTR>(opened) <= 32) {
      MessageBoxW(s.hwnd,
                  L"Zertifikat wurde erstellt, konnte aber nicht im "
                  L"Standardbrowser geöffnet werden.",
                  L"Oblivion · Zertifikat", MB_OK | MB_ICONWARNING);
      set_status(s, L"Löschzertifikat erstellt, Browserstart fehlgeschlagen: " +
                        out_file.filename().wstring());
    } else {
      set_status(s,
                 L"Löschzertifikat erstellt: " + out_file.filename().wstring());
    }
  } else {
    MessageBoxW(s.hwnd,
                L"Löschzertifikat konnte nicht aus dieser Datei generiert werden.",
                L"Oblivion · Zertifikat", MB_OK | MB_ICONERROR);
  }
}

void show_diagnostics_action(main_state &s) {
  const auto hardening = harden_current_process();
  const std::wstring msg =
      format_runtime_hardening(hardening) + L"\n\nAudit-Verzeichnis:\n" +
      audit_directory().wstring() + L"\n\nProgramm-Pfad:\n" +
      current_exe_path().wstring();
  MessageBoxW(s.hwnd, msg.c_str(), L"Oblivion · Systemdiagnose",
              MB_OK | (hardening.complete() ? MB_ICONINFORMATION : MB_ICONWARNING));
}

void enable_drop_messages(HWND target) {
  if (!target)
    return;
  DragAcceptFiles(target, TRUE);
  ChangeWindowMessageFilterEx(target, WM_DROPFILES, MSGFLT_ALLOW, nullptr);
}

LRESULT CALLBACK list_drop_proc(HWND hwnd, UINT msg, WPARAM w, LPARAM l,
                                UINT_PTR id, DWORD_PTR ref_data) noexcept try {
  (void)id;
  if (msg == WM_DROPFILES) {
    auto parent = reinterpret_cast<HWND>(ref_data);
    if (parent)
      return SendMessageW(parent, WM_DROPFILES, w, l);
  }
  if (msg == WM_NCDESTROY)
    RemoveWindowSubclass(hwnd, list_drop_proc, 1);
  return DefSubclassProc(hwnd, msg, w, l);
} catch (...) {
  return DefSubclassProc(hwnd, msg, w, l);
}

LRESULT CALLBACK main_proc(HWND h, UINT m, WPARAM w, LPARAM l) noexcept try {
  auto *s = reinterpret_cast<main_state *>(GetWindowLongPtrW(h, GWLP_USERDATA));
  switch (m) {
  case WM_NCCREATE: {
    auto *cs = reinterpret_cast<CREATESTRUCTW *>(l);
    s = static_cast<main_state *>(cs->lpCreateParams);
    SetWindowLongPtrW(h, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(s));
    return TRUE;
  }
  case WM_CREATE: {
    s->hwnd = h;
    const bool dark = is_dark_theme();
    apply_window_theme(h);
    set_window_icons(h, IDI_OBLIVION_CONTEXT);
    enable_drop_messages(h);

    s->font_title = CreateFontW(-20, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                                CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    s->font_section = CreateFontW(-14, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE,
                                  FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                                  CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                  DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    s->font_body = CreateFontW(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                               DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                               CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                               DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    s->font_small = CreateFontW(-12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                                CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                DEFAULT_PITCH | FF_SWISS, L"Segoe UI");

    s->icon_ctrl = CreateWindowExW(
        0, L"STATIC", nullptr, WS_CHILD | WS_VISIBLE | SS_ICON | SS_REALSIZEIMAGE,
        20, 16, 40, 40, h, nullptr, GetModuleHandleW(nullptr), nullptr);
    if (HICON hi = load_ui_icon(IDI_OBLIVION_CONTEXT, 40, 40)) {
      SendMessageW(s->icon_ctrl, STM_SETICON, reinterpret_cast<WPARAM>(hi), 0);
    }

    s->title_lbl = make_label(h, L"Oblivion Native 2.1.4", 72, 14, 420, 26,
                              s->font_title, dark);
    s->subtitle_lbl = make_label(
        h, L"Sichere Dateivernichtung, Datenträgeranalyse && Compliance", 72, 42,
        460, 20, s->font_small, dark);
    s->badge_lbl = make_label(h, L"", 20, 68, 720, 20, s->font_small, dark);

    // Section 1: Targets (Files & Folders)
    make_group(h, L" Dateien && Ordner (Drag && Drop unterstützt) ", 20, 96, 724,
               230, s->font_section, dark);

    s->list_targets = CreateWindowExW(
        WS_EX_CLIENTEDGE, L"LISTBOX", nullptr,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | WS_HSCROLL |
            LBS_NOINTEGRALHEIGHT,
        34, 122, 540, 148, h,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_LIST_TARGETS)),
        GetModuleHandleW(nullptr), nullptr);
    apply_font_and_theme(s->list_targets, s->font_body, dark);
    enable_drop_messages(s->list_targets);
    SetWindowSubclass(s->list_targets, list_drop_proc, 1,
                      reinterpret_cast<DWORD_PTR>(h));

    make_button(h, ID_BTN_ADD_FILES, L"+ Dateien…", 588, 122, 140, 32,
                s->font_body, dark);
    make_button(h, ID_BTN_ADD_FOLDER, L"+ Ordner…", 588, 160, 140, 32,
                s->font_body, dark);
    make_button(h, ID_BTN_REMOVE, L"Entfernen", 588, 198, 140, 32,
                s->font_body, dark);
    make_button(h, ID_BTN_CLEAR, L"Liste leeren", 588, 236, 140, 32,
                s->font_body, dark);

    make_button(h, ID_BTN_ANALYZE, L"Analysieren (Dry Run)", 34, 280, 260, 34,
                s->font_body, dark);
    make_button(h, ID_BTN_ERASE, L"Auswahl sicher löschen", 314, 280, 260, 34,
                s->font_section, dark, true);

    // Section 2: System & Drives
    make_group(h, L" Datenträger && Papierkorb ", 20, 338, 724, 108,
               s->font_section, dark);

    make_label(h, L"Volume:", 34, 368, 64, 22, s->font_body, dark);
    s->combo_drives = CreateWindowExW(
        0, L"COMBOBOX", nullptr,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL,
        102, 364, 330, 220, h,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_COMBO_DRIVES)),
        GetModuleHandleW(nullptr), nullptr);
    apply_font_and_theme(s->combo_drives, s->font_body, dark);

    make_button(h, ID_BTN_WIPE_FREE, L"Freien Speicher überschreiben", 446, 362,
                282, 32, s->font_body, dark);
    make_button(h, ID_BTN_RECYCLE, L"Windows-Papierkorb sicher leeren", 34, 402,
                398, 32, s->font_body, dark);

    // Section 3: Settings, Certificates & Shell Integration
    make_group(h, L" Compliance, Einstellungen && Explorer-Integration ", 20, 458,
               724, 96, s->font_section, dark);

    make_button(h, ID_BTN_SETTINGS, L"Löschstandard && Optionen…", 34, 486, 215,
                32, s->font_body, dark);
    make_button(h, ID_BTN_CERTIFICATE, L"Löschzertifikat (HTML)…", 261, 486, 200,
                32, s->font_body, dark);
    make_button(h, ID_BTN_DIAGNOSTICS, L"Systemdiagnose", 473, 486, 122, 32,
                s->font_body, dark);
    make_button(h, ID_BTN_INSTALL_SHELL, L"Kontextmenü +", 607, 486, 121, 32,
                s->font_body, dark);
    make_button(h, ID_BTN_REMOVE_SHELL, L"Kontextmenü entfernen", 558, 520, 170,
                26, s->font_small, dark);

    s->status_lbl =
        make_label(h, L"Bereit.", 20, 562, 724, 22, s->font_small, dark);

    refresh_settings_badge(*s);
    populate_drives(*s);
    refresh_target_list(*s);
    return 0;
  }
  case WM_DROPFILES: {
    auto drop = reinterpret_cast<HDROP>(w);
    drop_handle_guard finish_drop{drop};
    const UINT count = DragQueryFileW(drop, 0xFFFFFFFF, nullptr, 0);
    const auto limit = static_cast<UINT>((std::min)(
        static_cast<std::uint64_t>(count),
        static_cast<std::uint64_t>(max_operation_targets)));
    for (UINT i = 0; i < limit && s->targets.size() < max_operation_targets;
         ++i) {
      const UINT needed = DragQueryFileW(drop, i, nullptr, 0);
      if (!needed)
        continue;
      std::wstring path(needed + 1, L'\0');
      if (DragQueryFileW(drop, i, path.data(), needed + 1)) {
        path.resize(needed);
        add_unique_target(*s, std::filesystem::path{path});
      }
    }
    refresh_target_list(*s);
    return 0;
  }
  case WM_COMMAND: {
    const int id = LOWORD(w);
    switch (id) {
    case ID_BTN_ADD_FILES:
      browse_files(*s);
      return 0;
    case ID_BTN_ADD_FOLDER:
      browse_folders(*s);
      return 0;
    case ID_BTN_REMOVE:
      remove_selected_target(*s);
      return 0;
    case ID_BTN_CLEAR:
      s->targets.clear();
      refresh_target_list(*s);
      return 0;
    case ID_BTN_ANALYZE:
      run_targets_action(*s, true);
      return 0;
    case ID_BTN_ERASE:
      run_targets_action(*s, false);
      return 0;
    case ID_BTN_RECYCLE:
      run_recycle_bin_action(*s);
      return 0;
    case ID_BTN_WIPE_FREE:
      run_wipe_free_space_action(*s);
      return 0;
    case ID_BTN_SETTINGS:
      if (show_settings_window()) {
        refresh_settings_badge(*s);
        set_status(*s, L"Einstellungen aktualisiert.");
      }
      return 0;
    case ID_BTN_CERTIFICATE:
      export_certificate_action(*s);
      return 0;
    case ID_BTN_DIAGNOSTICS:
      show_diagnostics_action(*s);
      return 0;
    case ID_BTN_INSTALL_SHELL: {
      const auto exe = current_exe_path();
      const auto r =
          install_context_menu(exe, exe.parent_path() / L"OblivionShell.dll");
      MessageBoxW(h, r.message.c_str(), L"Oblivion · Kontextmenü",
                  MB_OK | (r.success ? MB_ICONINFORMATION : MB_ICONERROR));
      set_status(*s, r.success ? L"Kontextmenü installiert."
                               : L"Kontextmenü-Installation fehlgeschlagen.");
      return 0;
    }
    case ID_BTN_REMOVE_SHELL: {
      const auto r = uninstall_context_menu();
      MessageBoxW(h, r.message.c_str(), L"Oblivion · Kontextmenü",
                  MB_OK | (r.success ? MB_ICONINFORMATION : MB_ICONERROR));
      set_status(*s, r.success ? L"Kontextmenü entfernt."
                               : L"Kontextmenü-Entfernung fehlgeschlagen.");
      return 0;
    }
    default:
      break;
    }
    break;
  }
  case WM_CTLCOLORDLG:
  case WM_CTLCOLORSTATIC:
  case WM_CTLCOLORBTN:
  case WM_CTLCOLORLISTBOX:
  case WM_CTLCOLOREDIT: {
    LRESULT res = 0;
    if (handle_theme_colors(h, m, w, l, res))
      return res;
    break;
  }
  case WM_DESTROY:
    if (s) {
      if (s->font_title)
        DeleteObject(s->font_title);
      if (s->font_section)
        DeleteObject(s->font_section);
      if (s->font_body)
        DeleteObject(s->font_body);
      if (s->font_small)
        DeleteObject(s->font_small);
    }
    PostQuitMessage(0);
    return 0;
  default:
    break;
  }
  return DefWindowProcW(h, m, w, l);
} catch (...) {
  SetWindowLongPtrW(h, GWLP_USERDATA, 0);
  if (IsWindow(h))
    DestroyWindow(h);
  PostQuitMessage(10);
  return 0;
}

} // namespace

int show_main_window() {
  constexpr wchar_t CLASS_NAME[] = L"OblivionMainControlCenterV1";
  WNDCLASSEXW wc{};
  wc.cbSize = sizeof(wc);
  wc.lpfnWndProc = main_proc;
  wc.hInstance = GetModuleHandleW(nullptr);
  wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
  wc.hbrBackground = is_dark_theme() ? get_dark_background_brush()
                                     : reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
  wc.lpszClassName = CLASS_NAME;
  wc.hIcon = load_ui_icon(IDI_OBLIVION_CONTEXT, GetSystemMetrics(SM_CXICON),
                          GetSystemMetrics(SM_CYICON));
  wc.hIconSm = load_ui_icon(IDI_OBLIVION_CONTEXT, GetSystemMetrics(SM_CXSMICON),
                            GetSystemMetrics(SM_CYSMICON));
  RegisterClassExW(&wc);

  const int width = 780;
  const int height = 628;
  const int screen_w = GetSystemMetrics(SM_CXSCREEN);
  const int screen_h = GetSystemMetrics(SM_CYSCREEN);
  const int pos_x = (std::max)(0, (screen_w - width) / 2);
  const int pos_y = (std::max)(0, (screen_h - height) / 2);

  main_state state{};
  HWND hwnd = CreateWindowExW(
      WS_EX_APPWINDOW | WS_EX_ACCEPTFILES, CLASS_NAME,
      L"Oblivion Native 2.1.4 – Sichere Dateivernichtung",
      WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, pos_x, pos_y,
      width, height, nullptr, nullptr, GetModuleHandleW(nullptr), &state);
  if (!hwnd)
    return 1;

  ShowWindow(hwnd, SW_SHOW);
  UpdateWindow(hwnd);

  MSG msg{};
  while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
    if (!IsDialogMessageW(hwnd, &msg)) {
      TranslateMessage(&msg);
      DispatchMessageW(&msg);
    }
  }
  return 0;
}

} // namespace oblivion
