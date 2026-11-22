#include "oblivion/app_logic.hpp"
#include "oblivion/certificate.hpp"
#include "oblivion/elevation.hpp"
#include "oblivion/main_window.hpp"
#include "oblivion/progress_window.hpp"
#include "oblivion/recycle_bin.hpp"
#include "oblivion/runtime_guard.hpp"
#include "oblivion/settings.hpp"
#include "oblivion/settings_window.hpp"
#include "oblivion/shell_batch.hpp"
#include "oblivion/shell_integration.hpp"
#include "oblivion/wipe_free_space.hpp"
#include "oblivion/win_handle.hpp"
#include "oblivion/ui_icons.hpp"
#include <CommCtrl.h>
#include <Windows.h>
#include <exception>
#include <filesystem>
#include <iterator>
#include <shellapi.h>
#include <string>
#include <string_view>
#include <vector>
namespace {
using namespace oblivion;
std::filesystem::path exe() {
  std::wstring b(32768, L'\0');
  DWORD n = GetModuleFileNameW(nullptr, b.data(), static_cast<DWORD>(b.size()));
  if (!n || static_cast<std::size_t>(n) >= b.size())
    return {};
  b.resize(n);
  return b;
}
bool parse_rename_rounds(const std::wstring_view value,
                         unsigned &rounds) noexcept try {
  std::size_t consumed = 0;
  const auto parsed = std::stoul(std::wstring{value}, &consumed);
  if (consumed != value.size() || parsed > 32u)
    return false;
  rounds = static_cast<unsigned>(parsed);
  return true;
} catch (...) {
  return false;
}
bool hardlinks(erase_options &o, const file_analysis &a) {
  if (!a.hardlinked_files && !requires_hardlink_confirmation(o))
    return true;
  if (!a.hardlinked_files)
    return typed_confirmation(
        L"Hardlink Shared Content",
        L"Die gefährliche Shared-Hardlink-Strategie bleibt auch dann aktiv, "
        L"wenn Hardlinks erst nach der Voranalyse entstehen.",
        L"HARDLINK");
  constexpr int BLOCK = 4101, DEL = 4102, OVER = 4103;
  TASKDIALOG_BUTTON bs[] = {
      {BLOCK, L"Blockieren"},
      {DEL, L"Nur ausgewählte Linknamen entfernen"},
      {OVER, L"GEFÄHRLICH · gemeinsamen Inhalt überschreiben"}};
  TASKDIALOGCONFIG c{};
  c.cbSize = sizeof(c);
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
  int s = IDCANCEL;
  if (FAILED(TaskDialogIndirect(&c, &s, nullptr, nullptr)))
    return false;
  if (s == BLOCK) {
    o.hardlinks = hardlink_policy::block;
    return true;
  }
  if (s == DEL) {
    o.hardlinks = hardlink_policy::delete_link_only;
    return true;
  }
  if (s == OVER) {
    o.hardlinks = hardlink_policy::overwrite_shared_content;
    return typed_confirmation(
        L"Hardlink Shared Content",
        L"Der gemeinsam referenzierte Inhalt aller Hardlinks wird verändert. "
        L"Alle bekannten Namen werden vorher gegen Schutzpfade validiert.",
        L"HARDLINK");
  }
  return false;
}
std::vector<std::wstring> elevation_args(
    const erase_options &options,
    const std::vector<std::filesystem::path> &targets) {
  return build_elevation_arguments(options, targets);
}

bool show_settings_singleton() {
  unique_win_handle mutex{CreateMutexW(
      nullptr, FALSE, L"Local\\Oblivion.Settings.Singleton")};
  if (!mutex)
    return false;
  if (GetLastError() == ERROR_ALREADY_EXISTS)
    return true;
  return show_settings_window();
}

int oblivion_message_box(HWND owner, LPCWSTR text, LPCWSTR caption,
                         UINT type) {
  const std::wstring_view title = caption ? caption : L"Oblivion";
  int icon_id = IDI_OBLIVION_RESULT;
  if (title.find(L"Analyse") != std::wstring_view::npos)
    icon_id = IDI_OBLIVION_ANALYZE;
  else if ((type & MB_ICONWARNING) || (type & MB_ICONERROR) ||
           title.find(L"lösch") != std::wstring_view::npos ||
           title.find(L"blockiert") != std::wstring_view::npos)
    icon_id = IDI_OBLIVION_WARNING;

  TASKDIALOGCONFIG config{};
  config.cbSize = sizeof(config);
  config.hwndParent = owner;
  config.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION | TDF_SIZE_TO_CONTENT |
                   TDF_USE_HICON_MAIN;
  config.dwCommonButtons = (type & MB_YESNO)
                               ? TDCBF_YES_BUTTON | TDCBF_NO_BUTTON
                               : TDCBF_OK_BUTTON;
  config.pszWindowTitle = caption ? caption : L"Oblivion";
  config.pszMainInstruction = caption ? caption : L"Oblivion";
  config.pszContent = text ? text : L"";
  config.hMainIcon = load_ui_icon(icon_id, 48, 48);
  config.nDefaultButton = (type & MB_DEFBUTTON2) ? IDNO : 0;
  int button = IDCANCEL;
  if (SUCCEEDED(TaskDialogIndirect(&config, &button, nullptr, nullptr)))
    return button;
  return MessageBoxW(owner, text, caption, type);
}
} // namespace

#define MessageBoxW oblivion_message_box

int WINAPI wWinMain(_In_ HINSTANCE, _In_opt_ HINSTANCE, _In_ PWSTR,
                    _In_ int) try {
  using namespace oblivion;
  const auto hardening = harden_current_process();
  int argc = 0;
  wchar_t **argv = CommandLineToArgvW(GetCommandLineW(), &argc);
  if (!argv)
    return 1;
  if (argc == 2 && std::wstring_view{argv[1]} == L"--diagnostics") {
    const auto report = format_runtime_hardening(hardening);
    MessageBoxW(nullptr, report.c_str(), L"Oblivion - Diagnose",
                MB_OK | (hardening.complete() ? MB_ICONINFORMATION
                                               : MB_ICONERROR));
    LocalFree(argv);
    return hardening.complete() ? 0 : 7;
  }
  if (!hardening.complete()) {
    const auto report = format_runtime_hardening(hardening);
    MessageBoxW(nullptr, report.c_str(), L"Oblivion - Sicherheitsfehler",
                MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
    LocalFree(argv);
    return 7;
  }
  if (argc < 2 || std::wstring_view{argv[1]} == L"--gui") {
    const int exit_code = show_main_window();
    LocalFree(argv);
    return exit_code;
  }
  std::wstring_view first = argv[1];
  if (first == L"--install-shell") {
    auto d = exe().parent_path();
    auto r = install_context_menu(exe(), d / L"OblivionShell.dll");
    MessageBoxW(nullptr, r.message.c_str(), L"Oblivion",
                MB_OK | (r.success ? MB_ICONINFORMATION : MB_ICONERROR));
    LocalFree(argv);
    return r.success ? 0 : 1;
  }
  if (first == L"--uninstall-shell" || first == L"--uninstall-shell-quiet") {
    auto r = uninstall_context_menu();
    if (first == L"--uninstall-shell") {
      MessageBoxW(nullptr, r.message.c_str(), L"Oblivion",
                  MB_OK | (r.success ? MB_ICONINFORMATION : MB_ICONERROR));
    }
    LocalFree(argv);
    return r.success ? 0 : 1;
  }
  if (first == L"--settings" || first == L"--settings-singleton") {
    const bool shown = first == L"--settings-singleton"
                           ? show_settings_singleton()
                           : show_settings_window();
    LocalFree(argv);
    return shown ? 0 : 1;
  }
  if (first == L"--empty-recycle-bin") {
    const int btn = MessageBoxW(
        nullptr,
        L"Möchten Sie alle Dateien im Windows-Papierkorb aller unterstützten "
        L"lokalen Laufwerke "
        L"unwiderruflich und sicher überschreiben?",
        L"Oblivion · Papierkorb sicher leeren",
        MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2);
    if (btn != IDYES) {
      LocalFree(argv);
      return 0;
    }
    erase_options o = load_default_erase_options();
    auto res = run_progress_window(
        L"Papierkorb sicher leeren",
        [&](const progress_callback &cb, const std::function<bool()> &stop) {
          (void)stop;
          auto r = secure_empty_recycle_bin(o, cb);
          return gui_run_result{r.success, r.cancelled, r.success ? 0 : 1,
                                r.message};
        });
    MessageBoxW(nullptr, res.summary.c_str(), L"Oblivion · Papierkorb",
                MB_OK |
                    (res.exit_code == 0 ? MB_ICONINFORMATION : MB_ICONERROR));
    LocalFree(argv);
    return res.exit_code;
  }
  if (first == L"--wipe-free-space") {
    if (argc < 3) {
      MessageBoxW(nullptr, L"Zielvolume für Freispeicher-Bereinigung fehlt.",
                  L"Oblivion", MB_OK | MB_ICONERROR);
      LocalFree(argv);
      return 1;
    }
    const std::filesystem::path target = argv[2];
    const std::wstring prompt =
        L"Möchten Sie den gesamten freien Speicherplatz auf dem Volume sicher "
        L"überschreiben?\n\n(Bestehende Dateien bleiben unberührt.)";
    const int btn = MessageBoxW(nullptr, prompt.c_str(),
                                L"Oblivion · Freien Speicherplatz bereinigen",
                                MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2);
    if (btn != IDYES) {
      LocalFree(argv);
      return 0;
    }
    erase_options o = load_default_erase_options();
    auto res = run_progress_window(
        L"Freien Speicherplatz bereinigen",
        [&](const progress_callback &cb, const std::function<bool()> &stop) {
          (void)stop;
          auto r = wipe_volume_free_space(target, o, cb);
          return gui_run_result{r.success, r.cancelled, r.success ? 0 : 1,
                                r.message};
        });
    MessageBoxW(nullptr, res.summary.c_str(), L"Oblivion · Freispeicher",
                MB_OK |
                    (res.exit_code == 0 ? MB_ICONINFORMATION : MB_ICONERROR));
    LocalFree(argv);
    return res.exit_code;
  }
  if (first == L"--export-certificate") {
    if (argc < 3) {
      MessageBoxW(nullptr, L"Audit-Log-Pfad fehlt.", L"Oblivion",
                  MB_OK | MB_ICONERROR);
      LocalFree(argv);
      return 1;
    }
    const std::filesystem::path audit_file = argv[2];
    std::filesystem::path out_file = audit_file;
    out_file.replace_extension(L".html");
    const bool ok = generate_certificate_from_audit(audit_file, out_file);
    if (ok) {
      const auto opened = ShellExecuteW(nullptr, L"open", out_file.c_str(),
                                        nullptr, nullptr, SW_SHOWNORMAL);
      if (reinterpret_cast<INT_PTR>(opened) <= 32)
        MessageBoxW(nullptr,
                    L"Zertifikat wurde erstellt, konnte aber nicht im "
                    L"Standardbrowser geöffnet werden.",
                    L"Oblivion", MB_OK | MB_ICONWARNING);
    } else {
      MessageBoxW(nullptr, L"Zertifikat konnte nicht generiert werden.",
                  L"Oblivion", MB_OK | MB_ICONERROR);
    }
    LocalFree(argv);
    return ok ? 0 : 1;
  }
  erase_options o = load_default_erase_options();
  bool analyze = false, elev = false;
  std::vector<std::filesystem::path> targets;
  int parse_start = 1;

  if (first == L"--shell-batch") {
    if (argc != 4) {
      MessageBoxW(nullptr, L"Ungültiger Shell-Batch-Aufruf.", L"Oblivion",
                  MB_OK | MB_ICONERROR);
      LocalFree(argv);
      return 1;
    }
    const std::wstring_view action = argv[2];
    shell_batch_action batch_action{};
    if (action == L"erase")
      batch_action = shell_batch_action::erase;
    else if (action == L"analyze") {
      batch_action = shell_batch_action::analyze;
      analyze = true;
    } else {
      MessageBoxW(nullptr, L"Unbekannte Shell-Batch-Aktion.", L"Oblivion",
                  MB_OK | MB_ICONERROR);
      LocalFree(argv);
      return 1;
    }

    auto batch = collect_shell_batch(batch_action,
                                     std::filesystem::path{argv[3]});
    if (!batch.success) {
      MessageBoxW(nullptr, batch.error.c_str(), L"Oblivion - Shell",
                  MB_OK | MB_ICONERROR);
      LocalFree(argv);
      return 1;
    }
    if (!batch.owner) {
      LocalFree(argv);
      return 0;
    }
    targets = std::move(batch.targets);
    parse_start = argc;
  }

  for (int i = parse_start; i < argc; ++i) {
    std::wstring_view a = argv[i];
    if (a == L"--shell")
      continue;
    else if (a == L"--analyze")
      analyze = true;
    else if (a == L"--fast") {
      o.mode = erase_mode::fast;
      o.verify = false;
    } else if (a == L"--standard") {
      o.mode = erase_mode::standard;
      o.verify = true;
    } else if (a == L"--strong") {
      o.mode = erase_mode::strong;
      o.verify = true;
    } else if (a == L"--dod") {
      o.mode = erase_mode::dod_5220_22_m;
      o.verify = true;
    } else if (a == L"--nist") {
      o.mode = erase_mode::nist_800_88;
      o.verify = true;
    } else if (a == L"--bsi") {
      o.mode = erase_mode::bsi_gs;
      o.verify = true;
    } else if (a == L"--gutmann") {
      o.mode = erase_mode::gutmann;
      o.verify = true;
    } else if (a == L"--no-verify")
      o.verify = false;
    else if (a == L"--no-ads")
      o.erase_alternate_streams = false;
    else if (a == L"--no-rename")
      o.rename_before_delete = false;
    else if (a == L"--rename-rounds") {
      if (i + 1 >= argc || !parse_rename_rounds(argv[++i], o.rename_rounds)) {
        MessageBoxW(nullptr, L"Ungültige Rename-Runden.", L"Oblivion",
                    MB_OK | MB_ICONERROR);
        LocalFree(argv);
        return 1;
      }
    }
    else if (a == L"--hardlink-block")
      o.hardlinks = hardlink_policy::block;
    else if (a == L"--hardlink-delete-name")
      o.hardlinks = hardlink_policy::delete_link_only;
    else if (a == L"--hardlink-overwrite-shared")
      o.hardlinks = hardlink_policy::overwrite_shared_content;
    else if (a == L"--elevated-retry")
      elev = true;
    else if (a.starts_with(L"--")) {
      std::wstring m = L"Unbekannte Option: " + std::wstring{a};
      MessageBoxW(nullptr, m.c_str(), L"Oblivion", MB_OK | MB_ICONERROR);
      LocalFree(argv);
      return 1;
    } else
      targets.emplace_back(argv[i]);
  }
  if (targets.empty()) {
    MessageBoxW(nullptr, L"Keine Ziele.", L"Oblivion", MB_OK | MB_ICONERROR);
    LocalFree(argv);
    return 1;
  }
  apply_security_policy(o);
  auto p = prepare_operation(targets);
  if (!p.valid) {
    MessageBoxW(nullptr, p.error.c_str(), L"Oblivion - blockiert",
                MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
    LocalFree(argv);
    return 2;
  }
  if (analyze) {
    auto r = format_prepared_analysis(p);
    MessageBoxW(nullptr, r.c_str(), L"Oblivion - Analyse",
                MB_OK | MB_ICONINFORMATION);
    LocalFree(argv);
    return 0;
  }
  if (!hardlinks(o, p.analysis)) {
    LocalFree(argv);
    return 0;
  }
  auto ct = confirmation_text(p, o);
  bool confirmed = false;
  if (requires_typed_confirmation(p.analysis)) {
    if (MessageBoxW(nullptr, ct.c_str(), L"Oblivion - große Operation",
                    MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 |
                        MB_SYSTEMMODAL) == IDYES)
      confirmed = typed_confirmation(L"Oblivion - endgültige Bestätigung",
                                     L"Große Löschoperation wurde geprüft. "
                                     L"Diese Aktion ist unwiderruflich.");
  } else
    confirmed =
        MessageBoxW(nullptr, ct.c_str(), L"Oblivion - endgültig löschen?",
                    MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 |
                        MB_SYSTEMMODAL) == IDYES;
  if (!confirmed) {
    LocalFree(argv);
    return 0;
  }
  auto r = run_progress_window(
      L"OBLIVION - Sicheres Löschen",
      [&](const progress_callback &cb, const std::function<bool()> &stop) {
        return execute_prepared_operation(p, o, cb, stop);
      });
  MessageBoxW(nullptr, r.summary.c_str(), L"Oblivion",
              MB_OK | (r.exit_code == 0 ? MB_ICONINFORMATION : MB_ICONWARNING) |
                  MB_SYSTEMMODAL);
  if (r.exit_code == 5 && !elev && !r.elevation_retry_targets.empty() &&
      !is_process_elevated() &&
      MessageBoxW(
          nullptr,
          L"Zugriff verweigert. Mit Administratorrechten erneut versuchen?",
          L"Oblivion", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) == IDYES) {
    if (!relaunch_elevated(exe(),
                           elevation_args(o, r.elevation_retry_targets))) {
      MessageBoxW(nullptr,
                  L"Der Neustart mit Administratorrechten ist fehlgeschlagen "
                  L"oder wurde abgebrochen.",
                  L"Oblivion", MB_OK | MB_ICONERROR);
    } else {
      LocalFree(argv);
      return 0;
    }
  }
  int ec = r.exit_code;
  LocalFree(argv);
  return ec;
} catch (const std::exception &) {
  MessageBoxW(nullptr,
              L"OBLIVION wurde wegen einer unerwarteten C++-Ausnahme sicher "
              L"beendet.",
              L"Oblivion", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
  return 10;
} catch (...) {
  MessageBoxW(nullptr, L"OBLIVION wurde wegen einer unbekannten Ausnahme "
                       L"sicher beendet.",
              L"Oblivion", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
  return 10;
}
