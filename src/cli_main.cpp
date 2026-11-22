#include "oblivion/app_logic.hpp"
#include "oblivion/audit_integrity.hpp"
#include "oblivion/certificate.hpp"
#include "oblivion/elevation.hpp"
#include "oblivion/recycle_bin.hpp"
#include "oblivion/runtime_guard.hpp"
#include "oblivion/settings.hpp"
#include "oblivion/shell_integration.hpp"
#include "oblivion/wipe_free_space.hpp"
#include <Windows.h>
#include <filesystem>
#include <exception>
#include <iostream>
#include <optional>
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

void usage() {
  std::wcout
      << L"OBLIVION Native CLI 2.1.2\n"
      << L"Aufruf: OblivionCLI.exe [Optionen] <Pfad...>\n\n"
      << L"Löschmodi:\n"
      << L"  --fast                     1 Pass Random (ohne Readback)\n"
      << L"  --standard                 2 Passes: Random + Zero (Default)\n"
      << L"  --strong                   3 Passes: Random + Zero + Random (SHA-256 Readback)\n"
      << L"  --dod                      DoD 5220.22-M (Zero + Ones + Random)\n"
      << L"  --nist                     NIST SP 800-88 Rev. 1 Clear (Zero + Readback)\n"
      << L"  --bsi                      BSI IT-Grundschutz (Random + Ones + Random)\n"
      << L"  --gutmann                  Gutmann 35-Pass (Legacy magnetische Medien)\n\n"
      << L"Aktionen & Tools:\n"
      << L"  --analyze                  Dry Run: Struktur & Speicher ohne Löschen prüfen\n"
      << L"  --wipe-free-space <Pfad>   Freien Speicherplatz auf dem Zielvolume sicher überschreiben\n"
      << L"  --empty-recycle-bin        Papierkorb unterstützter lokaler Laufwerke sicher leeren\n"
      << L"  --verify-audit <Logfile>   Audit-Integritätskette kryptographisch verifizieren\n"
      << L"  --export-certificate <Log> [Out.html]  Löschbericht / Zertifikat generieren\n"
      << L"  --json                     Maschinenlesbare JSON-Ausgabe\n"
      << L"  --diagnostics              Prozesshärtung und Sicherheitsstatus anzeigen\n"
      << L"  --install-shell            Explorer-Kontextmenü für aktuellen Benutzer registrieren\n"
      << L"  --uninstall-shell          Explorer-Kontextmenü entfernen\n"
      << L"  --confirm-destruction TOKEN  Nichtinteraktive Löschbestätigung\n"
      << L"  --confirm-hardlink HARDLINK  Shared-Hardlink-Bestätigung\n";
}

std::optional<std::wstring_view> option_value(const int argc,
                                               wchar_t *argv[],
                                               const std::wstring_view name) {
  for (int index = 1; index < argc; ++index) {
    if (std::wstring_view{argv[index]} == name) {
      if (index + 1 >= argc)
        return std::nullopt;
      return std::wstring_view{argv[index + 1]};
    }
  }
  return std::nullopt;
}

bool confirm_irreversible(const bool json_output,
                          const std::optional<std::wstring_view> supplied,
                          const std::wstring_view prompt) {
  constexpr std::wstring_view token = L"OBLIVION";
  if (supplied)
    return *supplied == token;
  if (json_output)
    return false;
  std::wcout << prompt << L"\nExakt OBLIVION eingeben: ";
  std::wstring entered;
  std::getline(std::wcin, entered);
  return entered == token;
}

bool valid_destructive_tail(const int argc, wchar_t *argv[], int index) {
  bool json_seen = false, confirmation_seen = false;
  while (index < argc) {
    const std::wstring_view option = argv[index++];
    if (option == L"--json" && !json_seen) {
      json_seen = true;
      continue;
    }
    if (option == L"--confirm-destruction" && !confirmation_seen &&
        index < argc) {
      confirmation_seen = true;
      ++index;
      continue;
    }
    return false;
  }
  return true;
}

bool u(const std::wstring_view s, unsigned &v) {
  try {
    std::size_t n = 0;
    auto x = std::stoul(std::wstring{s}, &n);
    if (n != s.size() || x > 32)
      return false;
    v = static_cast<unsigned>(x);
    return true;
  } catch (...) {
    return false;
  }
}
std::wstring json_string(const std::wstring_view value) {
  constexpr wchar_t digits[] = L"0123456789abcdef";
  std::wstring result;
  result.reserve(value.size() + 2u);
  result.push_back(L'"');
  for (const wchar_t character : value) {
    switch (character) {
    case L'"': result += L"\\\""; break;
    case L'\\': result += L"\\\\"; break;
    case L'\b': result += L"\\b"; break;
    case L'\f': result += L"\\f"; break;
    case L'\n': result += L"\\n"; break;
    case L'\r': result += L"\\r"; break;
    case L'\t': result += L"\\t"; break;
    default: {
      const auto code_point = static_cast<unsigned>(character);
      if (code_point < 0x20u) {
        result += L"\\u00";
        result.push_back(digits[(code_point >> 4u) & 0x0fu]);
        result.push_back(digits[code_point & 0x0fu]);
      } else if (code_point >= 0xd800u && code_point <= 0xdfffu) {
        result += L"\\u";
        result.push_back(digits[(code_point >> 12u) & 0x0fu]);
        result.push_back(digits[(code_point >> 8u) & 0x0fu]);
        result.push_back(digits[(code_point >> 4u) & 0x0fu]);
        result.push_back(digits[code_point & 0x0fu]);
      } else {
        result.push_back(character);
      }
      break;
    }
    }
  }
  result.push_back(L'"');
  return result;
}
} // namespace

int wmain(int argc, wchar_t *argv[]) try {
  using namespace oblivion;
  const auto hardening = harden_current_process();
  if (argc == 2 && std::wstring_view{argv[1]} == L"--diagnostics") {
    std::wcout << format_runtime_hardening(hardening) << L'\n';
    return hardening.complete() ? 0 : 7;
  }
  if (!hardening.complete()) {
    std::wcerr << format_runtime_hardening(hardening) << L'\n';
    return 7;
  }

  bool json_output = false;
  for (int i = 1; i < argc; ++i) {
    if (std::wstring_view{argv[i]} == L"--json") {
      json_output = true;
      break;
    }
  }
  const auto destruction_confirmation =
      option_value(argc, argv, L"--confirm-destruction");

  if (argc >= 3 && std::wstring_view{argv[1]} == L"--export-certificate") {
    const std::filesystem::path audit_file = argv[2];
    std::filesystem::path out_file;
    bool output_seen = false, json_seen = false;
    for (int index = 3; index < argc; ++index) {
      const std::wstring_view argument = argv[index];
      if (argument == L"--json" && !json_seen) {
        json_seen = true;
      } else if (!argument.starts_with(L"--") && !output_seen) {
        out_file = argv[index];
        output_seen = true;
      } else {
        std::wcerr << L"Unbekanntes oder mehrfaches Argument für "
                      L"--export-certificate.\n";
        return 1;
      }
    }
    if (!output_seen) {
      out_file = audit_file;
      out_file.replace_extension(L".html");
    }
    const bool ok = generate_certificate_from_audit(audit_file, out_file);
    if (json_output) {
      std::wcout << L"{\"certificate_export\": " << (ok ? L"true" : L"false")
                 << L", \"output\": " << json_string(out_file.wstring())
                 << L"}\n";
    } else {
      std::wcout << (ok ? (L"Löschzertifikat erfolgreich erstellt: " + out_file.wstring() + L"\n")
                        : L"Fehler beim Erstellen des Löschzertifikats.\n");
    }
    return ok ? 0 : 9;
  }

  if (argc >= 3 && std::wstring_view{argv[1]} == L"--verify-audit") {
    for (int index = 3; index < argc; ++index) {
      if (std::wstring_view{argv[index]} != L"--json" || index != 3) {
        std::wcerr << L"Unbekanntes oder mehrfaches Argument für "
                      L"--verify-audit.\n";
        return 1;
      }
    }
    const std::filesystem::path audit_path{argv[2]};
    const bool record_valid = verify_audit_file(audit_path);
    const bool chain_valid =
        record_valid && verify_audit_chain(audit_path.parent_path());
    if (json_output) {
      std::wcout << L"{\"audit_file\": " << json_string(argv[2])
                 << L", \"record_valid\": "
                 << (record_valid ? L"true" : L"false")
                 << L", \"chain_valid\": "
                 << (chain_valid ? L"true" : L"false") << L"}\n";
    } else {
      if (chain_valid) {
        std::wcout << L"Einzeldatensatz-HMAC gültig & vollständige "
                      L"Audit-Kette bis chain.head verifiziert.\n";
      } else if (record_valid) {
        std::wcout << L"Einzeldatensatz-HMAC gültig, aber vollständige "
                      L"Audit-Kette bis chain.head nicht lückenlos "
                      L"verifizierbar.\n";
      } else {
        std::wcout << L"Audit-HMAC ungültig oder Datei manipuliert.\n";
      }
    }
    return chain_valid ? 0 : 8;
  }

  if (argc >= 2 && std::wstring_view{argv[1]} == L"--empty-recycle-bin") {
    if (!valid_destructive_tail(argc, argv, 2)) {
      std::wcerr << L"Unbekanntes oder unvollständiges Argument für "
                    L"--empty-recycle-bin.\n";
      return 1;
    }
    if (!confirm_irreversible(
            json_output, destruction_confirmation,
            L"Der vollständig aufgezählte Papierkorb wird sicher und "
            L"unwiderruflich geleert.")) {
      if (json_output)
        std::wcout << L"{\"action\": \"empty_recycle_bin\", "
                      L"\"success\": false, \"confirmation_required\": "
                      L"true}\n";
      return 4;
    }
    erase_options o = load_default_erase_options();
    auto cb = [json_output](const progress_info &i) {
      if (!json_output) {
        std::wcout << L"\r" << i.phase << L" · " << i.current.filename().wstring()
                   << L"        " << std::flush;
      }
      return true;
    };
    auto r = secure_empty_recycle_bin(o, cb);
    if (json_output) {
      std::wcout << L"{\"action\": \"empty_recycle_bin\", \"success\": "
                 << (r.success ? L"true" : L"false")
                 << L", \"files_deleted\": " << r.files_deleted
                 << L", \"bytes_written\": " << r.bytes_written << L"}\n";
    } else {
      std::wcout << L"\n" << r.message << L"\n";
    }
    return r.success ? 0 : 1;
  }

  if (argc >= 3 && std::wstring_view{argv[1]} == L"--wipe-free-space") {
    if (!valid_destructive_tail(argc, argv, 3)) {
      std::wcerr << L"Unbekanntes oder unvollständiges Argument für "
                    L"--wipe-free-space.\n";
      return 1;
    }
    if (!confirm_irreversible(
            json_output, destruction_confirmation,
            L"Der freie Speicherplatz des Zielvolumes wird überschrieben.")) {
      if (json_output)
        std::wcout << L"{\"action\": \"wipe_free_space\", \"success\": "
                      L"false, \"confirmation_required\": true}\n";
      return 4;
    }
    erase_options o = load_default_erase_options();
    const std::filesystem::path path = argv[2];
    auto cb = [json_output](const progress_info &i) {
      if (!json_output && i.total) {
        auto pc = static_cast<unsigned long long>(
            (std::min)(100.0L, static_cast<long double>(i.completed) * 100.0L /
                                   static_cast<long double>(i.total)));
        std::wcout << L"\r[" << pc << L"%] " << i.phase << L" · "
                   << (i.completed / (1024 * 1024)) << L" MiB geschrieben        "
                   << std::flush;
      }
      return true;
    };
    auto r = wipe_volume_free_space(path, o, cb);
    if (json_output) {
      std::wcout << L"{\"action\": \"wipe_free_space\", \"success\": "
                 << (r.success ? L"true" : L"false")
                 << L", \"bytes_written\": " << r.bytes_written << L"}\n";
    } else {
      std::wcout << L"\n" << r.message << L"\n";
    }
    return r.success ? 0 : 1;
  }

  if (argc < 2) {
    usage();
    return 1;
  }

  if (std::wstring_view{argv[1]} == L"--install-shell") {
    if (argc != 2) {
      std::wcerr << L"--install-shell akzeptiert keine weiteren Argumente.\n";
      return 1;
    }
    auto d = exe().parent_path();
    auto r =
        install_context_menu(d / L"Oblivion.exe", d / L"OblivionShell.dll");
    std::wcout << r.message << L"\n";
    return r.success ? 0 : 1;
  }

  if (std::wstring_view{argv[1]} == L"--uninstall-shell") {
    if (argc != 2) {
      std::wcerr << L"--uninstall-shell akzeptiert keine weiteren Argumente.\n";
      return 1;
    }
    auto r = uninstall_context_menu();
    std::wcout << r.message << L"\n";
    return r.success ? 0 : 1;
  }

  erase_options o = load_default_erase_options();
  bool analyze = false, elev = false;
  std::optional<std::wstring> supplied_delete_confirmation;
  std::optional<std::wstring> supplied_hardlink_confirmation;
  std::vector<std::filesystem::path> targets;

  for (int i = 1; i < argc; ++i) {
    std::wstring_view a = argv[i];
    if (a == L"--json") {
      json_output = true;
    } else if (a == L"--fast") {
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
    } else if (a == L"--no-verify") {
      o.verify = false;
    } else if (a == L"--no-ads") {
      o.erase_alternate_streams = false;
    } else if (a == L"--no-rename") {
      o.rename_before_delete = false;
    } else if (a == L"--rename-rounds") {
      if (i + 1 >= argc || !u(argv[++i], o.rename_rounds)) {
        std::wcerr << L"Ungültige Rename-Runden.\n";
        return 1;
      }
    } else if (a == L"--hardlink-block") {
      o.hardlinks = hardlink_policy::block;
    } else if (a == L"--hardlink-delete-name") {
      o.hardlinks = hardlink_policy::delete_link_only;
    } else if (a == L"--hardlink-overwrite-shared") {
      o.hardlinks = hardlink_policy::overwrite_shared_content;
    } else if (a == L"--analyze") {
      analyze = true;
    } else if (a == L"--elevated-retry") {
      elev = true;
    } else if (a == L"--confirm-destruction") {
      if (i + 1 >= argc || supplied_delete_confirmation) {
        std::wcerr << L"Bestätigungstoken fehlt oder wurde mehrfach angegeben.\n";
        return 1;
      }
      supplied_delete_confirmation = std::wstring{argv[++i]};
    } else if (a == L"--confirm-hardlink") {
      if (i + 1 >= argc || supplied_hardlink_confirmation) {
        std::wcerr << L"Hardlink-Bestätigungstoken fehlt oder wurde mehrfach "
                      L"angegeben.\n";
        return 1;
      }
      supplied_hardlink_confirmation = std::wstring{argv[++i]};
    } else if (a == L"--help" || a == L"-h" || a == L"/?") {
      usage();
      return 0;
    } else if (a.starts_with(L"--")) {
      std::wcerr << L"Unbekannte Option: " << a << L"\n";
      return 1;
    } else {
      targets.emplace_back(argv[i]);
    }
  }

  if (targets.empty()) {
    usage();
    return 1;
  }

  const bool shared_hardlink_overwrite_requested =
      o.hardlinks == hardlink_policy::overwrite_shared_content;
  apply_security_policy(o);
  if (shared_hardlink_overwrite_requested &&
      o.hardlinks != hardlink_policy::overwrite_shared_content) {
    if (json_output)
      std::wcout << L"{\"success\": false, \"policy_blocked\": "
                    L"\"shared_hardlink_overwrite\"}\n";
    else
      std::wcerr << L"Shared-Hardlink-Overwrite ist durch Richtlinie "
                    L"gesperrt.\n";
    return 6;
  }

  auto p = prepare_operation(targets);
  if (!p.valid) {
    if (json_output) {
      std::wcout << L"{\"valid\": false, \"error\": "
                 << json_string(p.error) << L"}\n";
    } else {
      std::wcerr << p.error << L"\n";
    }
    return 2;
  }

  if (json_output && analyze) {
    std::wcout << L"{\"valid\": true, \"files\": " << p.analysis.files
               << L", \"directories\": " << p.analysis.directories
               << L", \"logical_bytes\": " << p.analysis.logical_bytes
               << L", \"hardlinked_files\": " << p.analysis.hardlinked_files
               << L", \"alternate_streams\": " << p.analysis.alternate_streams
               << L", \"reparse_points\": " << p.analysis.reparse_points
               << L"}\n";
    return 0;
  }

  if (!json_output) {
    std::wcout << format_prepared_analysis(p) << L"\n";
  }

  if (analyze)
    return 0;

  if (requires_hardlink_confirmation(o)) {
    if (!supplied_hardlink_confirmation) {
      if (json_output)
        std::wcout << L"{\"success\": false, "
                      L"\"hardlink_confirmation_required\": true}\n";
      if (json_output)
        return 4;
      std::wcout << L"\nGEFÄHRLICH: gemeinsamer Hardlink-Inhalt. Exakt "
                    L"HARDLINK eingeben: ";
      std::wstring entered;
      std::getline(std::wcin, entered);
      supplied_hardlink_confirmation = std::move(entered);
    }
    if (*supplied_hardlink_confirmation != L"HARDLINK")
      return 4;
  }

  const std::wstring_view expected_confirmation =
      requires_typed_confirmation(p.analysis) ? L"OBLIVION" : L"JA";
  bool deletion_confirmed = supplied_delete_confirmation &&
                            *supplied_delete_confirmation ==
                                expected_confirmation;
  if (!deletion_confirmed && !json_output) {
    std::wcout << L"\n"
               << confirmation_text(p, o) << L"\n\nExakt "
               << expected_confirmation
               << L" eingeben: ";
    std::wstring ans;
    std::getline(std::wcin, ans);
    deletion_confirmed = ans == expected_confirmation;
  }
  if (!deletion_confirmed) {
    if (json_output)
      std::wcout << L"{\"success\": false, \"confirmation_required\": "
                    L"true}\n";
    return 4;
  }

  auto cb = [json_output](const progress_info &i) {
    if (!json_output) {
      auto d = i.overall_total ? i.overall_completed : i.completed,
           t = i.overall_total ? i.overall_total : i.total;
      auto pc = t ? static_cast<unsigned long long>(
                        (std::min)(100.0L, static_cast<long double>(d) * 100.0L /
                                               static_cast<long double>(t)))
                  : 0;
      std::wcout << L"\r[" << pc << L"%] " << i.phase << L" · "
                 << i.current.filename().wstring() << L" · Pass " << i.pass_index
                 << L"/" << i.pass_count << L"        " << std::flush;
    }
    return true;
  };

  auto r = execute_prepared_operation(p, o, cb, [] { return false; });

  if (json_output) {
    std::wcout << L"{\"exit_code\": " << r.exit_code
               << L", \"success\": " << (r.exit_code == 0 ? L"true" : L"false")
               << L", \"cancelled\": " << (r.cancelled ? L"true" : L"false")
               << L"}\n";
  } else {
    std::wcout << L"\n\n" << r.summary << L"\n";
  }

  if (r.exit_code == 5 && !json_output && !elev &&
      !r.elevation_retry_targets.empty() && !is_process_elevated()) {
    std::wcout << L"Mit Administratorrechten erneut versuchen? [j/N]: ";
    std::wstring x;
    std::getline(std::wcin, x);
    if (x == L"j" || x == L"J") {
      auto a = build_elevation_arguments(o, r.elevation_retry_targets);
      if (relaunch_elevated(exe(), a))
        return 0;
    }
  }
  return r.exit_code;
} catch (const std::exception &error) {
  std::cerr << "OBLIVION: Unbehandelte C++-Ausnahme: " << error.what() << '\n';
  return 10;
} catch (...) {
  std::cerr << "OBLIVION: Unbekannte Ausnahme.\n";
  return 10;
}
