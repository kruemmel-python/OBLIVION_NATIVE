#include "oblivion/recycle_bin.hpp"
#include "oblivion/erase_engine.hpp"

#include <Windows.h>
#include <shellapi.h>
#include <algorithm>
#include <string>
#ifdef OBLIVION_TESTING
#include "oblivion/test_hooks.hpp"
#endif

namespace oblivion {

recycle_bin_scan_result scan_recycle_bin_items() {
  recycle_bin_scan_result result;

  const auto fail = [&result](const std::error_code &ec) {
    result.complete = false;
    if (result.win32_error == 0)
      result.win32_error = static_cast<std::uint32_t>(ec.value());
  };

  const DWORD drive_mask = GetLogicalDrives();
  if (drive_mask == 0) {
    result.complete = false;
    result.win32_error = GetLastError();
    return result;
  }
  for (int d = 0; d < 26; ++d) {
    if ((drive_mask & (1 << d)) == 0)
      continue;

    const wchar_t root[] = {static_cast<wchar_t>(L'A' + d), L':', L'\\', L'\0'};
    const UINT drive_type = GetDriveTypeW(root);
    if (drive_type != DRIVE_FIXED && drive_type != DRIVE_REMOVABLE)
      continue;

    const auto bin_path = std::filesystem::path{root} / L"$Recycle.Bin";
    std::error_code ec;
    if (!std::filesystem::exists(bin_path, ec)) {
      if (ec)
        fail(ec);
      continue;
    }

    // Permission errors deliberately remain visible.  Silently skipping a
    // directory would let the shell delete data that was not overwritten.
    std::filesystem::directory_iterator sid_it(bin_path, ec), end_it;
    if (ec) {
      fail(ec);
      continue;
    }
    while (sid_it != end_it) {
      const bool is_directory = sid_it->is_directory(ec);
      if (ec) {
        fail(ec);
        break;
      }
      // Finde darin alle $R* (Nutzdaten) und $I* (Indexdateien), ohne desktop.ini
      if (is_directory) {
        std::filesystem::directory_iterator item_it(sid_it->path(), ec), item_end;
        if (ec) {
          fail(ec);
          break;
        }
        while (item_it != item_end) {
          if (_wcsicmp(item_it->path().filename().c_str(), L"desktop.ini") != 0)
            result.items.push_back(item_it->path());
          item_it.increment(ec);
          if (ec) {
            fail(ec);
            break;
          }
        }
        if (!result.complete)
          break;
      }
      sid_it.increment(ec);
      if (ec) {
        fail(ec);
        break;
      }
    }
  }

  return result;
}

std::vector<std::filesystem::path> find_recycle_bin_items() {
  return scan_recycle_bin_items().items;
}

erase_result secure_empty_recycle_bin(
    const erase_options &options,
    const progress_callback &callback) {
#ifdef OBLIVION_TESTING
  const auto scan = testing::hooks().recycle_scan
                        ? testing::hooks().recycle_scan()
                        : scan_recycle_bin_items();
#else
  const auto scan = scan_recycle_bin_items();
#endif
  if (!scan.complete) {
    erase_result r{};
    r.win32_error = scan.win32_error;
    r.message = L"Papierkorb-Aufzählung unvollständig; reguläre Windows-"
                L"Bereinigung wurde zum Schutz vor unüberschriebenem Löschen "
                L"nicht ausgeführt.";
    return r;
  }
  const auto &items = scan.items;

  // Sicheres Überschreiben aller im Papierkorb befindlichen Objekte
  erase_result result{};
  result.success = true;
  erase_engine engine;
  for (const auto &item : items) {
    std::error_code ec;
#ifdef OBLIVION_TESTING
    const bool item_exists = testing::hooks().recycle_exists
                                 ? testing::hooks().recycle_exists(item, ec)
                                 : std::filesystem::exists(item, ec);
#else
    const bool item_exists = std::filesystem::exists(item, ec);
#endif
    if (ec) {
      result.success = false;
      result.win32_error = static_cast<std::uint32_t>(ec.value());
      result.message = L"Papierkorb-Objekt konnte vor dem sicheren "
                       L"Überschreiben nicht geprüft werden; reguläre "
                       L"Windows-Bereinigung wird nicht ausgeführt.";
      break;
    }
    if (!item_exists)
      continue;
#ifdef OBLIVION_TESTING
    const auto r = testing::hooks().recycle_erase
                       ? testing::hooks().recycle_erase(item, options, callback)
                       : engine.erase_recycle_bin_item(item, options, callback);
#else
    const auto r = engine.erase_recycle_bin_item(item, options, callback);
#endif
    if (r.cancelled) {
      result.success = false;
      result.cancelled = true;
      result.message = r.message;
      break;
    }
    if (!r.success) {
      result.success = false;
      result.message = r.message;
    }
    result.files_deleted += r.files_deleted;
    result.directories_deleted += r.directories_deleted;
    result.bytes_written += r.bytes_written;
  }

  // A second complete scan closes the interval between enumeration and the
  // shell operation.  Objects that appeared meanwhile must never be deleted
  // by SHEmptyRecycleBinW without having been overwritten first.
  if (result.success && !result.cancelled) {
#ifdef OBLIVION_TESTING
    const auto pre_shell_scan = testing::hooks().recycle_scan
                                    ? testing::hooks().recycle_scan()
                                    : scan_recycle_bin_items();
#else
    const auto pre_shell_scan = scan_recycle_bin_items();
#endif
    if (!pre_shell_scan.complete || !pre_shell_scan.items.empty()) {
      result.success = false;
      result.win32_error = pre_shell_scan.complete
                               ? ERROR_DIR_NOT_EMPTY
                               : pre_shell_scan.win32_error;
      result.message = L"Papierkorb hat sich während der sicheren "
                       L"Verarbeitung geändert oder konnte nicht vollständig "
                       L"erneut aufgezählt werden; reguläre Windows-"
                       L"Bereinigung wird nicht ausgeführt.";
    }
  }

  // Nur wenn alle Papierkorb-Objekte ohne Abbruch/Fehler sicher überschrieben
  // wurden und der erneute Scan leer und vollständig ist, den
  // Windows-Papierkorbindex bereinigen.
  if (result.success && !result.cancelled) {
#ifdef OBLIVION_TESTING
    const auto empty = testing::hooks().recycle_empty
                           ? testing::hooks().recycle_empty
                           : SHEmptyRecycleBinW;
#else
    const auto empty = SHEmptyRecycleBinW;
#endif
    const HRESULT empty_result = empty(nullptr, nullptr,
                                       SHERB_NOCONFIRMATION |
                                           SHERB_NOPROGRESSUI | SHERB_NOSOUND);
    if (FAILED(empty_result)) {
      result.success = false;
      result.win32_error = HRESULT_CODE(empty_result);
      result.message = L"Windows-Papierkorbindex konnte nach dem sicheren "
                       L"Überschreiben nicht bereinigt werden.";
    } else {
      SHQUERYRBINFO query_info{};
      query_info.cbSize = sizeof(query_info);
#ifdef OBLIVION_TESTING
      const auto query = testing::hooks().recycle_query
                             ? testing::hooks().recycle_query
                             : SHQueryRecycleBinW;
#else
      const auto query = SHQueryRecycleBinW;
#endif
      const HRESULT query_result = query(nullptr, &query_info);
      if (FAILED(query_result)) {
        result.success = false;
        result.win32_error = HRESULT_CODE(query_result);
        result.message = L"Sicheres Überschreiben und Windows-Bereinigung "
                         L"waren erfolgreich, aber der Papierkorb-Endzustand "
                         L"konnte nicht verifiziert werden.";
      } else if (query_info.i64NumItems != 0) {
        result.success = false;
        result.win32_error = ERROR_DIR_NOT_EMPTY;
        result.message = L"Sicheres Überschreiben und Windows-Bereinigung "
                         L"waren erfolgreich, aber der Papierkorb enthält " +
                         std::to_wstring(query_info.i64NumItems) +
                         L" verbleibende Objekte.";
      } else if (items.empty()) {
        result.message = L"Papierkorb ist leer (Endzustand verifiziert).";
      } else {
        result.message =
            L"Papierkorb wurde sicher geleert und der Endzustand verifiziert (" +
            std::to_wstring(result.files_deleted) + L" Dateien, " +
            std::to_wstring(result.directories_deleted) + L" Ordner vernichtet).";
      }
    }
  } else if (!result.cancelled && result.message.empty()) {
    result.message =
        L"Papierkorb-Leerung unvollständig; reguläre Windows-Bereinigung "
        L"wurde zum Schutz vor unüberschriebenem Löschen ausgesetzt.";
  }
  return result;
}

} // namespace oblivion
