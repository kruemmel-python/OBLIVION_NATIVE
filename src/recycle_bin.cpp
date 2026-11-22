#include "oblivion/recycle_bin.hpp"
#include "oblivion/erase_engine.hpp"

#include <Windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <algorithm>
#include <iterator>
#include <limits>
#include <new>
#include <string>
#ifdef OBLIVION_TESTING
#include "oblivion/test_hooks.hpp"
#endif

namespace oblivion {

namespace {
constexpr std::size_t max_recycle_items = 100000u;
std::uint64_t saturating_add(const std::uint64_t left,
                             const std::uint64_t right) noexcept {
  const auto maximum = (std::numeric_limits<std::uint64_t>::max)();
  return right > maximum - left ? maximum : left + right;
}
void merge_result(erase_result &target, const erase_result &source) {
  target.files_deleted =
      saturating_add(target.files_deleted, source.files_deleted);
  target.directories_deleted =
      saturating_add(target.directories_deleted, source.directories_deleted);
  target.bytes_written =
      saturating_add(target.bytes_written, source.bytes_written);
  target.alternate_streams_overwritten = saturating_add(
      target.alternate_streams_overwritten, source.alternate_streams_overwritten);
  target.reparse_points_removed = saturating_add(
      target.reparse_points_removed, source.reparse_points_removed);
  target.hardlinks_blocked =
      saturating_add(target.hardlinks_blocked, source.hardlinks_blocked);
  if (target.win32_error == ERROR_SUCCESS)
    target.win32_error = source.win32_error;
  constexpr std::size_t max_diagnostics = 256u;
  for (const auto &warning : source.warnings) {
    if (target.warnings.size() >= max_diagnostics)
      break;
    target.warnings.push_back(warning);
  }
  for (const auto &owner : source.lock_owners) {
    if (target.lock_owners.size() >= max_diagnostics)
      break;
    target.lock_owners.push_back(owner);
  }
}
}

recycle_bin_scan_result scan_recycle_bin_items() noexcept try {
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
    if (!result.complete)
      break;
    if ((drive_mask & (1 << d)) == 0)
      continue;

    const wchar_t root[] = {static_cast<wchar_t>(L'A' + d), L':', L'\\', L'\0'};
    const UINT drive_type = GetDriveTypeW(root);
    if (drive_type != DRIVE_FIXED && drive_type != DRIVE_REMOVABLE)
      continue;
    wchar_t volume_name[1024]{};
    if (!GetVolumeNameForVolumeMountPointW(root, volume_name,
                                           static_cast<DWORD>(std::size(volume_name)))) {
      result.complete = false;
      result.win32_error = GetLastError();
      continue;
    }
    result.scanned_roots.emplace_back(root);
    result.scanned_volumes.emplace_back(volume_name);

    const auto bin_path = std::filesystem::path{root} / L"$Recycle.Bin";
    std::error_code ec;
    if (!std::filesystem::exists(bin_path, ec)) {
      if (ec)
        fail(ec);
      continue;
    }
    const DWORD bin_attributes = GetFileAttributesW(bin_path.c_str());
    if (bin_attributes == INVALID_FILE_ATTRIBUTES ||
        (bin_attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
        (bin_attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
      result.complete = false;
      result.win32_error = bin_attributes == INVALID_FILE_ATTRIBUTES
                               ? GetLastError()
                               : ERROR_REPARSE_TAG_INVALID;
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
      const DWORD sid_attributes = GetFileAttributesW(sid_it->path().c_str());
      if (sid_attributes == INVALID_FILE_ATTRIBUTES) {
        result.complete = false;
        result.win32_error = GetLastError();
        break;
      }
      if ((sid_attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        result.complete = false;
        result.win32_error = ERROR_REPARSE_TAG_INVALID;
        break;
      }
      const bool is_directory =
          (sid_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
      // Finde darin alle $R* (Nutzdaten) und $I* (Indexdateien), ohne desktop.ini
      if (is_directory) {
        std::filesystem::directory_iterator item_it(sid_it->path(), ec), item_end;
        if (ec) {
          fail(ec);
          break;
        }
        while (item_it != item_end) {
          if (_wcsicmp(item_it->path().filename().c_str(), L"desktop.ini") !=
              0) {
            if (result.items.size() >= max_recycle_items) {
              result.complete = false;
              result.win32_error = ERROR_TOO_MANY_NAMES;
              break;
            }
            result.items.push_back(item_it->path());
          }
          item_it.increment(ec);
          if (ec) {
            fail(ec);
            break;
          }
        }
        if (!result.complete)
          break;
      } else if (_wcsicmp(sid_it->path().filename().c_str(), L"desktop.ini") !=
                 0) {
        result.complete = false;
        result.win32_error = ERROR_INVALID_DATA;
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
} catch (const std::bad_alloc &) {
  recycle_bin_scan_result result;
  result.complete = false;
  result.win32_error = ERROR_NOT_ENOUGH_MEMORY;
  return result;
} catch (...) {
  recycle_bin_scan_result result;
  result.complete = false;
  result.win32_error = ERROR_UNHANDLED_EXCEPTION;
  return result;
}

std::vector<std::filesystem::path> find_recycle_bin_items() noexcept {
  return scan_recycle_bin_items().items;
}

erase_result secure_empty_recycle_bin(
    const erase_options &options,
    const progress_callback &callback) noexcept {
  erase_result result{};
  try {
  if (!valid_erase_options(options)) {
    result.win32_error = ERROR_INVALID_PARAMETER;
    result.message = L"Ungültige oder unbeschränkte Engine-Optionen.";
    return result;
  }
#ifdef OBLIVION_TESTING
  const auto scan = testing::hooks().recycle_scan
                        ? testing::hooks().recycle_scan()
                        : scan_recycle_bin_items();
#else
  const auto scan = scan_recycle_bin_items();
#endif
  if (!scan.complete) {
    result.win32_error = scan.win32_error;
    result.message = L"Papierkorb-Aufzählung unvollständig; reguläre Windows-"
                     L"Bereinigung wurde zum Schutz vor unüberschriebenem "
                     L"Löschen nicht ausgeführt.";
    return result;
  }
  const auto &items = scan.items;

  // Sicheres Überschreiben aller im Papierkorb befindlichen Objekte
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
    merge_result(result, r);
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
  }

  // A second complete scan detects objects that appeared during overwriting.
  // No destructive shell API is called afterwards: such an API would reopen
  // a race in which a newly recycled, unoverwritten object could be deleted.
  if (result.success && !result.cancelled) {
#ifdef OBLIVION_TESTING
    const auto pre_shell_scan = testing::hooks().recycle_scan
                                    ? testing::hooks().recycle_scan()
                                    : scan_recycle_bin_items();
#else
    const auto pre_shell_scan = scan_recycle_bin_items();
#endif
    const auto same_path = [](const std::filesystem::path &left,
                              const std::filesystem::path &right) {
      return CompareStringOrdinal(left.c_str(), -1, right.c_str(), -1, TRUE) ==
             CSTR_EQUAL;
    };
    const bool same_volume_map =
        pre_shell_scan.scanned_roots.size() == scan.scanned_roots.size() &&
        pre_shell_scan.scanned_volumes.size() == scan.scanned_volumes.size() &&
        pre_shell_scan.scanned_roots.size() == scan.scanned_volumes.size() &&
        std::equal(scan.scanned_roots.begin(), scan.scanned_roots.end(),
                   pre_shell_scan.scanned_roots.begin(), same_path) &&
        std::equal(scan.scanned_volumes.begin(), scan.scanned_volumes.end(),
                   pre_shell_scan.scanned_volumes.begin(), same_path);
    if (!pre_shell_scan.complete || !pre_shell_scan.items.empty() ||
        !same_volume_map) {
      result.success = false;
      result.win32_error = !pre_shell_scan.complete
                               ? pre_shell_scan.win32_error
                               : (!same_volume_map ? ERROR_MEDIA_CHANGED
                                                   : ERROR_DIR_NOT_EMPTY);
      result.message = L"Papierkorb hat sich während der sicheren "
                       L"Verarbeitung geändert oder konnte nicht vollständig "
                       L"erneut aufgezählt werden; reguläre Windows-"
                       L"Bereinigung wird nicht ausgeführt.";
    }
  }

  // OBLIVION removes the enumerated $R/$I objects itself.  Notify Explorer of
  // the filesystem change, then query every scanned volume separately.  The
  // notification is non-destructive; a concurrently added object remains
  // intact and makes the final verification fail instead of being deleted.
  if (result.success && !result.cancelled) {
#ifndef OBLIVION_TESTING
    for (const auto &root : scan.scanned_roots) {
      const auto recycle_directory = root / L"$Recycle.Bin";
      SHChangeNotify(SHCNE_UPDATEDIR,
                     SHCNF_PATHW | SHCNF_FLUSHNOWAIT,
                     recycle_directory.c_str(), nullptr);
    }
#endif
#ifdef OBLIVION_TESTING
    const auto query = testing::hooks().recycle_query
                           ? testing::hooks().recycle_query
                           : SHQueryRecycleBinW;
#else
    const auto query = SHQueryRecycleBinW;
#endif
    std::int64_t remaining_items = 0;
    for (const auto &root : scan.scanned_roots) {
      SHQUERYRBINFO query_info{};
      query_info.cbSize = sizeof(query_info);
      const HRESULT query_result = query(root.c_str(), &query_info);
      if (FAILED(query_result)) {
        result.success = false;
        result.win32_error = HRESULT_CODE(query_result);
        result.message = L"Die erfassten Papierkorbobjekte wurden sicher "
                         L"entfernt, aber der Endzustand konnte nicht für "
                         L"alle Volumes verifiziert werden.";
        break;
      } else if (query_info.i64NumItems < 0) {
        result.success = false;
        result.win32_error = ERROR_INVALID_DATA;
        result.message = L"Die Windows-Papierkorbabfrage lieferte einen "
                         L"ungültigen Endzustand.";
        break;
      } else if (query_info.i64NumItems != 0) {
        result.success = false;
        result.win32_error = ERROR_DIR_NOT_EMPTY;
        remaining_items = query_info.i64NumItems;
        break;
      }
    }
    if (result.success) {
      if (items.empty()) {
        result.message = L"Papierkorb ist leer (Endzustand verifiziert).";
      } else {
        result.message =
            L"Papierkorb wurde sicher geleert und der Endzustand verifiziert (" +
            std::to_wstring(result.files_deleted) + L" Dateien, " +
            std::to_wstring(result.directories_deleted) + L" Ordner vernichtet).";
      }
    } else if (result.win32_error == ERROR_DIR_NOT_EMPTY) {
      result.message =
          L"Die erfassten Papierkorbobjekte wurden sicher entfernt, aber "
          L"mindestens ein Volume enthält " +
          std::to_wstring(remaining_items) +
          L" neues oder verbleibendes Objekt; es wurde nicht durch eine "
          L"destruktive Shell-Bereinigung gelöscht.";
    }
  } else if (!result.cancelled && result.message.empty()) {
    result.message =
        L"Papierkorb-Leerung unvollständig; reguläre Windows-Bereinigung "
        L"wurde zum Schutz vor unüberschriebenem Löschen ausgesetzt.";
  }
  return result;
  } catch (const std::bad_alloc &) {
    result.success = false;
    if (result.win32_error == ERROR_SUCCESS)
      result.win32_error = ERROR_NOT_ENOUGH_MEMORY;
    return result;
  } catch (...) {
    result.success = false;
    if (result.win32_error == ERROR_SUCCESS)
      result.win32_error = ERROR_UNHANDLED_EXCEPTION;
    return result;
  }
}

} // namespace oblivion
