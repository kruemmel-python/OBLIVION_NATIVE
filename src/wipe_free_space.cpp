#include "oblivion/wipe_free_space.hpp"
#include "oblivion/erase_engine.hpp"
#include "oblivion/random.hpp"
#include "oblivion/secure_memory.hpp"
#include "oblivion/win_handle.hpp"

#include <Windows.h>
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <new>
#include <sstream>
#include <vector>
#ifdef OBLIVION_TESTING
#include "oblivion/test_hooks.hpp"
#endif

namespace oblivion {
namespace {

std::wstring format_size(std::uint64_t bytes) {
  wchar_t buf[64]{};
  const double gib = static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0);
  if (gib >= 1.0) {
    swprintf_s(buf, L"%.2f GiB", gib);
  } else {
    const double mib = static_cast<double>(bytes) / (1024.0 * 1024.0);
    swprintf_s(buf, L"%.1f MiB", mib);
  }
  return buf;
}

bool clean_wipe_directory(const std::filesystem::path &dir,
                          const std::vector<std::filesystem::path> &files,
                          unique_win_handle &directory_handle,
                          DWORD &error) {
  bool complete = true;
  error = ERROR_SUCCESS;
  for (const auto &file : files) {
    unique_win_handle file_handle{CreateFileW(
        file.c_str(), DELETE | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES, 0,
        nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
    if (!file_handle) {
      const DWORD current = GetLastError();
      if (current == ERROR_FILE_NOT_FOUND || current == ERROR_PATH_NOT_FOUND)
        continue;
      if (error == ERROR_SUCCESS)
        error = current;
      complete = false;
      continue;
    }
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    FILE_BASIC_INFO basic{};
    FILE_DISPOSITION_INFO disposition{TRUE};
    if (!GetFileInformationByHandleEx(file_handle.get(), FileAttributeTagInfo,
                                      &attributes, sizeof(attributes)) ||
        (attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ||
        !GetFileInformationByHandleEx(file_handle.get(), FileBasicInfo, &basic,
                                      sizeof(basic))) {
      if (error == ERROR_SUCCESS)
        error = GetLastError();
      complete = false;
      continue;
    }
    basic.FileAttributes = FILE_ATTRIBUTE_NORMAL;
    if (!SetFileInformationByHandle(file_handle.get(), FileBasicInfo, &basic,
                                    sizeof(basic)) ||
        !SetFileInformationByHandle(file_handle.get(), FileDispositionInfo,
                                    &disposition, sizeof(disposition))) {
      if (error == ERROR_SUCCESS)
        error = GetLastError();
      complete = false;
    }
  }
  directory_handle.reset();
  if (!RemoveDirectoryW(dir.c_str())) {
    if (error == ERROR_SUCCESS)
      error = GetLastError();
    complete = false;
  }
  return complete;
}

bool create_wipe_directory(const std::filesystem::path &volume_root,
                           std::filesystem::path &directory, DWORD &error) {
  constexpr wchar_t digits[] = L"0123456789abcdef";
  for (unsigned attempt = 0; attempt < 32; ++attempt) {
    std::array<std::byte, 16> random{};
    if (!try_fill_secure_random(random)) {
      error = ERROR_GEN_FAILURE;
      return false;
    }
    std::wstring name = L".oblivion_wipetmp_";
    name.reserve(name.size() + random.size() * 2u);
    for (const auto byte : random) {
      const auto value = std::to_integer<unsigned>(byte);
      name.push_back(digits[(value >> 4u) & 0x0fu]);
      name.push_back(digits[value & 0x0fu]);
    }
    directory = volume_root / name;
    if (CreateDirectoryW(directory.c_str(), nullptr)) {
      const DWORD attributes = GetFileAttributesW(directory.c_str());
      if (attributes != INVALID_FILE_ATTRIBUTES &&
          (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
          (attributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0) {
        error = ERROR_SUCCESS;
        return true;
      }
      error = attributes == INVALID_FILE_ATTRIBUTES ? GetLastError()
                                                    : ERROR_REPARSE_TAG_INVALID;
      (void)RemoveDirectoryW(directory.c_str());
      return false;
    }
    error = GetLastError();
    if (error != ERROR_ALREADY_EXISTS && error != ERROR_FILE_EXISTS)
      return false;
  }
  error = ERROR_FILE_EXISTS;
  return false;
}

} // namespace

erase_result wipe_volume_free_space(
    const std::filesystem::path &target_volume_or_path,
    const erase_options &options,
    const progress_callback &callback) noexcept {
  erase_result result{};
  std::uint64_t total_written = 0;
  try {
  if (!valid_erase_options(options)) {
    result.win32_error = ERROR_INVALID_PARAMETER;
    result.message = L"Ungültige oder unbeschränkte Engine-Optionen.";
    return result;
  }

  wchar_t volume_root[MAX_PATH + 1]{};
  if (!GetVolumePathNameW(target_volume_or_path.c_str(), volume_root,
                          MAX_PATH + 1u)) {
    result.win32_error = GetLastError();
    result.message = L"Volume-Pfad konnte nicht ermittelt werden: " +
                     target_volume_or_path.wstring();
    return result;
  }
  std::array<wchar_t, 1024> volume_guid{};
  if (!GetVolumeNameForVolumeMountPointW(
          volume_root, volume_guid.data(),
          static_cast<DWORD>(volume_guid.size()))) {
    result.win32_error = GetLastError();
    result.message = L"Volume-GUID konnte nicht stabil ermittelt werden: " +
                     std::wstring{volume_root};
    return result;
  }
  const UINT drive_type = GetDriveTypeW(volume_guid.data());
  if (drive_type != DRIVE_FIXED && drive_type != DRIVE_REMOVABLE) {
    result.win32_error = ERROR_NOT_SUPPORTED;
    result.message =
        L"Freispeicher-Bereinigung ist nur auf lokalen festen oder "
        L"entfernbaren Datenträgern erlaubt.";
    return result;
  }

  ULARGE_INTEGER free_bytes_caller{}, total_bytes{}, total_free_bytes{};
  if (!GetDiskFreeSpaceExW(volume_guid.data(), &free_bytes_caller, &total_bytes,
                           &total_free_bytes)) {
    result.win32_error = GetLastError();
    result.message =
        L"Freier Speicherplatz konnte nicht abgefragt werden: " +
        std::wstring{volume_root};
    return result;
  }

  const std::uint64_t initial_free = free_bytes_caller.QuadPart;
  if (initial_free == 0) {
    result.success = true;
    result.message = L"Kein freier Speicherplatz auf Volume vorhanden.";
    return result;
  }

  // Der Name ist nicht vorhersagbar und CreateDirectoryW akzeptiert keine
  // vorbereitete Junction bzw. kein bereits bestehendes Verzeichnis.
  std::filesystem::path wipe_dir;
  DWORD directory_error = ERROR_SUCCESS;
  if (!create_wipe_directory(volume_guid.data(), wipe_dir, directory_error)) {
    result.win32_error = directory_error;
    result.message = L"Temporäres Bereinigungsverzeichnis konnte nicht erstellt "
                     L"werden: " +
                     wipe_dir.wstring();
    return result;
  }
  if (!SetFileAttributesW(wipe_dir.c_str(),
                          FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) {
    result.win32_error = GetLastError();
    (void)RemoveDirectoryW(wipe_dir.c_str());
    result.message = L"Temporäres Bereinigungsverzeichnis konnte nicht "
                     L"gehärtet werden.";
    return result;
  }
  unique_win_handle wipe_directory_handle{CreateFileW(
      wipe_dir.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
      nullptr, OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
  FILE_ATTRIBUTE_TAG_INFO wipe_directory_attributes{};
  DWORD directory_lock_error = ERROR_SUCCESS;
  if (!wipe_directory_handle)
    directory_lock_error = GetLastError();
  else if (!GetFileInformationByHandleEx(
               wipe_directory_handle.get(), FileAttributeTagInfo,
               &wipe_directory_attributes, sizeof(wipe_directory_attributes)))
    directory_lock_error = GetLastError();
  else if ((wipe_directory_attributes.FileAttributes &
            FILE_ATTRIBUTE_DIRECTORY) == 0 ||
           (wipe_directory_attributes.FileAttributes &
            FILE_ATTRIBUTE_REPARSE_POINT) != 0)
    directory_lock_error = ERROR_REPARSE_TAG_INVALID;
  if (directory_lock_error != ERROR_SUCCESS) {
    result.win32_error = directory_lock_error;
    wipe_directory_handle.reset();
    (void)RemoveDirectoryW(wipe_dir.c_str());
    result.message = L"Temporäres Bereinigungsverzeichnis konnte nicht sicher "
                     L"gesperrt werden.";
    return result;
  }

  std::vector<std::filesystem::path> created_files;

  // RAII Cleanup Guard: Garantiert, dass temporäre Dateien bei Fehler oder Abbruch gelöscht werden
  struct cleanup_guard {
    const std::filesystem::path &dir;
    std::vector<std::filesystem::path> &files;
    unique_win_handle &directory_handle;
    bool armed{true};
    ~cleanup_guard() {
      if (armed) {
        DWORD ignored = ERROR_SUCCESS;
        (void)clean_wipe_directory(dir, files, directory_handle, ignored);
      }
    }
  } guard{wipe_dir, created_files, wipe_directory_handle, true};

  const auto finish_with_cleanup = [&]() -> erase_result {
    guard.armed = false;
    DWORD cleanup_error = ERROR_SUCCESS;
    result.bytes_written = total_written;
    if (!clean_wipe_directory(wipe_dir, created_files, wipe_directory_handle,
                              cleanup_error)) {
      result.success = false;
      if (result.win32_error == ERROR_SUCCESS)
        result.win32_error = cleanup_error ? cleanup_error : ERROR_CANNOT_MAKE;
      if (!result.message.empty())
        result.message += L" ";
      result.message +=
          L"Temporäre Bereinigungsdateien konnten nicht vollständig entfernt "
          L"werden.";
    }
    return result;
  };

  // Puffer für Schreibvorgänge
  constexpr std::size_t BUFFER_SIZE = 4u * 1024u * 1024u; // 4 MiB
  secure_buffer buf{BUFFER_SIZE};
  if (!buf.valid()) {
    result.win32_error = ERROR_OUTOFMEMORY;
    result.message = L"Arbeitsspeicher für Bereinigungspuffer konnte nicht "
                     L"reserviert werden.";
    return finish_with_cleanup();
  }

  // Füllmuster vorbereiten: Je nach Modus Random oder Zero
  const bool use_random = (options.mode != erase_mode::nist_800_88);
  if (use_random) {
    if (!try_fill_secure_random(buf.bytes())) {
      result.win32_error = ERROR_GEN_FAILURE;
      result.message = L"CSPRNG-Fehler beim Initialisieren des "
                       L"Freispeicher-Bereinigungspuffers.";
      return finish_with_cleanup();
    }
  } else {
    buf.clear();
  }

  std::uint32_t chunk_index = 0;
  bool disk_full = false;

  // Chunk-Größe: Starte mit 512 MiB pro Datei, verkleinere bei Annäherung an Disk-Full
  std::uint64_t max_chunk_size = 512ULL * 1024ULL * 1024ULL;
#ifdef OBLIVION_TESTING
  if (testing::hooks().wipe_max_chunk_bytes != 0)
    max_chunk_size = testing::hooks().wipe_max_chunk_bytes;
#endif

  while (!disk_full && !result.cancelled) {
    std::wostringstream name_stream;
    name_stream << L"wipe_chunk_" << std::setw(8) << std::setfill(L'0')
                << ++chunk_index << L".tmp";
    const auto chunk_path = wipe_dir / name_stream.str();

    unique_win_handle file_handle{CreateFileW(
        chunk_path.c_str(), GENERIC_WRITE | GENERIC_READ | DELETE, 0, nullptr,
        CREATE_NEW,
        FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_TEMPORARY |
            FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr)};

    if (!file_handle) {
      const DWORD err = GetLastError();
      if (err == ERROR_DISK_FULL || err == ERROR_HANDLE_DISK_FULL) {
        disk_full = true;
        break;
      }
      result.win32_error = err;
      result.message =
          L"Temporäre Datei konnte nicht angelegt werden: " + chunk_path.wstring();
      return finish_with_cleanup();
    }

    try {
      created_files.push_back(chunk_path);
    } catch (...) {
      FILE_DISPOSITION_INFO disposition{TRUE};
      const bool discard_ok =
          SetFileInformationByHandle(file_handle.get(), FileDispositionInfo,
                                     &disposition, sizeof(disposition)) != FALSE;
      const DWORD discard_error = discard_ok ? ERROR_SUCCESS : GetLastError();
      file_handle.reset();
      result.win32_error =
          discard_ok ? ERROR_NOT_ENOUGH_MEMORY : discard_error;
      result.message =
          discard_ok
              ? L"Temporäre Bereinigungsdatei konnte nicht sicher "
                L"nachverfolgt werden."
              : L"Temporäre Bereinigungsdatei konnte nach einem "
                L"Speicherfehler nicht handlegebunden verworfen werden.";
      return finish_with_cleanup();
    }

    std::uint64_t chunk_written = 0;
    while (chunk_written < max_chunk_size) {
      const DWORD to_write = static_cast<DWORD>(
          (std::min)(static_cast<std::uint64_t>(buf.size()),
                     max_chunk_size - chunk_written));

      if (use_random && (chunk_written % (64ULL * 1024ULL * 1024ULL) == 0)) {
        // Entropie periodisch auffrischen
        if (!try_fill_secure_random(buf.bytes())) {
          result.win32_error = ERROR_GEN_FAILURE;
          result.message =
              L"CSPRNG-Fehler während Freispeicher-Bereinigung.";
          file_handle.reset();
          return finish_with_cleanup();
        }
      }

      DWORD written = 0;
      if (!WriteFile(file_handle.get(), buf.data(), to_write, &written, nullptr) ||
          written != to_write) {
        const DWORD write_err = GetLastError();
        if (write_err == ERROR_DISK_FULL ||
            write_err == ERROR_HANDLE_DISK_FULL) {
          disk_full = true;
          total_written += written;
          break;
        }
        result.win32_error = write_err;
        result.message = L"Schreibfehler während Freispeicher-Bereinigung.";
        file_handle.reset();
        return finish_with_cleanup();
      }

      chunk_written += written;
      total_written += written;

      if (callback) {
        progress_info pi{};
        pi.current = chunk_path;
        pi.phase = L"Freien Speicherplatz überschreiben";
        pi.pass_name = use_random ? L"Zufallsmuster" : L"Null-Muster";
        pi.pass_index = 1;
        pi.pass_count = 1;
        pi.completed = total_written;
        pi.total = (std::max)(initial_free, total_written);
        pi.bytes_written_total = total_written;

        if (!callback(pi)) {
          result.cancelled = true;
          result.message = L"Bereinigung des freien Speichers abgebrochen.";
          file_handle.reset();
          return finish_with_cleanup();
        }
      }
    }

#ifdef OBLIVION_TESTING
    const auto flush = testing::hooks().flush ? testing::hooks().flush
                                              : FlushFileBuffers;
#else
    const auto flush = FlushFileBuffers;
#endif
    if (!flush(file_handle.get())) {
      result.win32_error = GetLastError();
      if (result.win32_error == ERROR_SUCCESS)
        result.win32_error = ERROR_WRITE_FAULT;
      result.message =
          L"FlushFileBuffers während Freispeicher-Bereinigung fehlgeschlagen.";
      file_handle.reset();
      return finish_with_cleanup();
    }
  }

  // Alle temporären Chunks schließen, zurücksetzen und bereinigen
  DWORD cleanup_error = ERROR_SUCCESS;
  guard.armed = false;
  if (!clean_wipe_directory(wipe_dir, created_files, wipe_directory_handle,
                            cleanup_error)) {
    result.win32_error = cleanup_error ? cleanup_error : ERROR_CANNOT_MAKE;
    result.bytes_written = total_written;
    result.message = L"Freispeicher wurde überschrieben, aber temporäre "
                     L"Bereinigungsdateien konnten nicht vollständig entfernt "
                     L"werden.";
    return result;
  }

  if (total_written == 0 && initial_free != 0) {
    result.win32_error = ERROR_DISK_FULL;
    result.message =
        L"Das Volume meldete freien Speicher, es konnte jedoch kein Byte "
        L"davon überschrieben werden; der Endzustand gilt nicht als "
        L"erfolgreich bereinigt.";
    return result;
  }

  result.success = !result.cancelled;
  result.bytes_written = total_written;
  result.message =
      L"Freier Speicherplatz (" + format_size(total_written) +
      L") auf " + std::wstring{volume_root} + L" wurde sicher bereinigt.";
  return result;
  } catch (const std::bad_alloc &) {
    result.success = false;
    result.bytes_written = total_written;
    if (result.win32_error == ERROR_SUCCESS)
      result.win32_error = ERROR_NOT_ENOUGH_MEMORY;
    return result;
  } catch (...) {
    result.success = false;
    result.bytes_written = total_written;
    if (result.win32_error == ERROR_SUCCESS)
      result.win32_error = ERROR_UNHANDLED_EXCEPTION;
    return result;
  }
}

} // namespace oblivion
