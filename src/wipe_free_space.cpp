#include "oblivion/wipe_free_space.hpp"
#include "oblivion/random.hpp"
#include "oblivion/secure_memory.hpp"
#include "oblivion/win_handle.hpp"

#include <Windows.h>
#include <algorithm>
#include <cstdint>
#include <iomanip>
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

void clean_wipe_directory(const std::filesystem::path &dir,
                          const std::vector<std::filesystem::path> &files) {
  for (const auto &file : files) {
    SetFileAttributesW(file.c_str(), FILE_ATTRIBUTE_NORMAL);
    DeleteFileW(file.c_str());
  }
  std::error_code ec;
  std::filesystem::remove_all(dir, ec);
}

} // namespace

erase_result wipe_volume_free_space(
    const std::filesystem::path &target_volume_or_path,
    const erase_options &options,
    const progress_callback &callback) {
  erase_result result{};

  wchar_t volume_root[MAX_PATH + 1]{};
  if (!GetVolumePathNameW(target_volume_or_path.c_str(), volume_root,
                          MAX_PATH)) {
    result.win32_error = GetLastError();
    result.message = L"Volume-Pfad konnte nicht ermittelt werden: " +
                     target_volume_or_path.wstring();
    return result;
  }

  ULARGE_INTEGER free_bytes_caller{}, total_bytes{}, total_free_bytes{};
  if (!GetDiskFreeSpaceExW(volume_root, &free_bytes_caller, &total_bytes,
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

  // Erstelle temporäres Arbeitsverzeichnis auf dem Zielvolume
  const std::wstring temp_dirname =
      L".oblivion_wipetmp_" + std::to_wstring(GetCurrentProcessId()) + L"_" +
      std::to_wstring(GetTickCount64());
  const std::filesystem::path wipe_dir =
      std::filesystem::path{volume_root} / temp_dirname;

  std::error_code ec;
  std::filesystem::create_directories(wipe_dir, ec);
  if (ec) {
    result.win32_error = static_cast<std::uint32_t>(ec.value());
    result.message = L"Temporäres Bereinigungsverzeichnis konnte nicht erstellt "
                     L"werden: " +
                     wipe_dir.wstring();
    return result;
  }
  SetFileAttributesW(wipe_dir.c_str(),
                     FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);

  std::vector<std::filesystem::path> created_files;

  // RAII Cleanup Guard: Garantiert, dass temporäre Dateien bei Fehler oder Abbruch gelöscht werden
  struct cleanup_guard {
    const std::filesystem::path &dir;
    std::vector<std::filesystem::path> &files;
    bool armed{true};
    ~cleanup_guard() {
      if (armed) {
        clean_wipe_directory(dir, files);
      }
    }
  } guard{wipe_dir, created_files, true};

  // Puffer für Schreibvorgänge
  constexpr std::size_t BUFFER_SIZE = 4u * 1024u * 1024u; // 4 MiB
  secure_buffer buf{BUFFER_SIZE};
  if (!buf.valid()) {
    result.win32_error = ERROR_OUTOFMEMORY;
    result.message = L"Arbeitsspeicher für Bereinigungspuffer konnte nicht "
                     L"reserviert werden.";
    return result;
  }

  // Füllmuster vorbereiten: Je nach Modus Random oder Zero
  const bool use_random = (options.mode != erase_mode::nist_800_88);
  if (use_random) {
    if (!try_fill_secure_random(buf.bytes())) {
      result.win32_error = ERROR_GEN_FAILURE;
      result.message = L"CSPRNG-Fehler beim Initialisieren des "
                       L"Freispeicher-Bereinigungspuffers.";
      return result;
    }
  } else {
    buf.clear();
  }

  std::uint64_t total_written = 0;
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
        chunk_path.c_str(), GENERIC_WRITE | GENERIC_READ, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_TEMPORARY,
        nullptr)};

    if (!file_handle) {
      const DWORD err = GetLastError();
      if (err == ERROR_DISK_FULL) {
        disk_full = true;
        break;
      }
      result.win32_error = err;
      result.message =
          L"Temporäre Datei konnte nicht angelegt werden: " + chunk_path.wstring();
      return result;
    }

    created_files.push_back(chunk_path);

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
          return result;
        }
      }

      DWORD written = 0;
      if (!WriteFile(file_handle.get(), buf.data(), to_write, &written, nullptr) ||
          written != to_write) {
        const DWORD write_err = GetLastError();
        if (write_err == ERROR_DISK_FULL) {
          disk_full = true;
          total_written += written;
          break;
        }
        result.win32_error = write_err;
        result.message = L"Schreibfehler während Freispeicher-Bereinigung.";
        return result;
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
          return result;
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
      result.message =
          L"FlushFileBuffers während Freispeicher-Bereinigung fehlgeschlagen.";
      return result;
    }
  }

  // Alle temporären Chunks schließen, zurücksetzen und bereinigen
  guard.armed = false; // Wir führen das kontrollierte Cleanup manuell durch
  clean_wipe_directory(wipe_dir, created_files);

  result.success = !result.cancelled;
  result.bytes_written = total_written;
  result.message =
      L"Freier Speicherplatz (" + format_size(total_written) +
      L") auf " + std::wstring{volume_root} + L" wurde sicher bereinigt.";
  return result;
}

} // namespace oblivion
