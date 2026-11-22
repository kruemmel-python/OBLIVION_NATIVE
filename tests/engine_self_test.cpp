#include "oblivion/analyzer.hpp"
#include "oblivion/app_logic.hpp"
#include "oblivion/audit.hpp"
#include "oblivion/audit_integrity.hpp"
#include "oblivion/erase_engine.hpp"
#include "oblivion/path_validator.hpp"
#include "oblivion/certificate.hpp"
#include "oblivion/runtime_guard.hpp"
#include "oblivion/secure_memory.hpp"
#include "oblivion/test_hooks.hpp"
#include "oblivion/win_handle.hpp"
#include "oblivion/wipe_free_space.hpp"

#include <Windows.h>
#include <ShlObj.h>

#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
class test_directory final {
public:
  test_directory() {
    path_ = std::filesystem::temp_directory_path() /
            (L"oblivion-engine-self-test-" +
             std::to_wstring(GetCurrentProcessId()) + L"-" +
             std::to_wstring(GetTickCount64()));
    std::filesystem::create_directories(path_);
  }
  ~test_directory() {
    std::error_code ignored;
    std::filesystem::remove_all(path_, ignored);
  }
  const std::filesystem::path &path() const { return path_; }

private:
  std::filesystem::path path_;
};

class environment_variable_guard final {
public:
  environment_variable_guard(const wchar_t *name, const wchar_t *replacement)
      : name_(name) {
    const DWORD size = GetEnvironmentVariableW(name_.c_str(), nullptr, 0);
    existed_ = size != 0;
    if (existed_) {
      previous_.resize(size);
      const DWORD written = GetEnvironmentVariableW(
          name_.c_str(), previous_.data(), static_cast<DWORD>(previous_.size()));
      if (written == 0 || static_cast<std::size_t>(written) >= previous_.size())
        return;
      previous_.resize(written);
    }
    changed_ =
        SetEnvironmentVariableW(name_.c_str(), replacement) != FALSE;
  }
  ~environment_variable_guard() {
    if (changed_)
      (void)SetEnvironmentVariableW(
          name_.c_str(), existed_ ? previous_.c_str() : nullptr);
  }
  [[nodiscard]] bool changed() const noexcept { return changed_; }

private:
  std::wstring name_;
  std::wstring previous_;
  bool existed_{false};
  bool changed_{false};
};

bool require(const bool condition, const char *message) {
  if (!condition)
    std::cerr << "FEHLER: " << message << '\n';
  return condition;
}

class hook_guard final {
public:
  hook_guard() { oblivion::testing::reset_hooks(); }
  ~hook_guard() { oblivion::testing::reset_hooks(); }
  hook_guard(const hook_guard &) = delete;
  hook_guard &operator=(const hook_guard &) = delete;
};

std::filesystem::path audit_test_directory;
std::filesystem::path test_audit_directory() { return audit_test_directory; }

bool fail_random(std::span<std::byte>) noexcept { return false; }

BOOL WINAPI fail_flush(HANDLE) {
  SetLastError(ERROR_WRITE_FAULT);
  return FALSE;
}

int recycle_scan_calls{};
int recycle_query_calls{};
int recycle_erase_calls{};
bool recycle_global_query_requested{};

HRESULT WINAPI query_recycle_empty(LPCWSTR root, LPSHQUERYRBINFO info) {
  ++recycle_query_calls;
  recycle_global_query_requested |= root == nullptr;
  info->i64NumItems = 0;
  info->i64Size = 0;
  return S_OK;
}

HRESULT WINAPI fail_recycle_query(LPCWSTR root, LPSHQUERYRBINFO) {
  ++recycle_query_calls;
  recycle_global_query_requested |= root == nullptr;
  return E_FAIL;
}

HRESULT WINAPI query_recycle_with_items(LPCWSTR root, LPSHQUERYRBINFO info) {
  ++recycle_query_calls;
  recycle_global_query_requested |= root == nullptr;
  info->i64NumItems = 1;
  info->i64Size = 1;
  return S_OK;
}

oblivion::recycle_bin_scan_result incomplete_recycle_scan() {
  return {{}, false, ERROR_ACCESS_DENIED};
}

oblivion::recycle_bin_scan_result empty_recycle_scan() {
  oblivion::recycle_bin_scan_result result;
  result.scanned_roots.emplace_back(L"C:\\");
  result.scanned_volumes.emplace_back(L"\\\\?\\Volume{OBLIVION-TEST}\\");
  return result;
}

oblivion::recycle_bin_scan_result one_recycle_item_scan() {
  auto result = empty_recycle_scan();
  result.items.push_back(std::filesystem::temp_directory_path());
  return result;
}

oblivion::recycle_bin_scan_result two_recycle_items_scan() {
  auto result = empty_recycle_scan();
  result.items.push_back(std::filesystem::temp_directory_path());
  result.items.push_back(std::filesystem::temp_directory_path());
  return result;
}

oblivion::recycle_bin_scan_result changed_recycle_scan() {
  ++recycle_scan_calls;
  return recycle_scan_calls == 1 ? empty_recycle_scan()
                                 : one_recycle_item_scan();
}

oblivion::erase_result cancelled_recycle_erase(const std::filesystem::path &,
                                               const oblivion::erase_options &,
                                               const oblivion::progress_callback &) {
  oblivion::erase_result result;
  result.cancelled = true;
  result.win32_error = ERROR_CANCELLED;
  result.files_deleted = 2;
  result.directories_deleted = 3;
  result.bytes_written = 4;
  result.alternate_streams_overwritten = 5;
  result.reparse_points_removed = 6;
  result.hardlinks_blocked = 7;
  result.warnings.emplace_back(L"Testwarnung");
  result.lock_owners.push_back({42, L"Testprozess", L"Testdienst"});
  result.message = L"Testabbruch";
  return result;
}

oblivion::erase_result throwing_second_recycle_erase(
    const std::filesystem::path &, const oblivion::erase_options &,
    const oblivion::progress_callback &) {
  if (++recycle_erase_calls == 2)
    throw std::runtime_error("simulated recycle erase failure");
  oblivion::erase_result result;
  result.success = true;
  result.files_deleted = 1;
  result.bytes_written = 32;
  return result;
}

bool inaccessible_recycle_item(const std::filesystem::path &, std::error_code &ec) {
  ec = std::error_code{ERROR_ACCESS_DENIED, std::system_category()};
  return false;
}

bool write_bytes(const std::filesystem::path &path, const std::size_t size,
                 const unsigned char value) {
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  const std::vector<unsigned char> bytes(size, value);
  output.write(reinterpret_cast<const char *>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
  return output.good();
}

std::vector<unsigned char> read_bytes(const std::filesystem::path &path) {
  std::ifstream input(path, std::ios::binary);
  return {std::istreambuf_iterator<char>(input),
          std::istreambuf_iterator<char>()};
}

bool test_hardlinks(const std::filesystem::path &root) {
  oblivion::analyzer analyzer;
  oblivion::erase_engine engine;
  oblivion::erase_options options;
  options.mode = oblivion::erase_mode::standard;
  options.verify = true;
  options.rename_before_delete = false;

  const auto first = root / L"hardlink-block-a.bin";
  const auto second = root / L"hardlink-block-b.bin";
  if (!require(write_bytes(first, 8192, 0x5a),
               "Hardlink-Testdatei konnte nicht geschrieben werden."))
    return false;
  if (!require(CreateHardLinkW(second.c_str(), first.c_str(), nullptr) != FALSE,
               "Hardlink konnte nicht erzeugt werden."))
    return false;
  const DWORD initial_attributes = GetFileAttributesW(first.c_str());
  if (!require(initial_attributes != INVALID_FILE_ATTRIBUTES &&
                   SetFileAttributesW(first.c_str(),
                                      initial_attributes |
                                          FILE_ATTRIBUTE_READONLY) != FALSE,
               "Hardlink konnte nicht auf Read-only gesetzt werden."))
    return false;
  if (!require(analyzer.analyze(first).hardlinked_files == 1,
               "Analyzer erkennt den Hardlink nicht."))
    return false;

  options.hardlinks = oblivion::hardlink_policy::block;
  const auto blocked = engine.erase(first, options);
  if (!require(!blocked.success && blocked.hardlinks_blocked == 1,
               "Block-Strategie blockiert Hardlink nicht."))
    return false;
  if (!require(std::filesystem::exists(first) &&
                   std::filesystem::exists(second),
               "Block-Strategie hat einen Hardlink entfernt."))
    return false;
  if (!require(read_bytes(second) == std::vector<unsigned char>(8192, 0x5a),
               "Block-Strategie hat gemeinsamen Inhalt verändert."))
    return false;
  if (!require((GetFileAttributesW(second.c_str()) & FILE_ATTRIBUTE_READONLY) !=
                   0,
               "Block-Strategie hat das Read-only-Attribut verändert."))
    return false;

  options.hardlinks = oblivion::hardlink_policy::delete_link_only;
  const auto link_only = engine.erase(first, options);
  if (!require(link_only.success && link_only.files_deleted == 1,
               "Delete-link-only ist fehlgeschlagen."))
    return false;
  if (!require(!std::filesystem::exists(first) &&
                   std::filesystem::exists(second),
               "Delete-link-only hat falsche Linknamen erhalten."))
    return false;
  if (!require(read_bytes(second) == std::vector<unsigned char>(8192, 0x5a),
               "Delete-link-only hat gemeinsamen Inhalt verändert."))
    return false;
  if (!require((GetFileAttributesW(second.c_str()) & FILE_ATTRIBUTE_READONLY) !=
                   0,
               "Delete-link-only hat das Read-only-Attribut des verbleibenden "
               "Links verändert."))
    return false;
  SetFileAttributesW(second.c_str(), GetFileAttributesW(second.c_str()) &
                                         ~FILE_ATTRIBUTE_READONLY);
  std::filesystem::remove(second);

  const auto shared_first = root / L"hardlink-shared-a.bin";
  const auto shared_second = root / L"hardlink-shared-b.bin";
  if (!require(write_bytes(shared_first, 4096, 0xa5),
               "Shared-Hardlink-Testdatei konnte nicht geschrieben werden."))
    return false;
  if (!require(CreateHardLinkW(shared_second.c_str(), shared_first.c_str(),
                               nullptr) != FALSE,
               "Shared-Hardlink konnte nicht erzeugt werden."))
    return false;
  options.hardlinks = oblivion::hardlink_policy::overwrite_shared_content;
  const auto shared = engine.erase(shared_first, options);
  if (!require(shared.success && !std::filesystem::exists(shared_first) &&
                   std::filesystem::exists(shared_second),
               "Shared-Overwrite hat falsches Ergebnis."))
    return false;
  const auto shared_bytes = read_bytes(shared_second);
  if (!require(shared_bytes.size() == 4096 &&
                   std::ranges::all_of(
                       shared_bytes,
                       [](const unsigned char value) { return value == 0; }),
               "Shared-Overwrite wurde am verbleibenden Hardlink nicht "
               "verifiziert."))
    return false;
  std::filesystem::remove(shared_second);
  return true;
}

bool test_ads(const std::filesystem::path &root) {
  oblivion::analyzer analyzer;
  oblivion::erase_engine engine;
  oblivion::erase_options options;
  options.mode = oblivion::erase_mode::standard;
  options.verify = true;
  options.rename_before_delete = false;
  options.erase_alternate_streams = true;

  const auto file = root / L"ads.bin";
  const auto stream = std::filesystem::path{file.wstring() + L":secret"};
  if (!require(write_bytes(file, 2048, 0x33),
               "ADS-Hauptdatenstrom konnte nicht geschrieben werden."))
    return false;
  if (!require(write_bytes(stream, 777, 0x77),
               "Alternativer Datenstrom konnte nicht geschrieben werden."))
    return false;
  const auto analysis = analyzer.analyze(file);
  if (!require(analysis.alternate_streams == 1 &&
                   analysis.alternate_stream_bytes == 777,
               "Analyzer erfasst ADS nicht korrekt."))
    return false;
  const auto result = engine.erase(file, options);
  if (!require(result.success && result.alternate_streams_overwritten == 1,
               "ADS wurde nicht überschrieben und gelöscht."))
    return false;
  return require(!std::filesystem::exists(file),
                 "ADS-Testdatei existiert nach erfolgreichem Löschen noch.");
}

bool test_reparse_point(const std::filesystem::path &root) {
  oblivion::analyzer analyzer;
  oblivion::erase_engine engine;
  oblivion::erase_options options;
  options.rename_before_delete = false;

  const auto target = root / L"reparse-target";
  const auto marker = target / L"marker.txt";
  const auto link = root / L"reparse-link";
  std::filesystem::create_directories(target);
  if (!require(write_bytes(marker, 128, 0x42),
               "Reparse-Zieldatei konnte nicht geschrieben werden."))
    return false;
  if (!CreateSymbolicLinkW(link.c_str(), target.c_str(),
                           SYMBOLIC_LINK_FLAG_DIRECTORY |
                               SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE)) {
    const DWORD error = GetLastError();
    std::cerr << "FEHLER: Verzeichnis-Symlink konnte nicht erzeugt werden, "
                 "Win32Error="
              << error << '\n';
    return false;
  }
  const auto analysis = analyzer.analyze(link);
  if (!require(analysis.reparse_points == 1 && analysis.directories == 1,
               "Analyzer erkennt Reparse Point nicht."))
    return false;
  const auto result = engine.erase(link, options);
  if (!require(result.success && result.reparse_points_removed == 1,
               "Reparse Point wurde nicht separat entfernt."))
    return false;
  if (!require(!std::filesystem::exists(link),
               "Reparse Point existiert nach dem Löschen noch."))
    return false;
  return require(
      std::filesystem::exists(marker),
      "Engine ist dem Reparse Point gefolgt und hat das Ziel verändert.");
}

bool test_reparse_ancestor_blocked(const std::filesystem::path &root) {
  oblivion::erase_engine engine;
  oblivion::erase_options options;
  options.rename_before_delete = false;
  const auto target = root / L"ancestor-target";
  const auto victim = target / L"victim.bin";
  const auto link = root / L"ancestor-link";
  std::filesystem::create_directories(target);
  if (!require(write_bytes(victim, 128, 0x5a),
               "Reparse-Vorfahren-Testdatei konnte nicht geschrieben werden."))
    return false;
  if (!CreateSymbolicLinkW(link.c_str(), target.c_str(),
                           SYMBOLIC_LINK_FLAG_DIRECTORY |
                               SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE))
    return require(false,
                   "Reparse-Vorfahre konnte nicht für den Test erzeugt werden.");
  const auto result = engine.erase(link / L"victim.bin", options);
  return require(!result.success && std::filesystem::exists(victim),
                 "Engine folgte einem Reparse-Vorfahren bis zum Löschziel.");
}

bool test_locked_file(const std::filesystem::path &root) {
  oblivion::erase_engine engine;
  oblivion::erase_options options;
  options.rename_before_delete = false;
  const auto file = root / L"locked.bin";
  if (!require(write_bytes(file, 1024, 0x19),
               "Locked-File-Testdatei konnte nicht geschrieben werden."))
    return false;
  HANDLE lock =
      CreateFileW(file.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (!require(lock != INVALID_HANDLE_VALUE,
               "Exklusiver Dateilock konnte nicht erzeugt werden."))
    return false;
  const auto blocked = engine.erase(file, options);
  const bool correctly_blocked =
      !blocked.success && std::filesystem::exists(file) &&
      (blocked.win32_error == ERROR_SHARING_VIOLATION ||
       blocked.win32_error == ERROR_LOCK_VIOLATION ||
       blocked.win32_error == ERROR_ACCESS_DENIED);
  CloseHandle(lock);
  if (!require(correctly_blocked,
               "Gesperrte Datei wurde nicht sicher blockiert."))
    return false;
  if (!require(!blocked.lock_owners.empty(),
               "Lock-Diagnose meldet keinen Besitzer der gesperrten Datei."))
    return false;
  const auto retried = engine.erase(file, options);
  return require(retried.success && !std::filesystem::exists(file),
                 "Datei konnte nach Freigabe des Locks nicht gelöscht werden.");
}


bool test_analysis_volume_grouping() {
  oblivion::prepared_operation prepared;
  prepared.valid = true;
  prepared.targets = {L"F:\\alpha.txt", L"F:\\beta.txt",
                      L"G:\\gamma.txt"};
  prepared.analysis.files = 3;

  oblivion::storage_info f;
  f.volume_root = L"F:\\";
  f.volume_guid = L"\\\\?\\Volume{OBLIVION-TEST-F}\\";
  f.filesystem = L"NTFS";
  f.device_model = L"Oblivion Test Device F";
  f.bus_type = L"USB";
  f.kind = oblivion::media_kind::solid_state;
  f.trim_enabled = true;

  oblivion::storage_info g = f;
  g.volume_root = L"G:\\";
  g.volume_guid = L"\\\\?\\Volume{OBLIVION-TEST-G}\\";
  g.device_model = L"Oblivion Test Device G";
  prepared.storage = {f, f, g};

  const auto report = oblivion::format_prepared_analysis(prepared);
  const auto first_f = report.find(L"Gerät: Oblivion Test Device F");
  const bool f_once =
      first_f != std::wstring::npos &&
      report.find(L"Gerät: Oblivion Test Device F", first_f + 1) ==
          std::wstring::npos;

  if (!require(report.find(L"Datenträger: 2") != std::wstring::npos &&
                   report.find(L"F:\\ · 2 Ziele") != std::wstring::npos &&
                   report.find(L"G:\\") != std::wstring::npos && f_once,
               "Analyse gruppiert identische Volumes nicht korrekt."))
    return false;
  oblivion::file_analysis incomplete;
  incomplete.inaccessible_entries = 1;
  if (!require(oblivion::requires_typed_confirmation(incomplete),
               "Unvollständige Voranalyse erzwingt keine starke "
               "Löschbestätigung."))
    return false;
  oblivion::erase_options dangerous;
  dangerous.hardlinks = oblivion::hardlink_policy::overwrite_shared_content;
  if (!require(oblivion::requires_hardlink_confirmation(dangerous),
               "Shared-Hardlink-Overwrite erfordert ohne Analysefund keine "
               "besondere Bestätigung."))
    return false;
  dangerous.mode = oblivion::erase_mode::gutmann;
  dangerous.verify = false;
  dangerous.erase_alternate_streams = false;
  dangerous.rename_before_delete = false;
  dangerous.rename_rounds = 17;
  const auto elevation = oblivion::build_elevation_arguments(
      dangerous, {L"C:\\retry-only.bin"});
  const auto has = [&elevation](const std::wstring_view option) {
    return std::ranges::find(elevation, option) != elevation.end();
  };
  return require(has(L"--gutmann") && has(L"--no-verify") &&
                     has(L"--no-ads") && has(L"--no-rename") &&
                     has(L"--rename-rounds") && has(L"17") &&
                     has(L"--hardlink-overwrite-shared") &&
                     has(L"C:\\retry-only.bin"),
                 "UAC-Retry serialisiert Löschoptionen oder Restziele nicht "
                 "vollständig.");
}

bool test_analysis_resource_limit(const std::filesystem::path &root) {
  hook_guard guard;
  const auto directory = root / L"analysis-limit";
  std::filesystem::create_directory(directory);
  if (!write_bytes(directory / L"one.bin", 1, 1) ||
      !write_bytes(directory / L"two.bin", 1, 2))
    return require(false, "Analyse-Limit-Test konnte nicht vorbereitet werden.");
  oblivion::testing::hooks().analysis_max_entries = 2;
  const auto analysis = oblivion::analyzer{}.analyze(directory);
  return require(analysis.inaccessible_entries != 0 &&
                     oblivion::requires_typed_confirmation(analysis),
                 "Übergroße Voranalyse wird nicht begrenzt und als "
                 "unvollständig markiert.");
}

bool test_secure_memory() {
  oblivion::secure_buffer buffer(4096);
  if (!require(buffer.valid(),
               "Sicherer Arbeitspuffer konnte nicht reserviert werden."))
    return false;
  std::fill_n(buffer.data(), buffer.size(), std::byte{0xa5});
  buffer.clear();
  return require(std::ranges::all_of(buffer.bytes(),
                                     [](const std::byte value) {
                                       return value == std::byte{0};
                                     }),
                 "Sicherer Arbeitspuffer wurde nicht vollständig bereinigt.");
}

bool test_engine_boundary_guard(const std::filesystem::path &root) {
  std::vector<wchar_t> windows_directory(32768);
  const UINT length = GetWindowsDirectoryW(
      windows_directory.data(), static_cast<UINT>(windows_directory.size()));
  if (!require(length > 0 && length < windows_directory.size(),
               "Windows-Verzeichnis konnte für den Schutztest nicht bestimmt "
               "werden."))
    return false;
  const std::filesystem::path protected_target{windows_directory.data()};
  environment_variable_guard spoofed_system_root(
      L"SystemRoot", L"Z:\\attacker-controlled-system-root");
  if (!require(spoofed_system_root.changed(),
               "SystemRoot konnte für den Schutzpfadtest nicht manipuliert "
               "werden."))
    return false;
  oblivion::erase_engine engine;
  const auto result = engine.erase(protected_target, {});
  if (!require(!result.success && result.win32_error == ERROR_ACCESS_DENIED &&
                   std::filesystem::exists(protected_target),
               "Direkter Engine-Aufruf hat einen geschützten Systempfad bei "
               "manipulierter Umgebung nicht blockiert."))
    return false;
  PWSTR program_files = nullptr;
  if (FAILED(SHGetKnownFolderPath(FOLDERID_ProgramFiles,
                                  KF_FLAG_DONT_VERIFY, nullptr,
                                  &program_files)) ||
      program_files == nullptr)
    return require(false, "Program Files konnte nicht bestimmt werden.");
  std::vector<wchar_t> short_path(32768);
  const DWORD short_length = GetShortPathNameW(
      program_files, short_path.data(), static_cast<DWORD>(short_path.size()));
  CoTaskMemFree(program_files);
  if (short_length != 0 &&
      static_cast<std::size_t>(short_length) < short_path.size()) {
    const std::filesystem::path alias{short_path.data()};
    const auto alias_result = engine.erase(alias, {});
    if (!require(!alias_result.success &&
                     alias_result.win32_error == ERROR_ACCESS_DENIED &&
                     std::filesystem::exists(alias),
                 "Kanonischer Schutzpfadvergleich blockiert einen Windows-"
                 "Kurznamenalias nicht."))
      return false;
  }
  PWSTR public_profile = nullptr;
  if (FAILED(SHGetKnownFolderPath(FOLDERID_Public, KF_FLAG_DONT_VERIFY, nullptr,
                                  &public_profile)) ||
      public_profile == nullptr)
    return require(false,
                   "Öffentliches Benutzerprofil konnte nicht bestimmt werden.");
  const std::filesystem::path public_path{public_profile};
  CoTaskMemFree(public_profile);
  const auto public_validation =
      oblivion::path_validator{}.validate(public_path);
  if (!require(!public_validation.allowed,
               "Direkte Benutzerprofilwurzel außerhalb der aktuellen "
                "Profilprüfung wurde nicht blockiert."))
    return false;
  PWSTR public_documents = nullptr;
  if (FAILED(SHGetKnownFolderPath(FOLDERID_PublicDocuments,
                                  KF_FLAG_DONT_VERIFY, nullptr,
                                  &public_documents)) ||
      public_documents == nullptr)
    return require(false,
                   "Öffentliche Dokumente konnten nicht bestimmt werden.");
  const std::filesystem::path public_documents_path{public_documents};
  CoTaskMemFree(public_documents);
  const auto public_documents_validation =
      oblivion::path_validator{}.validate(public_documents_path);
  if (!require(!public_documents_validation.allowed,
               "Unterpfad eines fremden/öffentlichen Profilbaums wurde nicht "
               "blockiert."))
    return false;

  const auto option_target = root / L"invalid-options.bin";
  if (!require(write_bytes(option_target, 1024, 0x5a),
               "Testdatei für Engine-Optionsgrenze konnte nicht erstellt "
               "werden."))
    return false;
  oblivion::erase_options invalid;
  invalid.hardlinks = static_cast<oblivion::hardlink_policy>(999u);
  const auto invalid_policy = engine.erase(option_target, invalid);
  if (!require(!invalid_policy.success &&
                   invalid_policy.win32_error == ERROR_INVALID_PARAMETER &&
                   std::filesystem::exists(option_target),
               "Ungültige Hardlink-Policy erreicht den Löschpfad."))
    return false;
  invalid = {};
  invalid.rename_rounds = 33u;
  const auto invalid_rounds = engine.erase(option_target, invalid);
  if (!require(!invalid_rounds.success &&
                   invalid_rounds.win32_error == ERROR_INVALID_PARAMETER &&
                   std::filesystem::exists(option_target),
               "Unbeschränkte Rename-Runden erreichen den Löschpfad."))
    return false;
  invalid = {};
  invalid.buffer_size = 0u;
  const auto invalid_buffer = engine.erase(option_target, invalid);
  return require(!invalid_buffer.success &&
                     invalid_buffer.win32_error == ERROR_INVALID_PARAMETER &&
                     std::filesystem::exists(option_target),
                  "Ungültige Puffergröße erreicht den Löschpfad.");
}

bool test_callback_exception_preserves_partial_result(
    const std::filesystem::path &root) {
  const auto directory = root / L"callback-exception";
  std::filesystem::create_directory(directory);
  if (!write_bytes(directory / L"first.bin", 1024, 0x31) ||
      !write_bytes(directory / L"second.bin", 1024, 0x32))
    return require(false, "Callback-Ausnahmetest konnte nicht vorbereitet werden.");

  oblivion::erase_options options;
  options.mode = oblivion::erase_mode::fast;
  options.verify = false;
  options.rename_before_delete = false;
  unsigned callbacks = 0;
  const auto result = oblivion::erase_engine{}.erase(
      directory, options, [&](const oblivion::progress_info &) {
        if (++callbacks == 2)
          throw std::runtime_error("simulated callback failure");
        return true;
      });
  std::error_code error;
  const auto remaining = static_cast<std::size_t>(
      std::distance(std::filesystem::directory_iterator(directory, error),
                    std::filesystem::directory_iterator{}));
  return require(!error && !result.success && result.cancelled &&
                     result.files_deleted == 1 && remaining == 1,
                 "Callback-Ausnahme verliert bereits ausgeführte Teilergebnisse "
                 "oder löscht nach dem Fehler weiter.");
}

bool test_cancellation_exception_fails_closed(
    const std::filesystem::path &root) {
  const auto file = root / L"cancellation-exception.bin";
  if (!write_bytes(file, 1024, 0x41))
    return require(false,
                   "Abbruch-Ausnahmetest konnte nicht vorbereitet werden.");
  oblivion::prepared_operation prepared;
  prepared.valid = true;
  prepared.targets.push_back(file);
  const auto result = oblivion::execute_prepared_operation(
      prepared, {}, {}, []() -> bool {
        throw std::runtime_error("simulated cancellation failure");
      });
  return require(result.cancelled && result.exit_code == 130 &&
                     std::filesystem::exists(file),
                 "Ausnahme im Abbruch-Callback wurde nicht fail-closed als "
                 "Abbruch behandelt.");
}

bool test_runtime_hardening() {
  const auto status = oblivion::harden_current_process();
  return require(
      status.complete(),
      "Native Prozesshärtung konnte nicht vollständig aktiviert werden.");
}

bool test_wipe_failure_paths(const std::filesystem::path &root) {
  oblivion::erase_options options;
  {
    auto invalid = options;
    invalid.mode = static_cast<oblivion::erase_mode>(999);
    const auto result = oblivion::wipe_volume_free_space(root, invalid, {});
    if (!require(!result.success &&
                     result.win32_error == ERROR_INVALID_PARAMETER,
                 "Ungültiger Freispeicher-Modus wird nicht vor jeder "
                 "Volume-Operation abgewiesen."))
      return false;
  }
  options.mode = oblivion::erase_mode::standard;
  const auto no_wipe_artifacts = [&root] {
    std::error_code error;
    std::filesystem::directory_iterator it(root, error), end;
    if (error)
      return false;
    while (it != end) {
      if (it->path().filename().wstring().starts_with(L".oblivion_wipetmp_"))
        return false;
      it.increment(error);
      if (error)
        return false;
    }
    return true;
  };
  {
    hook_guard guard;
    oblivion::testing::hooks().random = fail_random;
    const auto result = oblivion::wipe_volume_free_space(root, options, {});
    if (!require(!result.success && result.win32_error == ERROR_GEN_FAILURE &&
                     no_wipe_artifacts(),
                  "CSPRNG-Fehler beendet Freispeicher-Bereinigung nicht fail-closed."))
      return false;
  }
  {
    hook_guard guard;
    options.mode = oblivion::erase_mode::nist_800_88;
    oblivion::testing::hooks().wipe_max_chunk_bytes = 4096;
    oblivion::testing::hooks().flush = fail_flush;
    const auto result = oblivion::wipe_volume_free_space(root, options, {});
    if (!require(!result.success && result.win32_error == ERROR_WRITE_FAULT &&
                     no_wipe_artifacts(),
                  "Flush-Fehler beendet Freispeicher-Bereinigung nicht fail-closed."))
      return false;
  }
  {
    hook_guard guard;
    options.mode = oblivion::erase_mode::nist_800_88;
    oblivion::testing::hooks().wipe_max_chunk_bytes = 4096;
    const auto result = oblivion::wipe_volume_free_space(
        root, options, [](const oblivion::progress_info &) -> bool {
          throw std::runtime_error("simulated wipe callback failure");
        });
    if (!require(!result.success &&
                     result.win32_error == ERROR_UNHANDLED_EXCEPTION &&
                     result.bytes_written == 4096 && no_wipe_artifacts(),
                 "Callback-Ausnahme verliert Freispeicher-Teilergebnisse oder "
                 "hinterlässt Bereinigungsartefakte."))
      return false;
  }
  return true;
}

bool test_recycle_bin_failure_paths() {
  oblivion::erase_options options;
  {
    hook_guard guard;
    recycle_scan_calls = 0;
    auto invalid = options;
    invalid.hardlinks = static_cast<oblivion::hardlink_policy>(999);
    oblivion::testing::hooks().recycle_scan = changed_recycle_scan;
    const auto result = oblivion::secure_empty_recycle_bin(invalid, {});
    if (!require(!result.success &&
                     result.win32_error == ERROR_INVALID_PARAMETER &&
                     recycle_scan_calls == 0,
                 "Ungültige Papierkorboptionen werden nicht vor der ersten "
                 "Aufzählung abgewiesen."))
      return false;
  }
  {
    hook_guard guard;
    recycle_query_calls = 0;
    oblivion::testing::hooks().recycle_scan = incomplete_recycle_scan;
    oblivion::testing::hooks().recycle_query = query_recycle_empty;
    const auto result = oblivion::secure_empty_recycle_bin(options, {});
    if (!require(!result.success && result.win32_error == ERROR_ACCESS_DENIED &&
                     recycle_query_calls == 0,
                 "Unvollständiger Papierkorb-Scan erreicht die Endzustandsabfrage."))
      return false;
  }
  {
    hook_guard guard;
    recycle_query_calls = 0;
    recycle_scan_calls = 0;
    oblivion::testing::hooks().recycle_scan = changed_recycle_scan;
    oblivion::testing::hooks().recycle_query = query_recycle_empty;
    const auto result = oblivion::secure_empty_recycle_bin(options, {});
    if (!require(!result.success && result.win32_error == ERROR_DIR_NOT_EMPTY &&
                     recycle_query_calls == 0,
                 "Neu erschienene Papierkorbobjekte erreichen die "
                 "Endzustandsabfrage trotz abgebrochener Verarbeitung."))
      return false;
  }
  {
    hook_guard guard;
    recycle_query_calls = 0;
    oblivion::testing::hooks().recycle_scan = one_recycle_item_scan;
    oblivion::testing::hooks().recycle_exists = inaccessible_recycle_item;
    oblivion::testing::hooks().recycle_query = query_recycle_empty;
    const auto result = oblivion::secure_empty_recycle_bin(options, {});
    if (!require(!result.success && result.win32_error == ERROR_ACCESS_DENIED &&
                     recycle_query_calls == 0,
                 "Fehler beim Prüfen eines Papierkorbobjekts ist nicht fail-closed."))
      return false;
  }
  {
    hook_guard guard;
    recycle_query_calls = 0;
    recycle_global_query_requested = false;
    oblivion::testing::hooks().recycle_scan = empty_recycle_scan;
    oblivion::testing::hooks().recycle_query = fail_recycle_query;
    const auto result = oblivion::secure_empty_recycle_bin(options, {});
    if (!require(!result.success && result.win32_error == HRESULT_CODE(E_FAIL) &&
                     recycle_query_calls == 1 &&
                     !recycle_global_query_requested,
                 "Unverifizierter Papierkorb-Endzustand wird als Erfolg gemeldet."))
      return false;
  }
  {
    hook_guard guard;
    recycle_query_calls = 0;
    oblivion::testing::hooks().recycle_scan = empty_recycle_scan;
    oblivion::testing::hooks().recycle_query = query_recycle_with_items;
    const auto result = oblivion::secure_empty_recycle_bin(options, {});
    if (!require(!result.success && result.win32_error == ERROR_DIR_NOT_EMPTY,
                 "Verbleibende Papierkorbobjekte werden als Erfolg gemeldet."))
      return false;
  }
  {
    hook_guard guard;
    recycle_query_calls = 0;
    recycle_global_query_requested = false;
    oblivion::testing::hooks().recycle_scan = empty_recycle_scan;
    oblivion::testing::hooks().recycle_query = query_recycle_empty;
    const auto result = oblivion::secure_empty_recycle_bin(options, {});
    if (!require(result.success && recycle_query_calls == 1 &&
                     !recycle_global_query_requested,
                  "Verifizierter leerer Papierkorb wird nicht als Erfolg "
                  "gemeldet oder global statt volumengebunden abgefragt."))
      return false;
  }
  {
    hook_guard guard;
    recycle_query_calls = 0;
    oblivion::testing::hooks().recycle_scan = one_recycle_item_scan;
    oblivion::testing::hooks().recycle_erase = cancelled_recycle_erase;
    oblivion::testing::hooks().recycle_query = query_recycle_empty;
    const auto result = oblivion::secure_empty_recycle_bin(options, {});
    if (!require(!result.success && result.cancelled &&
                     result.win32_error == ERROR_CANCELLED &&
                     result.files_deleted == 2 &&
                     result.directories_deleted == 3 &&
                     result.bytes_written == 4 &&
                     result.alternate_streams_overwritten == 5 &&
                     result.reparse_points_removed == 6 &&
                     result.hardlinks_blocked == 7 &&
                     result.warnings.size() == 1 &&
                     result.lock_owners.size() == 1 &&
                     recycle_query_calls == 0,
                 "Abgebrochene Papierkorb-Operation erreicht die "
                 "Endzustandsabfrage oder verliert Teilergebnisse."))
      return false;
  }
  {
    hook_guard guard;
    recycle_erase_calls = 0;
    oblivion::testing::hooks().recycle_scan = two_recycle_items_scan;
    oblivion::testing::hooks().recycle_erase = throwing_second_recycle_erase;
    const auto result = oblivion::secure_empty_recycle_bin(options, {});
    if (!require(!result.success &&
                     result.win32_error == ERROR_UNHANDLED_EXCEPTION &&
                     result.files_deleted == 1 && result.bytes_written == 32,
                 "Papierkorb-Ausnahme verliert bereits ausgeführte "
                 "Teilergebnisse."))
      return false;
  }
  return true;
}

bool test_unique_handle() {
  const std::wstring name = L"Local\\OblivionHandleTest-" +
                            std::to_wstring(GetCurrentProcessId()) + L"-" +
                            std::to_wstring(GetTickCount64());
  {
    oblivion::unique_win_handle event{
        CreateEventW(nullptr, TRUE, FALSE, name.c_str())};
    if (!require(static_cast<bool>(event),
                 "RAII-Testhandle konnte nicht erzeugt werden."))
      return false;
  }
  oblivion::unique_win_handle reopened{
      OpenEventW(EVENT_MODIFY_STATE, FALSE, name.c_str())};
  return require(
      !reopened && GetLastError() == ERROR_FILE_NOT_FOUND,
      "RAII-Wrapper hat das Kernel-Handle nicht deterministisch geschlossen.");
}

bool test_private_audit(const std::filesystem::path &root) {
  hook_guard guard;
  audit_test_directory = root;
  oblivion::testing::hooks().audit_directory = test_audit_directory;
  oblivion::operation_audit audit;
  audit.operation_id = oblivion::create_operation_id();
  audit.target = root / L"streng-geheimer-dateiname.txt";
  audit.storage.volume_root = L"Z:\\geheimes-volume";
  audit.storage.volume_guid = L"geheime-volume-guid";
  audit.storage.device_model = L"geheimes-modell";
  audit.storage.device_serial = L"geheime-seriennummer";
  audit.result.success = true;
  audit.result.message = L"geheime-diagnosemeldung";
  const auto collision = root / L"exclusive-create-guard.log";
  {
    std::ofstream guard_file(collision, std::ios::binary | std::ios::trunc);
    guard_file << "guard";
  }
  if (!require(!oblivion::write_new_audit_file(collision, "replacement") &&
                   read_bytes(collision) ==
                       std::vector<unsigned char>{'g', 'u', 'a', 'r', 'd'},
               "Vorhandene Auditdatei wurde statt exklusiver Neuerstellung "
               "überschrieben."))
    return false;
  const auto file = oblivion::write_audit_record(audit);
  if (!require(!file.empty() && std::filesystem::exists(file),
               "Privater Auditdatensatz konnte nicht geschrieben werden."))
    return false;
  if (!require(oblivion::verify_audit_file(file),
               "HMAC-Auditdatensatz konnte nicht verifiziert werden."))
    return false;
  auto second_audit = audit;
  second_audit.operation_id = oblivion::create_operation_id();
  second_audit.result.message = L"zweiter-Auditdatensatz";
  const auto second_file = oblivion::write_audit_record(second_audit);
  if (!require(!second_file.empty() && std::filesystem::exists(second_file),
               "Zweiter Auditdatensatz konnte nicht geschrieben werden."))
    return false;
  const auto audit_directory = file.parent_path();
  if (!require(oblivion::verify_audit_chain(audit_directory),
                "Vollständige Audit-Kette konnte nicht verifiziert werden."))
    return false;
  const auto audit_files = [&audit_directory] {
    std::vector<std::wstring> names;
    for (const auto &entry : std::filesystem::directory_iterator(audit_directory))
      names.push_back(entry.path().filename().wstring());
    std::ranges::sort(names);
    return names;
  };
  const auto files_before_rng_failure = audit_files();
  auto failed_audit = audit;
  failed_audit.operation_id = oblivion::create_operation_id();
  oblivion::testing::hooks().random = fail_random;
  const auto failed_file = oblivion::write_audit_record(failed_audit);
  oblivion::testing::hooks().random = nullptr;
  if (!require(failed_file.empty() &&
                   audit_files() == files_before_rng_failure &&
                   oblivion::verify_audit_chain(audit_directory),
               "Audit-Versiegelungsfehler hinterlässt unversiegelte "
               "Datensätze, Hashes oder HMAC-Sidecars."))
    return false;
  const auto head_file = audit_directory / L"chain.head";
  const auto original_head = read_bytes(head_file);
  {
    std::ofstream append_head(head_file, std::ios::binary | std::ios::app);
    append_head << '\n';
  }
  if (!require(!oblivion::verify_audit_chain(audit_directory),
               "Zusätzliche Daten im Audit-Kettenkopf wurden akzeptiert."))
    return false;
  {
    std::ofstream restore_head(head_file,
                               std::ios::binary | std::ios::trunc);
    restore_head.write(
        reinterpret_cast<const char *>(original_head.data()),
        static_cast<std::streamsize>(original_head.size()));
  }
  {
    std::ofstream tamper_head(head_file,
                              std::ios::binary | std::ios::trunc);
    tamper_head << std::string(64, '0') << '\n';
  }
  if (!require(!oblivion::verify_audit_chain(audit_directory),
               "Manipulierter Audit-Kettenkopf wurde nicht erkannt."))
    return false;
  auto rejected_audit = audit;
  rejected_audit.operation_id = oblivion::create_operation_id();
  if (!require(oblivion::write_audit_record(rejected_audit).empty(),
               "Neuer Auditdatensatz wurde trotz beschädigtem Kettenkopf "
               "als erfolgreich versiegelt."))
    return false;
  std::ifstream input(file, std::ios::binary);
  const std::string content{std::istreambuf_iterator<char>(input),
                            std::istreambuf_iterator<char>()};
  if (!require(content.find("streng-geheimer-dateiname") == std::string::npos &&
                   content.find("geheime-seriennummer") == std::string::npos &&
                   content.find("geheime-diagnosemeldung") == std::string::npos,
               "Auditdatensatz enthält sensible Klartextwerte."))
    return false;
  std::ofstream tamper(file, std::ios::binary | std::ios::app);
  tamper << 'X';
  tamper.close();
  if (!require(!oblivion::verify_audit_file(file),
               "Manipulierter Auditdatensatz wurde nicht erkannt."))
    return false;
  const auto key_file = audit_directory / L"audit.key.dpapi";
  {
    oblivion::unique_win_handle corrupt_key{CreateFileW(
        key_file.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr)};
    constexpr char replacement[] = "corrupt";
    DWORD written = 0;
    if (!require(corrupt_key &&
                     WriteFile(corrupt_key.get(), replacement,
                               static_cast<DWORD>(sizeof(replacement) - 1u),
                               &written, nullptr) != FALSE &&
                     written == sizeof(replacement) - 1u &&
                     SetEndOfFile(corrupt_key.get()) != FALSE &&
                     FlushFileBuffers(corrupt_key.get()) != FALSE,
                 "Audit-Schlüssel konnte für den Korruptionstest nicht "
                 "überschrieben werden."))
      return false;
  }
  if (!require(!oblivion::verify_audit_file(second_file),
               "Beschädigter Audit-Schlüssel wurde nicht fail-closed "
               "abgewiesen."))
    return false;
  const auto key_after_failure = read_bytes(key_file);
  return require(
      std::string{key_after_failure.begin(), key_after_failure.end()} ==
          "corrupt",
      "Beschädigter Audit-Schlüssel wurde unbemerkt ersetzt und die Historie "
      "dadurch entwertet.");
}

bool test_certificate_html_escaping(const std::filesystem::path &root) {
  hook_guard guard;
  audit_test_directory = root;
  oblivion::testing::hooks().audit_directory = test_audit_directory;
  const auto audit_file = root / L"untrusted-audit.log";
  const auto certificate = root / L"certificate.html";
  {
    std::ofstream audit(audit_file, std::ios::binary | std::ios::trunc);
    audit << "OBLIVION AUDIT\nOperationID: <script>alert(1)</script>\n"
             "Media: HDD & SSD\nFiles: 999\nDirectories: 888\n"
             "LogicalBytes: 777\nSuccess: false\nCancelled: true\n"
             "Win32Error: 5\nBytesWritten: 123\nFilesDeleted: 2\n"
             "DirectoriesDeleted: 1\n";
    std::ofstream forged_hash(audit_file.wstring() + L".sha256",
                              std::ios::binary | std::ios::trunc);
    forged_hash << "forged-sidecar-value";
  }
  if (!require(oblivion::generate_certificate_from_audit(audit_file, certificate),
                "Zertifikat aus Test-Audit konnte nicht erstellt werden."))
    return false;
  const auto audit_before_self_export = read_bytes(audit_file);
  if (!require(
          !oblivion::generate_certificate_from_audit(audit_file, audit_file) &&
              read_bytes(audit_file) == audit_before_self_export,
          "Zertifikatexport durfte die Audit-Eingabedatei nicht überschreiben."))
    return false;
  const auto certificate_before_collision = read_bytes(certificate);
  if (!require(
          !oblivion::generate_certificate_from_audit(audit_file, certificate) &&
              read_bytes(certificate) == certificate_before_collision,
          "Vorhandenes Zertifikat wurde statt exklusiver Neuerstellung "
          "überschrieben."))
    return false;
  const auto html = read_bytes(certificate);
  const std::string text{reinterpret_cast<const char *>(html.data()), html.size()};
  if (!require(text.find("&lt;script&gt;alert(1)&lt;/script&gt;") !=
                           std::string::npos &&
                       text.find("<script>alert(1)</script>") ==
                           std::string::npos &&
                       text.find("HDD &amp; SSD") != std::string::npos &&
                       text.find(">2</td>") != std::string::npos &&
                       text.find(">1</td>") != std::string::npos &&
                       text.find(">123 Bytes</td>") != std::string::npos &&
                       text.find("Löschvorgang nicht als erfolgreich") !=
                           std::string::npos &&
                       text.find("forged-sidecar-value") == std::string::npos,
                   "Zertifikat exportiert Auditwerte unsicher oder vertraut "
                   "einem manipulierbaren SHA-256-Sidecar."))
    return false;
  const auto input_link = root / L"certificate-input-link";
  if (!CreateSymbolicLinkW(input_link.c_str(), root.c_str(),
                           SYMBOLIC_LINK_FLAG_DIRECTORY |
                               SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE))
    return require(false,
                   "Zertifikat-Eingabe-Symlink konnte nicht erzeugt werden.");
  if (!require(!oblivion::generate_certificate_from_audit(
                   input_link / audit_file.filename(),
                   root / L"linked-input.html"),
               "Zertifikatexport folgte einem Reparse-Eingabevorfahren."))
    return false;
  const auto output_target = root / L"certificate-output-target";
  const auto output_link = root / L"certificate-output-link";
  std::filesystem::create_directories(output_target);
  if (!CreateSymbolicLinkW(output_link.c_str(), output_target.c_str(),
                           SYMBOLIC_LINK_FLAG_DIRECTORY |
                               SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE))
    return require(false,
                   "Zertifikat-Ausgabe-Symlink konnte nicht erzeugt werden.");
  return require(
      !oblivion::generate_certificate_from_audit(
          audit_file, output_link / L"redirected.html") &&
          !std::filesystem::exists(output_target / L"redirected.html"),
      "Zertifikatexport folgte einem Reparse-Ausgabevorfahren.");
}

bool test_audit_input_limits(const std::filesystem::path &root) {
  hook_guard guard;
  audit_test_directory = root;
  oblivion::testing::hooks().audit_directory = test_audit_directory;
  const auto oversized = root / L"oversized-audit.log";
  {
    std::ofstream output(oversized, std::ios::binary | std::ios::trunc);
    output.seekp(16u * 1024u * 1024u);
    output.put('X');
  }
  const auto certificate = root / L"oversized-audit.html";
  return require(!oblivion::verify_audit_file(oversized) &&
                     !oblivion::generate_certificate_from_audit(oversized,
                                                                  certificate),
                 "Übergroße Auditdatei wird nicht fail-closed abgewiesen.");
}

bool test_local_dll_preloading_blocked() {
  HMODULE module = LoadLibraryW(L"OblivionShell.dll");
  if (module != nullptr) {
    FreeLibrary(module);
    return require(false,
                   "Lokale DLL wurde trotz gehärteter Suchrichtlinie geladen.");
  }
  return true;
}
} // namespace

int wmain() {
  try {
    test_directory directory;
    const auto run = [](const char *name, const auto &test) {
      std::cerr << "[ RUN      ] " << name << '\n';
      const bool passed = test();
      if (passed)
        std::cerr << "[       OK ] " << name << '\n';
      return passed;
    };
    if (!run("hardlinks", [&] { return test_hardlinks(directory.path()); }))
      return 1;
    if (!run("ads", [&] { return test_ads(directory.path()); }))
      return 2;
    if (!run("reparse_point",
             [&] { return test_reparse_point(directory.path()); }))
      return 3;
    if (!run("reparse_ancestor_blocked", [&] {
          return test_reparse_ancestor_blocked(directory.path());
        }))
      return 4;
    if (!run("locked_file",
             [&] { return test_locked_file(directory.path()); }))
      return 5;
    if (!run("analysis_volume_grouping", test_analysis_volume_grouping))
      return 6;
    if (!run("analysis_resource_limit",
             [&] { return test_analysis_resource_limit(directory.path()); }))
      return 18;
    if (!run("secure_memory", test_secure_memory))
      return 7;
    if (!run("engine_boundary_guard",
             [&] { return test_engine_boundary_guard(directory.path()); }))
      return 8;
    if (!run("callback_exception_preserves_partial_result", [&] {
          return test_callback_exception_preserves_partial_result(
              directory.path());
        }))
      return 17;
    if (!run("cancellation_exception_fails_closed", [&] {
          return test_cancellation_exception_fails_closed(directory.path());
        }))
      return 19;
    if (!run("runtime_hardening", test_runtime_hardening))
      return 9;
    if (!run("wipe_failure_paths",
             [&] { return test_wipe_failure_paths(directory.path()); }))
      return 10;
    if (!run("recycle_bin_failure_paths", test_recycle_bin_failure_paths))
      return 11;
    if (!run("unique_handle", test_unique_handle))
      return 12;
    if (!run("private_audit",
             [&] { return test_private_audit(directory.path()); }))
      return 13;
    if (!run("certificate_html_escaping", [&] {
          return test_certificate_html_escaping(directory.path());
        }))
      return 14;
    if (!run("audit_input_limits",
             [&] { return test_audit_input_limits(directory.path()); }))
      return 15;
    if (!run("local_dll_preloading_blocked",
             test_local_dll_preloading_blocked))
      return 16;
    std::cout << "Engine-Self-Test erfolgreich: Hardlinks, ADS, Reparse "
                  "Points/Vorfahren, Locked Files, Volume-Gruppierung, sichere "
                 "Arbeitspuffer, Engine-Grenzschutz, Prozesshärtung, "
                 "CSPRNG-/Flush-Fehlerpfade, Papierkorb-Abbruch und "
                 "RAII-Handles, privater HMAC-Audit einschließlich "
                 "Kettenmanipulation, HTML-sicherer Zertifikatsexport und "
                 "DLL-Preloading-Schutz.\n";
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "FEHLER: Ausnahme im Engine-Self-Test: " << error.what()
              << '\n';
    return 12;
  }
}
