#include "oblivion/analyzer.hpp"
#include "oblivion/app_logic.hpp"
#include "oblivion/audit.hpp"
#include "oblivion/audit_integrity.hpp"
#include "oblivion/erase_engine.hpp"
#include "oblivion/certificate.hpp"
#include "oblivion/runtime_guard.hpp"
#include "oblivion/secure_memory.hpp"
#include "oblivion/test_hooks.hpp"
#include "oblivion/win_handle.hpp"
#include "oblivion/wipe_free_space.hpp"

#include <Windows.h>

#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iostream>
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

class local_appdata_guard final {
public:
  explicit local_appdata_guard(const std::filesystem::path &replacement) {
    const DWORD size = GetEnvironmentVariableW(L"LOCALAPPDATA", nullptr, 0);
    if (size > 0) {
      previous_.resize(size);
      const DWORD written =
          GetEnvironmentVariableW(L"LOCALAPPDATA", previous_.data(), size);
      if (written > 0 && written < size)
        previous_.resize(written);
    }
    changed_ =
        SetEnvironmentVariableW(L"LOCALAPPDATA", replacement.c_str()) != FALSE;
  }
  ~local_appdata_guard() {
    if (changed_)
      SetEnvironmentVariableW(L"LOCALAPPDATA",
                              previous_.empty() ? nullptr : previous_.c_str());
  }
  [[nodiscard]] bool changed() const { return changed_; }

private:
  std::wstring previous_;
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

bool fail_random(std::span<std::byte>) noexcept { return false; }

BOOL WINAPI fail_flush(HANDLE) {
  SetLastError(ERROR_WRITE_FAULT);
  return FALSE;
}

int recycle_empty_calls{};
int recycle_scan_calls{};

HRESULT WINAPI fail_recycle_empty(HWND, LPCWSTR, DWORD) {
  ++recycle_empty_calls;
  return E_ACCESSDENIED;
}

HRESULT WINAPI count_recycle_empty(HWND, LPCWSTR, DWORD) {
  ++recycle_empty_calls;
  return S_OK;
}

HRESULT WINAPI query_recycle_empty(LPCWSTR, LPSHQUERYRBINFO info) {
  info->i64NumItems = 0;
  info->i64Size = 0;
  return S_OK;
}

HRESULT WINAPI fail_recycle_query(LPCWSTR, LPSHQUERYRBINFO) {
  return E_FAIL;
}

HRESULT WINAPI query_recycle_with_items(LPCWSTR, LPSHQUERYRBINFO info) {
  info->i64NumItems = 1;
  info->i64Size = 1;
  return S_OK;
}

oblivion::recycle_bin_scan_result incomplete_recycle_scan() {
  return {{}, false, ERROR_ACCESS_DENIED};
}

oblivion::recycle_bin_scan_result empty_recycle_scan() { return {}; }

oblivion::recycle_bin_scan_result one_recycle_item_scan() {
  return {{std::filesystem::temp_directory_path()}, true, 0};
}

oblivion::recycle_bin_scan_result changed_recycle_scan() {
  ++recycle_scan_calls;
  return recycle_scan_calls == 1 ? oblivion::recycle_bin_scan_result{}
                                 : one_recycle_item_scan();
}

oblivion::erase_result cancelled_recycle_erase(const std::filesystem::path &,
                                               const oblivion::erase_options &,
                                               const oblivion::progress_callback &) {
  oblivion::erase_result result;
  result.cancelled = true;
  result.message = L"Testabbruch";
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

  return require(report.find(L"Datenträger: 2") != std::wstring::npos &&
                     report.find(L"F:\\ · 2 Ziele") != std::wstring::npos &&
                     report.find(L"G:\\") != std::wstring::npos && f_once,
                 "Analyse gruppiert identische Volumes nicht korrekt.");
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

bool test_engine_boundary_guard() {
  std::vector<wchar_t> windows_directory(32768);
  const UINT length = GetWindowsDirectoryW(
      windows_directory.data(), static_cast<UINT>(windows_directory.size()));
  if (!require(length > 0 && length < windows_directory.size(),
               "Windows-Verzeichnis konnte für den Schutztest nicht bestimmt "
               "werden."))
    return false;
  const std::filesystem::path protected_target{windows_directory.data()};
  oblivion::erase_engine engine;
  const auto result = engine.erase(protected_target, {});
  return require(!result.success && result.win32_error == ERROR_ACCESS_DENIED &&
                     std::filesystem::exists(protected_target),
                 "Direkter Engine-Aufruf hat einen geschützten Systempfad "
                 "nicht blockiert.");
}

bool test_runtime_hardening() {
  const auto status = oblivion::harden_current_process();
  return require(
      status.complete(),
      "Native Prozesshärtung konnte nicht vollständig aktiviert werden.");
}

bool test_wipe_failure_paths(const std::filesystem::path &root) {
  oblivion::erase_options options;
  options.mode = oblivion::erase_mode::standard;
  {
    hook_guard guard;
    oblivion::testing::hooks().random = fail_random;
    const auto result = oblivion::wipe_volume_free_space(root, options, {});
    if (!require(!result.success && result.win32_error == ERROR_GEN_FAILURE,
                 "CSPRNG-Fehler beendet Freispeicher-Bereinigung nicht fail-closed."))
      return false;
  }
  {
    hook_guard guard;
    options.mode = oblivion::erase_mode::nist_800_88;
    oblivion::testing::hooks().wipe_max_chunk_bytes = 4096;
    oblivion::testing::hooks().flush = fail_flush;
    const auto result = oblivion::wipe_volume_free_space(root, options, {});
    if (!require(!result.success && result.win32_error == ERROR_WRITE_FAULT,
                 "Flush-Fehler beendet Freispeicher-Bereinigung nicht fail-closed."))
      return false;
  }
  return true;
}

bool test_recycle_bin_failure_paths() {
  oblivion::erase_options options;
  {
    hook_guard guard;
    recycle_empty_calls = 0;
    oblivion::testing::hooks().recycle_scan = incomplete_recycle_scan;
    oblivion::testing::hooks().recycle_empty = count_recycle_empty;
    const auto result = oblivion::secure_empty_recycle_bin(options, {});
    if (!require(!result.success && result.win32_error == ERROR_ACCESS_DENIED &&
                     recycle_empty_calls == 0,
                 "Unvollständiger Papierkorb-Scan ruft die Shell-Bereinigung auf."))
      return false;
  }
  {
    hook_guard guard;
    recycle_empty_calls = 0;
    recycle_scan_calls = 0;
    oblivion::testing::hooks().recycle_scan = changed_recycle_scan;
    oblivion::testing::hooks().recycle_empty = count_recycle_empty;
    const auto result = oblivion::secure_empty_recycle_bin(options, {});
    if (!require(!result.success && result.win32_error == ERROR_DIR_NOT_EMPTY &&
                     recycle_empty_calls == 0,
                 "Neu erschienene Papierkorbobjekte werden von der Shell gelöscht."))
      return false;
  }
  {
    hook_guard guard;
    recycle_empty_calls = 0;
    oblivion::testing::hooks().recycle_scan = one_recycle_item_scan;
    oblivion::testing::hooks().recycle_exists = inaccessible_recycle_item;
    oblivion::testing::hooks().recycle_empty = count_recycle_empty;
    const auto result = oblivion::secure_empty_recycle_bin(options, {});
    if (!require(!result.success && result.win32_error == ERROR_ACCESS_DENIED &&
                     recycle_empty_calls == 0,
                 "Fehler beim Prüfen eines Papierkorbobjekts ist nicht fail-closed."))
      return false;
  }
  {
    hook_guard guard;
    recycle_empty_calls = 0;
    oblivion::testing::hooks().recycle_scan = empty_recycle_scan;
    oblivion::testing::hooks().recycle_empty = fail_recycle_empty;
    const auto result = oblivion::secure_empty_recycle_bin(options, {});
    if (!require(!result.success && result.win32_error == ERROR_ACCESS_DENIED &&
                     recycle_empty_calls == 1,
                 "Fehler von SHEmptyRecycleBinW wird nicht weitergegeben."))
      return false;
  }
  {
    hook_guard guard;
    oblivion::testing::hooks().recycle_scan = empty_recycle_scan;
    oblivion::testing::hooks().recycle_empty = count_recycle_empty;
    oblivion::testing::hooks().recycle_query = fail_recycle_query;
    const auto result = oblivion::secure_empty_recycle_bin(options, {});
    if (!require(!result.success && result.win32_error == HRESULT_CODE(E_FAIL),
                 "Unverifizierter Papierkorb-Endzustand wird als Erfolg gemeldet."))
      return false;
  }
  {
    hook_guard guard;
    oblivion::testing::hooks().recycle_scan = empty_recycle_scan;
    oblivion::testing::hooks().recycle_empty = count_recycle_empty;
    oblivion::testing::hooks().recycle_query = query_recycle_with_items;
    const auto result = oblivion::secure_empty_recycle_bin(options, {});
    if (!require(!result.success && result.win32_error == ERROR_DIR_NOT_EMPTY,
                 "Verbleibende Papierkorbobjekte werden als Erfolg gemeldet."))
      return false;
  }
  {
    hook_guard guard;
    oblivion::testing::hooks().recycle_scan = empty_recycle_scan;
    oblivion::testing::hooks().recycle_empty = count_recycle_empty;
    oblivion::testing::hooks().recycle_query = query_recycle_empty;
    const auto result = oblivion::secure_empty_recycle_bin(options, {});
    if (!require(result.success,
                 "Verifizierter leerer Papierkorb wird nicht als Erfolg gemeldet."))
      return false;
  }
  {
    hook_guard guard;
    recycle_empty_calls = 0;
    oblivion::testing::hooks().recycle_scan = one_recycle_item_scan;
    oblivion::testing::hooks().recycle_erase = cancelled_recycle_erase;
    oblivion::testing::hooks().recycle_empty = count_recycle_empty;
    const auto result = oblivion::secure_empty_recycle_bin(options, {});
    if (!require(!result.success && result.cancelled && recycle_empty_calls == 0,
                 "Abgebrochene Papierkorb-Operation ruft die Shell-Bereinigung auf."))
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
  local_appdata_guard environment(root);
  if (!require(environment.changed(),
               "LOCALAPPDATA konnte für den Audit-Test nicht isoliert werden."))
    return false;
  oblivion::operation_audit audit;
  audit.operation_id = oblivion::create_operation_id();
  audit.target = root / L"streng-geheimer-dateiname.txt";
  audit.storage.volume_root = L"Z:\\geheimes-volume";
  audit.storage.volume_guid = L"geheime-volume-guid";
  audit.storage.device_model = L"geheimes-modell";
  audit.storage.device_serial = L"geheime-seriennummer";
  audit.result.success = true;
  audit.result.message = L"geheime-diagnosemeldung";
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
  {
    std::ofstream tamper_head(audit_directory / L"chain.head",
                              std::ios::binary | std::ios::trunc);
    tamper_head << std::string(64, '0') << '\n';
  }
  if (!require(!oblivion::verify_audit_chain(audit_directory),
               "Manipulierter Audit-Kettenkopf wurde nicht erkannt."))
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
  return require(!oblivion::verify_audit_file(file),
                 "Manipulierter Auditdatensatz wurde nicht erkannt.");
}

bool test_certificate_html_escaping(const std::filesystem::path &root) {
  local_appdata_guard environment(root);
  if (!require(environment.changed(),
               "LOCALAPPDATA konnte für den Zertifikat-Test nicht isoliert werden."))
    return false;
  const auto audit_file = root / L"untrusted-audit.log";
  const auto certificate = root / L"certificate.html";
  {
    std::ofstream audit(audit_file, std::ios::binary | std::ios::trunc);
    audit << "OBLIVION AUDIT\nOperationID: <script>alert(1)</script>\n"
             "Media: HDD & SSD\n";
  }
  if (!require(oblivion::generate_certificate_from_audit(audit_file, certificate),
               "Zertifikat aus Test-Audit konnte nicht erstellt werden."))
    return false;
  const auto html = read_bytes(certificate);
  const std::string text{reinterpret_cast<const char *>(html.data()), html.size()};
  return require(text.find("&lt;script&gt;alert(1)&lt;/script&gt;") !=
                         std::string::npos &&
                     text.find("<script>alert(1)</script>") == std::string::npos &&
                     text.find("HDD &amp; SSD") != std::string::npos,
                 "Zertifikat exportiert Auditwerte nicht HTML-escaped.");
}

bool test_audit_input_limits(const std::filesystem::path &root) {
  local_appdata_guard environment(root);
  if (!require(environment.changed(),
               "LOCALAPPDATA konnte für den Größenlimit-Test nicht isoliert werden."))
    return false;
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
    if (!test_hardlinks(directory.path()))
      return 1;
    if (!test_ads(directory.path()))
      return 2;
    if (!test_reparse_point(directory.path()))
      return 3;
    if (!test_locked_file(directory.path()))
      return 4;
    if (!test_analysis_volume_grouping())
      return 5;
    if (!test_secure_memory())
      return 6;
    if (!test_engine_boundary_guard())
      return 7;
    if (!test_runtime_hardening())
      return 8;
    if (!test_wipe_failure_paths(directory.path()))
      return 9;
    if (!test_recycle_bin_failure_paths())
      return 10;
    if (!test_unique_handle())
      return 11;
    if (!test_private_audit(directory.path()))
      return 12;
    if (!test_certificate_html_escaping(directory.path()))
      return 13;
    if (!test_audit_input_limits(directory.path()))
      return 14;
    if (!test_local_dll_preloading_blocked())
      return 15;
    std::cout << "Engine-Self-Test erfolgreich: Hardlinks, ADS, Reparse "
                 "Points, Locked Files, Volume-Gruppierung, sichere "
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
