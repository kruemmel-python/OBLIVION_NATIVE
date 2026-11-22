#include "oblivion/audit.hpp"
#include "oblivion/audit_integrity.hpp"
#include "oblivion/bcrypt_handle.hpp"
#include "oblivion/cotaskmem_string.hpp"
#include "oblivion/win_handle.hpp"
#include <Windows.h>
#include <ShlObj.h>
#include <algorithm>
#include <bcrypt.h>
#include <cstddef>
#include <cwctype>
#include <filesystem>
#include <limits>
#include <objbase.h>
#include <sstream>
#include <string>
#include <vector>
#ifdef OBLIVION_TESTING
#include "oblivion/test_hooks.hpp"
#endif
namespace oblivion {
namespace {
std::wstring mn(erase_mode m) {
  switch (m) {
  case erase_mode::fast: return L"FAST";
  case erase_mode::strong: return L"STRONG";
  case erase_mode::dod_5220_22_m: return L"DOD_5220_22_M";
  case erase_mode::nist_800_88: return L"NIST_800_88";
  case erase_mode::bsi_gs: return L"BSI_GS";
  case erase_mode::gutmann: return L"GUTMANN_35";
  case erase_mode::standard:
  default: return L"STANDARD";
  }
}
std::wstring hp(hardlink_policy p) {
  return p == hardlink_policy::delete_link_only ? L"DELETE_LINK_ONLY"
         : p == hardlink_policy::overwrite_shared_content
             ? L"OVERWRITE_SHARED_CONTENT"
             : L"BLOCK";
}
std::wstring med(media_kind k) {
  return k == media_kind::solid_state  ? L"SSD/NVMe"
         : k == media_kind::rotational ? L"HDD"
                                       : L"UNKNOWN";
}
std::wstring stamp() {
  SYSTEMTIME s{};
  GetLocalTime(&s);
  wchar_t b[64]{};
  swprintf_s(b, L"%04u-%02u-%02u_%02u-%02u-%02u-%03u", s.wYear, s.wMonth,
             s.wDay, s.wHour, s.wMinute, s.wSecond, s.wMilliseconds);
  return b;
}
std::string utf8(const std::wstring &w) {
  if (w.empty())
    return {};
  if (w.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)()))
    return {};
  int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()),
                              nullptr, 0, nullptr, nullptr);
  if (n <= 0)
    return {};
  std::string r(static_cast<std::size_t>(n), '\0');
  WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()),
                      r.data(), n, nullptr, nullptr);
  return r;
}
std::vector<std::byte> sha(const std::string &s) {
  unique_bcrypt_algorithm a;
  DWORD ol = 0, hl = 0, n = 0;
  if (BCryptOpenAlgorithmProvider(a.put(), BCRYPT_SHA256_ALGORITHM, nullptr,
                                  0) < 0)
    return {};
  if (BCryptGetProperty(a.get(), BCRYPT_OBJECT_LENGTH,
                        reinterpret_cast<PUCHAR>(&ol), sizeof(ol), &n, 0) < 0 ||
      BCryptGetProperty(a.get(), BCRYPT_HASH_LENGTH,
                        reinterpret_cast<PUCHAR>(&hl), sizeof(hl), &n, 0) < 0) {
    return {};
  }
  std::vector<std::byte> o(ol), d(hl);
  // BCrypt may retain the caller-owned hash-object buffer until the hash
  // handle is destroyed. Declare the handle after its backing storage so the
  // handle is released first during stack unwinding.
  unique_bcrypt_hash h;
  if (BCryptCreateHash(a.get(), h.put(), reinterpret_cast<PUCHAR>(o.data()), ol,
                       nullptr, 0, 0) < 0) {
    return {};
  }
  std::size_t off = 0;
  while (off < s.size()) {
    auto c = static_cast<ULONG>((std::min)(
        s.size() - off,
        static_cast<std::size_t>((std::numeric_limits<ULONG>::max)())));
    if (BCryptHashData(
            h.get(),
            reinterpret_cast<PUCHAR>(const_cast<char *>(s.data() + off)), c,
            0) < 0) {
      d.clear();
      break;
    }
    off += c;
  }
  if (!d.empty() &&
      BCryptFinishHash(h.get(), reinterpret_cast<PUCHAR>(d.data()), hl, 0) < 0)
    d.clear();
  return d;
}
std::string hex(const std::vector<std::byte> &d) {
  constexpr char x[] = "0123456789abcdef";
  std::string r;
  for (auto b : d) {
    auto v = std::to_integer<unsigned>(b);
    r.push_back(x[v >> 4]);
    r.push_back(x[v & 15]);
  }
  return r;
}
std::wstring frag(const std::wstring &id) {
  std::wstring r;
  for (wchar_t c : id)
    if (std::iswxdigit(c)) {
      r.push_back(c);
      if (r.size() == 16)
        break;
    }
  return r.empty() ? L"unknown" : r;
}
} // namespace
std::filesystem::path audit_directory() {
#ifdef OBLIVION_TESTING
  if (testing::hooks().audit_directory)
    return testing::hooks().audit_directory();
#endif
  unique_cotaskmem_string local;
  const HRESULT result = SHGetKnownFolderPath(
      FOLDERID_LocalAppData, KF_FLAG_DONT_VERIFY, nullptr, local.put());
  if (FAILED(result) || !local)
    return {};
  std::filesystem::path directory =
      std::filesystem::path{local.get()} / L"Oblivion" / L"Audit";
  return directory;
}
bool prepare_audit_directory(std::filesystem::path &directory) noexcept try {
  directory = audit_directory();
  if (directory.empty() || !directory.is_absolute())
    return false;

  std::filesystem::path current = directory.root_path();
  if (current.empty())
    return false;
  std::vector<unique_win_handle> locks;
  for (const auto &component : directory.relative_path()) {
    current /= component;
    DWORD attributes = GetFileAttributesW(current.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
      const DWORD error = GetLastError();
      if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND)
        return false;
      if (CreateDirectoryW(current.c_str(), nullptr) == FALSE) {
        const DWORD create_error = GetLastError();
        if (create_error != ERROR_ALREADY_EXISTS)
          return false;
      }
      attributes = GetFileAttributesW(current.c_str());
    }
    unique_win_handle handle{CreateFileW(
        current.c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
    FILE_ATTRIBUTE_TAG_INFO verified{};
    if (attributes == INVALID_FILE_ATTRIBUTES || !handle ||
        !GetFileInformationByHandleEx(handle.get(), FileAttributeTagInfo,
                                      &verified, sizeof(verified)) ||
        (verified.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
        (verified.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
      return false;
    locks.push_back(std::move(handle));
  }
  return true;
} catch (...) {
  directory.clear();
  return false;
}

namespace {
bool lock_audit_directory_tree(
    const std::filesystem::path &directory,
    std::vector<unique_win_handle> &locks) noexcept try {
  locks.clear();
  auto current = directory.root_path();
  if (current.empty())
    return false;
  for (const auto &component : directory.relative_path()) {
    if (component.empty() || component == L".")
      continue;
    if (component == L"..")
      return false;
    current /= component;
    unique_win_handle handle{CreateFileW(
        current.c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    if (!handle ||
        !GetFileInformationByHandleEx(handle.get(), FileAttributeTagInfo,
                                      &attributes, sizeof(attributes)) ||
        (attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
        (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
      return false;
    locks.push_back(std::move(handle));
  }
  return true;
} catch (...) {
  return false;
}

void discard_created_file(unique_win_handle &output) noexcept {
  FILE_DISPOSITION_INFO disposition{TRUE};
  (void)SetFileInformationByHandle(output.get(), FileDispositionInfo,
                                   &disposition, sizeof(disposition));
  output.reset();
}
class created_file_guard final {
public:
  explicit created_file_guard(unique_win_handle &file) noexcept : file_(file) {}
  ~created_file_guard() {
    if (armed_ && file_)
      discard_created_file(file_);
  }
  created_file_guard(const created_file_guard &) = delete;
  created_file_guard &operator=(const created_file_guard &) = delete;
  void commit() noexcept { armed_ = false; }

private:
  unique_win_handle &file_;
  bool armed_{true};
};

bool create_new_audit_file(const std::filesystem::path &file,
                           const std::string_view contents,
                           unique_win_handle &output) noexcept try {
  std::filesystem::path directory;
  if (!prepare_audit_directory(directory) || file.filename().empty())
    return false;
  std::vector<unique_win_handle> directory_locks;
  if (!lock_audit_directory_tree(directory, directory_locks))
    return false;
  std::error_code equivalent_error;
  if (!std::filesystem::equivalent(file.parent_path(), directory,
                                   equivalent_error) ||
      equivalent_error)
    return false;

  output.reset(CreateFileW(
      file.c_str(), GENERIC_WRITE | DELETE, FILE_SHARE_READ, nullptr, CREATE_NEW,
      FILE_ATTRIBUTE_NOT_CONTENT_INDEXED | FILE_FLAG_OPEN_REPARSE_POINT,
      nullptr));
  if (!output)
    return false;
  std::size_t offset = 0;
  while (offset < contents.size()) {
    const DWORD count = static_cast<DWORD>((std::min)(
        contents.size() - offset,
        static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
    DWORD written = 0;
    if (!WriteFile(output.get(), contents.data() + offset, count, &written,
                   nullptr) ||
        written != count) {
      discard_created_file(output);
      return false;
    }
    offset += written;
  }
  if (FlushFileBuffers(output.get()) == FALSE) {
    discard_created_file(output);
    return false;
  }
  return true;
} catch (...) {
  return false;
}
} // namespace

bool write_new_audit_file(const std::filesystem::path &file,
                          const std::string_view contents) noexcept {
  unique_win_handle output;
  return create_new_audit_file(file, contents, output);
}

bool write_new_audit_file(const std::filesystem::path &file,
                          const std::wstring_view contents) noexcept try {
  const auto encoded = utf8(std::wstring{contents});
  return !contents.empty() && !encoded.empty() &&
         write_new_audit_file(file, encoded);
} catch (...) {
  return false;
}

bool write_sealed_audit_file(const std::filesystem::path &file,
                             const std::wstring_view contents) noexcept try {
  const auto encoded = utf8(std::wstring{contents});
  unique_win_handle output;
  if (contents.empty() || encoded.empty() ||
      !create_new_audit_file(file, encoded, output))
    return false;
  if (!seal_audit_file_contents(file, encoded)) {
    discard_created_file(output);
    return false;
  }
  return true;
} catch (...) {
  return false;
}
std::wstring create_operation_id() noexcept try {
  GUID g{};
  if (FAILED(CoCreateGuid(&g)))
    return {};
  wchar_t b[64]{};
  return StringFromGUID2(g, b, 64) > 0 ? std::wstring{b} : std::wstring{};
} catch (...) {
  return {};
}
std::filesystem::path write_audit_record(const operation_audit &r) noexcept try {
  std::filesystem::path dir;
  if (!prepare_audit_directory(dir) || r.operation_id.empty())
    return {};
  auto f =
      dir / (L"oblivion_" + stamp() + L"_" + frag(r.operation_id) + L".log");
  std::wostringstream o;
  o << L"OBLIVION AUDIT 3\nOperationID: " << r.operation_id << L"\nTargetRef: "
    << audit_reference(r.target.lexically_normal().wstring())
    << L"\nDurationMs: " << r.duration_ms << L"\n\n[Storage]\nMedia: "
    << med(r.storage.kind) << L"\nVolumeRef: "
    << audit_reference(r.storage.volume_root) << L"\nVolumeGUIDRef: "
    << audit_reference(r.storage.volume_guid) << L"\nFilesystem: "
    << r.storage.filesystem << L"\nPhysicalDrive: "
    << r.storage.physical_drive_number << L"\nDeviceModelRef: "
    << audit_reference(r.storage.device_model) << L"\nDeviceSerialRef: "
    << audit_reference(r.storage.device_serial) << L"\nBus: "
    << r.storage.bus_type << L"\nTRIM: "
    << (r.storage.trim_enabled ? L"true" : L"false") << L"\nUSNJournal: "
    << (r.storage.usn_journal_active ? L"active" : L"not_detected")
    << L"\nShadowCopies: " << r.storage.shadow_copy_count
    << L"\n\n[Options]\nMode: " << mn(r.options.mode) << L"\nVerify: "
    << (r.options.verify ? L"true" : L"false") << L"\nAlternateStreams: "
    << (r.options.erase_alternate_streams ? L"true" : L"false")
    << L"\nRenameRounds: " << r.options.rename_rounds << L"\nHardlinkPolicy: "
    << hp(r.options.hardlinks) << L"\n\n[Analysis]\nFiles: " << r.analysis.files
    << L"\nDirectories: " << r.analysis.directories << L"\nLogicalBytes: "
    << r.analysis.logical_bytes << L"\nAlternateStreams: "
    << r.analysis.alternate_streams << L"\nReparsePoints: "
    << r.analysis.reparse_points << L"\nHardlinkedFiles: "
    << r.analysis.hardlinked_files << L"\n\n[Result]\nSuccess: "
    << (r.result.success ? L"true" : L"false") << L"\nCancelled: "
    << (r.result.cancelled ? L"true" : L"false") << L"\nWin32Error: "
    << r.result.win32_error << L"\nBytesWritten: " << r.result.bytes_written
    << L"\nFilesDeleted: " << r.result.files_deleted
    << L"\nDirectoriesDeleted: " << r.result.directories_deleted
    << L"\nAlternateStreamsOverwritten: "
    << r.result.alternate_streams_overwritten << L"\nReparsePointsRemoved: "
    << r.result.reparse_points_removed << L"\nHardlinksBlocked: "
    << r.result.hardlinks_blocked << L"\nMessageRef: "
    << audit_reference(r.result.message)
    << L"\n\n[Coverage]\nReparsePointTraversal: "
       L"disabled\nPhysicalMediaCoverage: "
    << (r.storage.kind == media_kind::solid_state
            ? L"not_guaranteed_due_to_flash_translation_layer"
            : L"logical_overwrite_only")
    << L"\nUSNMetadataHistory: "
    << (r.storage.usn_journal_active ? L"may_retain_metadata_history"
                                     : L"not_detected")
    << L"\nVolumeShadowCopies: "
    << (r.storage.shadow_copy_query_succeeded
            ? (r.storage.shadow_copy_count ? L"present_possible_historical_copy"
                                           : L"none_detected")
            : L"unknown")
    << L"\nExternalBackups: unknown\n";
  o << L"AnalysisWarningCount: " << r.analysis.warnings.size() << L"\n";
  o << L"ResultWarningCount: " << r.result.warnings.size() << L"\n";
  for (const auto &x : r.result.lock_owners)
    o << L"LockOwner: PID=" << x.process_id << L" AppRef="
      << audit_reference(x.application_name) << L" ServiceRef="
      << audit_reference(x.service_name) << L"\n";
  auto t = utf8(o.str());
  unique_win_handle record_handle;
  if (!create_new_audit_file(f, t, record_handle))
    return {};
  created_file_guard record_guard{record_handle};
  auto d = sha(t);
  if (d.empty())
    return {};
  auto hf = f;
  hf += L".sha256";
  const auto digest_text = hex(d) + "\n";
  unique_win_handle hash_handle;
  if (!create_new_audit_file(hf, digest_text, hash_handle))
    return {};
  created_file_guard hash_guard{hash_handle};
  if (!seal_audit_file_contents(f, t))
    return {};
  hash_guard.commit();
  record_guard.commit();
  return f;
} catch (...) {
  return {};
}
} // namespace oblivion
