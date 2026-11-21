#include "oblivion/audit.hpp"
#include "oblivion/audit_integrity.hpp"
#include <Windows.h>
#include <algorithm>
#include <bcrypt.h>
#include <cstddef>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <limits>
#include <objbase.h>
#include <sstream>
#include <string>
#include <vector>
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
  BCRYPT_ALG_HANDLE a = nullptr;
  BCRYPT_HASH_HANDLE h = nullptr;
  DWORD ol = 0, hl = 0, n = 0;
  if (BCryptOpenAlgorithmProvider(&a, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
    return {};
  if (BCryptGetProperty(a, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&ol),
                        sizeof(ol), &n, 0) < 0 ||
      BCryptGetProperty(a, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hl),
                        sizeof(hl), &n, 0) < 0) {
    BCryptCloseAlgorithmProvider(a, 0);
    return {};
  }
  std::vector<std::byte> o(ol), d(hl);
  if (BCryptCreateHash(a, &h, reinterpret_cast<PUCHAR>(o.data()), ol, nullptr,
                       0, 0) < 0) {
    BCryptCloseAlgorithmProvider(a, 0);
    return {};
  }
  std::size_t off = 0;
  while (off < s.size()) {
    auto c = static_cast<ULONG>((std::min)(
        s.size() - off,
        static_cast<std::size_t>((std::numeric_limits<ULONG>::max)())));
    if (BCryptHashData(
            h, reinterpret_cast<PUCHAR>(const_cast<char *>(s.data() + off)), c,
            0) < 0) {
      d.clear();
      break;
    }
    off += c;
  }
  if (!d.empty() &&
      BCryptFinishHash(h, reinterpret_cast<PUCHAR>(d.data()), hl, 0) < 0)
    d.clear();
  BCryptDestroyHash(h);
  BCryptCloseAlgorithmProvider(a, 0);
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
  std::wstring v(32768, L'\0');
  DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", v.data(),
                                    static_cast<DWORD>(v.size()));
  if (n && static_cast<std::size_t>(n) < v.size()) {
    v.resize(n);
    return std::filesystem::path{v} / L"Oblivion" / L"Audit";
  }
  return std::filesystem::temp_directory_path() / L"Oblivion" / L"Audit";
}
std::wstring create_operation_id() {
  GUID g{};
  if (FAILED(CoCreateGuid(&g)))
    return L"unknown";
  wchar_t b[64]{};
  return StringFromGUID2(g, b, 64) > 0 ? std::wstring{b} : L"unknown";
}
std::filesystem::path write_audit_record(const operation_audit &r) {
  std::error_code ec;
  auto dir = audit_directory();
  std::filesystem::create_directories(dir, ec);
  if (ec)
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
  std::ofstream out(f, std::ios::binary | std::ios::trunc);
  if (!out)
    return {};
  out.write(t.data(), static_cast<std::streamsize>(t.size()));
  out.close();
  auto d = sha(t);
  if (!d.empty()) {
    auto hf = f;
    hf += L".sha256";
    std::ofstream h(hf, std::ios::binary | std::ios::trunc);
    if (h)
      h << hex(d) << "\n";
  }
  if (!seal_audit_file(f)) {
    std::filesystem::remove(f, ec);
    auto hash_file = f;
    hash_file += L".sha256";
    std::filesystem::remove(hash_file, ec);
    return {};
  }
  return f;
}
} // namespace oblivion
