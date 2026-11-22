#include "oblivion/erase_engine.hpp"
#include "oblivion/path_validator.hpp"
#include "oblivion/random.hpp"
#include "oblivion/restart_manager.hpp"
#include "oblivion/secure_memory.hpp"
#include "oblivion/win_handle.hpp"
#include <Windows.h>
#include <algorithm>
#include <array>
#include <bcrypt.h>
#include <cstddef>
#include <cstring>
#include <filesystem>
#include <limits>
#include <new>
#include <span>
#include <string>
#include <system_error>
#include <vector>
namespace oblivion {
namespace {
enum class pattern { random, zero, ones, gutmann_pattern };
struct stream_entry {
  std::wstring name;
  std::uint64_t size{0};
};
class unique_find_handle final {
public:
  explicit unique_find_handle(const HANDLE handle) noexcept : handle_(handle) {}
  ~unique_find_handle() {
    if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE)
      FindClose(handle_);
  }
  unique_find_handle(const unique_find_handle &) = delete;
  unique_find_handle &operator=(const unique_find_handle &) = delete;

private:
  HANDLE handle_{INVALID_HANDLE_VALUE};
};
static constexpr std::uint8_t gutmann_bytes[27][3] = {
    {0x55, 0x55, 0x55}, {0xAA, 0xAA, 0xAA}, {0x92, 0x49, 0x24},
    {0x49, 0x24, 0x92}, {0x24, 0x92, 0x49}, {0x00, 0x00, 0x00},
    {0x11, 0x11, 0x11}, {0x22, 0x22, 0x22}, {0x33, 0x33, 0x33},
    {0x44, 0x44, 0x44}, {0x55, 0x55, 0x55}, {0x66, 0x66, 0x66},
    {0x77, 0x77, 0x77}, {0x88, 0x88, 0x88}, {0x99, 0x99, 0x99},
    {0xAA, 0xAA, 0xAA}, {0xBB, 0xBB, 0xBB}, {0xCC, 0xCC, 0xCC},
    {0xDD, 0xDD, 0xDD}, {0xEE, 0xEE, 0xEE}, {0xFF, 0xFF, 0xFF},
    {0x92, 0x49, 0x24}, {0x49, 0x24, 0x92}, {0x24, 0x92, 0x49},
    {0x6D, 0xB6, 0xDB}, {0xB6, 0xDB, 0x6D}, {0xDB, 0x6D, 0xB6}};

std::vector<pattern> passes(erase_mode m) {
  switch (m) {
  case erase_mode::fast:
    return {pattern::random};
  case erase_mode::strong:
    return {pattern::random, pattern::zero, pattern::random};
  case erase_mode::dod_5220_22_m:
    return {pattern::zero, pattern::ones, pattern::random};
  case erase_mode::nist_800_88:
    return {pattern::zero};
  case erase_mode::bsi_gs:
    return {pattern::random, pattern::ones, pattern::random};
  case erase_mode::gutmann: {
    std::vector<pattern> ps;
    ps.reserve(35);
    for (int i = 0; i < 4; ++i) ps.push_back(pattern::random);
    for (int i = 0; i < 27; ++i) ps.push_back(pattern::gutmann_pattern);
    for (int i = 0; i < 4; ++i) ps.push_back(pattern::random);
    return ps;
  }
  case erase_mode::standard:
  default:
    return {pattern::random, pattern::zero};
  }
}
bool valid_options_impl(const erase_options &options) noexcept {
  switch (options.mode) {
  case erase_mode::fast:
  case erase_mode::standard:
  case erase_mode::strong:
  case erase_mode::dod_5220_22_m:
  case erase_mode::nist_800_88:
  case erase_mode::bsi_gs:
  case erase_mode::gutmann:
    break;
  default:
    return false;
  }
  switch (options.hardlinks) {
  case hardlink_policy::block:
  case hardlink_policy::delete_link_only:
  case hardlink_policy::overwrite_shared_content:
    break;
  default:
    return false;
  }
  constexpr std::size_t max_buffer_size = 64u * 1024u * 1024u;
  return options.rename_rounds <= 32u && options.buffer_size != 0u &&
         options.buffer_size <= max_buffer_size;
}
std::wstring pname(pattern p, std::size_t pass_index = 0) {
  switch (p) {
  case pattern::random:
    return L"Kryptographische Zufallsdaten";
  case pattern::zero:
    return L"Null-Pass (0x00)";
  case pattern::ones:
    return L"Einsen-Pass (0xFF)";
  case pattern::gutmann_pattern:
    return L"Gutmann-Muster (Durchgang " + std::to_wstring(pass_index + 1) + L")";
  default:
    return L"Überschreibung";
  }
}
std::uint64_t sadd(std::uint64_t a, std::uint64_t b) {
  auto m = (std::numeric_limits<std::uint64_t>::max)();
  return b > m - a ? m : a + b;
}
std::uint64_t smul(std::uint64_t a, std::uint64_t b) {
  auto m = (std::numeric_limits<std::uint64_t>::max)();
  return a && b > m / a ? m : a * b;
}

bool lock_non_reparse_ancestors(
    const std::filesystem::path &target,
    std::vector<unique_win_handle> &locks, DWORD &error) noexcept try {
  locks.clear();
  error = ERROR_SUCCESS;
  const auto parent = target.parent_path();
  auto current = parent.root_path();
  if (current.empty()) {
    error = ERROR_INVALID_NAME;
    return false;
  }
  for (const auto &component : parent.relative_path()) {
    if (component.empty() || component == L".")
      continue;
    if (component == L"..") {
      error = ERROR_INVALID_NAME;
      return false;
    }
    current /= component;
    unique_win_handle handle{CreateFileW(
        current.c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
    if (!handle) {
      error = GetLastError();
      return false;
    }
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    if (!GetFileInformationByHandleEx(handle.get(), FileAttributeTagInfo,
                                      &attributes, sizeof(attributes))) {
      error = GetLastError();
      return false;
    }
    if ((attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
      error = ERROR_DIRECTORY;
      return false;
    }
    if ((attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
      error = ERROR_REPARSE_TAG_INVALID;
      return false;
    }
    locks.push_back(std::move(handle));
  }
  return true;
} catch (...) {
  error = ERROR_NOT_ENOUGH_MEMORY;
  return false;
}
class hash256 {
  BCRYPT_ALG_HANDLE a_{nullptr};
  BCRYPT_HASH_HANDLE h_{nullptr};
  std::vector<std::byte> o_;
  ULONG n_{0};
  bool ok_{false};

public:
  hash256() noexcept {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD ol = 0, returned = 0;
    ULONG digest_length = 0;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM,
                                    nullptr, 0) <
        0)
      return;
    if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                          reinterpret_cast<PUCHAR>(&ol), sizeof(ol), &returned,
                          0) < 0 ||
        BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH,
                          reinterpret_cast<PUCHAR>(&digest_length),
                          sizeof(digest_length), &returned, 0) < 0) {
      BCryptCloseAlgorithmProvider(algorithm, 0);
      return;
    }
    std::vector<std::byte> object;
    try {
      object.resize(ol);
    } catch (...) {
      BCryptCloseAlgorithmProvider(algorithm, 0);
      return;
    }
    if (BCryptCreateHash(algorithm, &hash,
                         reinterpret_cast<PUCHAR>(object.data()), ol, nullptr,
                         0, 0) < 0) {
      BCryptCloseAlgorithmProvider(algorithm, 0);
      return;
    }
    a_ = algorithm;
    h_ = hash;
    o_ = std::move(object);
    n_ = digest_length;
    ok_ = true;
  }
  ~hash256() {
    if (h_)
      BCryptDestroyHash(h_);
    if (a_)
      BCryptCloseAlgorithmProvider(a_, 0);
  }
  bool valid() const { return ok_; }
  bool add(std::span<const std::byte> s) {
    if (!ok_ || s.size() > static_cast<std::size_t>(
                               (std::numeric_limits<ULONG>::max)()))
      return false;
    return s.empty() ||
           BCryptHashData(
               h_,
               const_cast<PUCHAR>(reinterpret_cast<const UCHAR *>(s.data())),
               static_cast<ULONG>(s.size()), 0) >= 0;
  }
  std::vector<std::byte> finish() noexcept {
    if (!ok_ || !h_)
      return {};
    std::vector<std::byte> d;
    try {
      d.resize(n_);
    } catch (...) {
      BCryptDestroyHash(h_);
      h_ = nullptr;
      ok_ = false;
      return {};
    }
    if (BCryptFinishHash(h_, reinterpret_cast<PUCHAR>(d.data()), n_, 0) < 0)
      d.clear();
    BCryptDestroyHash(h_);
    h_ = nullptr;
    ok_ = false;
    return d;
  }
};
void merge(erase_result &a, const erase_result &b) {
  a.bytes_written = sadd(a.bytes_written, b.bytes_written);
  a.files_deleted = sadd(a.files_deleted, b.files_deleted);
  a.directories_deleted = sadd(a.directories_deleted, b.directories_deleted);
  a.alternate_streams_overwritten =
      sadd(a.alternate_streams_overwritten, b.alternate_streams_overwritten);
  a.reparse_points_removed =
      sadd(a.reparse_points_removed, b.reparse_points_removed);
  a.hardlinks_blocked = sadd(a.hardlinks_blocked, b.hardlinks_blocked);
  constexpr std::size_t max_diagnostics = 256;
  for (const auto &warning : b.warnings) {
    if (a.warnings.size() >= max_diagnostics)
      break;
    a.warnings.push_back(warning);
  }
  for (const auto &owner : b.lock_owners) {
    if (a.lock_owners.size() >= max_diagnostics)
      break;
    a.lock_owners.push_back(owner);
  }
  if (!b.success)
    a.success = false;
  if (b.cancelled)
    a.cancelled = true;
  if (!a.win32_error)
    a.win32_error = b.win32_error;
}
DWORD attrs(const std::filesystem::path &p) {
  return GetFileAttributesW(p.c_str());
}
void clear_ro(const std::filesystem::path &p) {
  DWORD a = attrs(p);
  if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_READONLY))
    SetFileAttributesW(p.c_str(), a & ~FILE_ATTRIBUTE_READONLY);
}
bool del_link_name(const std::filesystem::path &p, DWORD &e,
                   DWORD &actual_attributes) {
  unique_win_handle h{CreateFileW(
      p.c_str(), DELETE | FILE_READ_ATTRIBUTES,
      FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
      OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
  if (!h) {
    e = GetLastError();
    return false;
  }
  FILE_ATTRIBUTE_TAG_INFO attributes{};
  if (!GetFileInformationByHandleEx(h.get(), FileAttributeTagInfo, &attributes,
                                    sizeof(attributes))) {
    e = GetLastError();
    return false;
  }
  if ((attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0) {
    e = ERROR_REPARSE_TAG_INVALID;
    return false;
  }
  actual_attributes = attributes.FileAttributes;
  FILE_DISPOSITION_INFO_EX i{};
  i.Flags = FILE_DISPOSITION_FLAG_DELETE |
            FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE;
  bool ok = SetFileInformationByHandle(h.get(), FileDispositionInfoEx, &i,
                                       sizeof(i)) != FALSE;
  if (!ok && (GetLastError() == ERROR_INVALID_PARAMETER ||
              GetLastError() == ERROR_NOT_SUPPORTED)) {
    FILE_DISPOSITION_INFO legacy{};
    legacy.DeleteFile = TRUE;
    ok = SetFileInformationByHandle(h.get(), FileDispositionInfo, &legacy,
                                    sizeof(legacy)) != FALSE;
  }
  e = ok ? 0 : GetLastError();
  return ok;
}
std::wstring rndname() {
  std::array<std::byte, 12> b{};
  fill_secure_random(b);
  constexpr wchar_t h[] = L"0123456789abcdef";
  std::wstring r = L".oblivion-";
  for (auto x : b) {
    auto v = std::to_integer<unsigned>(x);
    r.push_back(h[(v >> 4) & 15]);
    r.push_back(h[v & 15]);
  }
  return r;
}
HANDLE open_meta(const std::filesystem::path &p, DWORD &e) {
  HANDLE h =
      CreateFileW(p.c_str(), FILE_READ_ATTRIBUTES,
                  FILE_SHARE_READ | FILE_SHARE_WRITE,
                  nullptr, OPEN_EXISTING,
                  FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                  nullptr);
  if (h == INVALID_HANDLE_VALUE)
    e = GetLastError();
  return h;
}
HANDLE open_delete(const std::filesystem::path &p, DWORD &e) {
  HANDLE handle = CreateFileW(
      p.c_str(), FILE_READ_ATTRIBUTES | DELETE,
      FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  if (handle == INVALID_HANDLE_VALUE)
    e = GetLastError();
  return handle;
}
bool same_identity(const BY_HANDLE_FILE_INFORMATION &left,
                   const BY_HANDLE_FILE_INFORMATION &right) noexcept {
  return left.dwVolumeSerialNumber == right.dwVolumeSerialNumber &&
         left.nFileIndexHigh == right.nFileIndexHigh &&
         left.nFileIndexLow == right.nFileIndexLow;
}
HANDLE open_rw(const std::filesystem::path &p, DWORD &e,
               const bool allow_delete = false) {
  const DWORD access = GENERIC_READ | GENERIC_WRITE |
                       (allow_delete ? DELETE : 0u);
  HANDLE h = CreateFileW(p.c_str(), access,
                         FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH |
                             FILE_FLAG_SEQUENTIAL_SCAN |
                             FILE_FLAG_OPEN_REPARSE_POINT,
                         nullptr);
  if (h == INVALID_HANDLE_VALUE)
    e = GetLastError();
  return h;
}
bool rename_handle_once(HANDLE handle, std::filesystem::path &path) {
  const auto parent = path.parent_path();
  for (unsigned attempt = 0; attempt < 32; ++attempt) {
    try {
      auto candidate = parent / rndname();
      const auto name = candidate.wstring();
      constexpr auto prefix = offsetof(FILE_RENAME_INFO, FileName);
      if (name.size() >
              (std::numeric_limits<DWORD>::max)() / sizeof(wchar_t) ||
          name.size() >
              ((std::numeric_limits<std::size_t>::max)() - prefix) /
                  sizeof(wchar_t))
        return false;
      const auto name_bytes = name.size() * sizeof(wchar_t);
      std::vector<std::byte> storage(prefix + name_bytes);
      auto *information =
          reinterpret_cast<FILE_RENAME_INFO *>(storage.data());
      information->ReplaceIfExists = FALSE;
      information->RootDirectory = nullptr;
      information->FileNameLength = static_cast<DWORD>(name_bytes);
      std::memcpy(information->FileName, name.data(), name_bytes);
      if (SetFileInformationByHandle(
              handle, FileRenameInfo, information,
              static_cast<DWORD>(storage.size())) != FALSE) {
        path = std::move(candidate);
        return true;
      }
      const DWORD error = GetLastError();
      if (error != ERROR_ALREADY_EXISTS && error != ERROR_FILE_EXISTS)
        return false;
    } catch (...) {
      return false;
    }
  }
  return false;
}
void rename_secure_handle(HANDLE handle, std::filesystem::path &path,
                          const unsigned rounds, erase_result &result) {
  for (unsigned round = 0; round < rounds; ++round) {
    if (!rename_handle_once(handle, path)) {
      result.warnings.push_back(L"Metadaten-Umbenennung unvollständig: " +
                                path.wstring());
      return;
    }
  }
}
bool delete_handle(HANDLE handle, DWORD &error) {
  FILE_DISPOSITION_INFO_EX information{};
  information.Flags = FILE_DISPOSITION_FLAG_DELETE |
                      FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE;
  if (SetFileInformationByHandle(handle, FileDispositionInfoEx, &information,
                                 sizeof(information)) == FALSE) {
    error = GetLastError();
    if (error != ERROR_INVALID_PARAMETER && error != ERROR_NOT_SUPPORTED)
      return false;
    FILE_DISPOSITION_INFO legacy{};
    legacy.DeleteFile = TRUE;
    if (SetFileInformationByHandle(handle, FileDispositionInfo, &legacy,
                                   sizeof(legacy)) == FALSE) {
      error = GetLastError();
      return false;
    }
  }
  error = ERROR_SUCCESS;
  return true;
}
bool file_size(HANDLE h, std::uint64_t &size, DWORD &error) {
  LARGE_INTEGER s{};
  if (!GetFileSizeEx(h, &s)) {
    error = GetLastError();
    if (error == ERROR_SUCCESS)
      error = ERROR_INVALID_DATA;
    return false;
  }
  if (s.QuadPart < 0) {
    error = ERROR_INVALID_DATA;
    return false;
  }
  size = static_cast<std::uint64_t>(s.QuadPart);
  error = ERROR_SUCCESS;
  return true;
}
bool seek0(HANDLE h) {
  LARGE_INTEGER z{};
  return SetFilePointerEx(h, z, nullptr, FILE_BEGIN) != FALSE;
}
struct stream_scan_result {
  std::vector<stream_entry> entries;
  bool complete{false};
  DWORD error{ERROR_SUCCESS};
};
bool same_stream_set(const stream_scan_result &left,
                     const stream_scan_result &right) {
  if (left.entries.size() != right.entries.size())
    return false;
  std::vector<const stream_entry *> a, b;
  a.reserve(left.entries.size());
  b.reserve(right.entries.size());
  for (const auto &entry : left.entries)
    a.push_back(&entry);
  for (const auto &entry : right.entries)
    b.push_back(&entry);
  const auto less = [](const stream_entry *x, const stream_entry *y) {
    return CompareStringOrdinal(x->name.c_str(), -1, y->name.c_str(), -1,
                                TRUE) == CSTR_LESS_THAN;
  };
  std::sort(a.begin(), a.end(), less);
  std::sort(b.begin(), b.end(), less);
  for (std::size_t i = 0; i < a.size(); ++i) {
    if (CompareStringOrdinal(a[i]->name.c_str(), -1, b[i]->name.c_str(), -1,
                             TRUE) != CSTR_EQUAL ||
        a[i]->size != b[i]->size)
      return false;
  }
  return true;
}
stream_scan_result streams(const std::filesystem::path &p) {
  constexpr std::size_t max_stream_entries = 100000u;
  stream_scan_result result;
  std::vector<wchar_t> volume_root(32768, L'\0');
  DWORD filesystem_flags = 0;
  if (!GetVolumePathNameW(p.c_str(), volume_root.data(),
                          static_cast<DWORD>(volume_root.size())) ||
      !GetVolumeInformationW(volume_root.data(), nullptr, 0, nullptr, nullptr,
                             &filesystem_flags, nullptr, 0)) {
    result.error = GetLastError();
    return result;
  }
  if ((filesystem_flags & FILE_NAMED_STREAMS) == 0) {
    result.complete = true;
    return result;
  }
  WIN32_FIND_STREAM_DATA d{};
  HANDLE h = FindFirstStreamW(p.c_str(), FindStreamInfoStandard, &d, 0);
  if (h == INVALID_HANDLE_VALUE) {
    result.error = GetLastError();
    result.complete = result.error == ERROR_HANDLE_EOF;
    return result;
  }
  unique_find_handle find_guard{h};
  for (;;) {
    try {
      std::wstring n = d.cStreamName;
      if (!n.empty() && n != L"::$DATA") {
        if (result.entries.size() >= max_stream_entries) {
          result.error = ERROR_TOO_MANY_NAMES;
          break;
        }
        result.entries.push_back(
            {n, d.StreamSize.QuadPart > 0
                    ? static_cast<std::uint64_t>(d.StreamSize.QuadPart)
                    : 0});
      }
    } catch (...) {
      result.error = ERROR_NOT_ENOUGH_MEMORY;
      break;
    }
    if (!FindNextStreamW(h, &d)) {
      result.error = GetLastError();
      result.complete = result.error == ERROR_HANDLE_EOF;
      break;
    }
  }
  return result;
}
bool verify_byte(HANDLE h, secure_buffer &b, std::uint64_t size, std::byte expected_val) {
  if (!seek0(h))
    return false;
  std::uint64_t done = 0;
  while (done < size) {
    DWORD want = static_cast<DWORD>(
              (std::min)(static_cast<std::uint64_t>(b.size()), size - done)),
          got = 0;
    if (!ReadFile(h, b.data(), want, &got, nullptr) || got != want)
      return false;
    if (std::ranges::any_of(std::span{b.data(), static_cast<std::size_t>(got)},
                            [expected_val](std::byte x) { return x != expected_val; }))
      return false;
    done += got;
  }
  return true;
}
bool verify_zero(HANDLE h, secure_buffer &b, std::uint64_t size) {
  return verify_byte(h, b, size, std::byte{0});
}
bool verify_hash(HANDLE h, secure_buffer &b, std::uint64_t size,
                 const std::vector<std::byte> &expected) {
  if (expected.empty() || !seek0(h))
    return false;
  hash256 x;
  if (!x.valid())
    return false;
  std::uint64_t done = 0;
  while (done < size) {
    DWORD want = static_cast<DWORD>(
              (std::min)(static_cast<std::uint64_t>(b.size()), size - done)),
          got = 0;
    if (!ReadFile(h, b.data(), want, &got, nullptr) || got != want ||
        !x.add(std::span<const std::byte>{b.data(),
                                          static_cast<std::size_t>(got)}))
      return false;
    done += got;
  }
  return x.finish() == expected;
}
bool progress(const progress_callback &cb, const std::filesystem::path &p,
              const std::wstring &phase, pattern pat, std::size_t pi,
              std::size_t pc, std::uint64_t done, std::uint64_t total,
              std::uint64_t bytes) noexcept try {
  if (!cb)
    return true;
  progress_info i;
  i.current = p;
  i.phase = phase;
  i.pass_name = pname(pat, pi);
  i.pass_index = static_cast<std::uint32_t>(pi + 1);
  i.pass_count = static_cast<std::uint32_t>(pc);
  i.completed = done;
  i.total = total;
  i.bytes_written_total = bytes;
  return cb(i);
} catch (...) {
  return false;
}
bool overwrite(const std::filesystem::path &display, HANDLE h,
               std::uint64_t size, const std::wstring &phase,
               const erase_options &o, erase_result &r,
               const progress_callback &cb) {
  auto ps = passes(o.mode);
  auto bs =
      (std::min)((std::max)(o.buffer_size, std::size_t{65536}),
                 static_cast<std::size_t>((std::numeric_limits<DWORD>::max)()));
  secure_buffer b(bs);
  if (!b.valid()) {
    r.win32_error = ERROR_NOT_ENOUGH_MEMORY;
    r.message = L"Sicherer Arbeitspuffer konnte nicht reserviert werden.";
    return false;
  }
  std::vector<std::byte> last_digest;
  auto total = smul(size, ps.size());
  for (std::size_t pi = 0; pi < ps.size(); ++pi) {
    if (!seek0(h)) {
      r.win32_error = GetLastError();
      r.message = L"Dateizeiger konnte nicht zurückgesetzt werden.";
      return false;
    }
    bool hash_last =
        o.verify && pi + 1 == ps.size() && ps[pi] == pattern::random;
    hash256 expected;
    if (hash_last && !expected.valid()) {
      r.win32_error = ERROR_NOT_SUPPORTED;
      r.message = L"SHA-256 konnte nicht initialisiert werden.";
      return false;
    }
    std::uint64_t wtot = 0;
    while (wtot < size) {
      DWORD n = static_cast<DWORD>(
          (std::min)(static_cast<std::uint64_t>(b.size()), size - wtot));
      if (ps[pi] == pattern::random) {
        if (!try_fill_secure_random(std::span{b.data(), n})) {
          r.win32_error = ERROR_GEN_FAILURE;
          r.message =
              L"Kryptographische Zufallsdaten konnten nicht erzeugt werden.";
          return false;
        }
      } else if (ps[pi] == pattern::ones) {
        std::fill_n(b.data(), n, std::byte{0xFF});
      } else if (ps[pi] == pattern::gutmann_pattern) {
        const auto &pat = gutmann_bytes[pi >= 4 && pi < 31 ? pi - 4 : 0];
        for (DWORD j = 0; j < n; ++j) {
          b.data()[j] = static_cast<std::byte>(pat[j % 3]);
        }
      } else {
        std::fill_n(b.data(), n, std::byte{0});
      }
      if (hash_last && !expected.add(std::span<const std::byte>{b.data(), n})) {
        r.win32_error = ERROR_CRC;
        r.message = L"SHA-256 Berechnung fehlgeschlagen.";
        return false;
      }
      DWORD w = 0;
      if (!WriteFile(h, b.data(), n, &w, nullptr) || w != n) {
        const DWORD write_error = GetLastError();
        r.win32_error = write_error ? write_error : ERROR_WRITE_FAULT;
        r.message = L"Fehler beim Überschreiben.";
        return false;
      }
      wtot += w;
      r.bytes_written = sadd(r.bytes_written, w);
      if (!progress(cb, display, phase, ps[pi], pi, ps.size(),
                    sadd(smul(size, pi), wtot), total, r.bytes_written)) {
        r.cancelled = true;
        r.message = L"Abgebrochen; aktuelles Objekt wurde nicht gelöscht.";
        return false;
      }
    }
    if (!FlushFileBuffers(h)) {
      r.win32_error = GetLastError();
      if (r.win32_error == ERROR_SUCCESS)
        r.win32_error = ERROR_WRITE_FAULT;
      r.message = L"Datenträger-Flush fehlgeschlagen; Objekt wird nicht gelöscht: " +
                  display.wstring();
      return false;
    }
    if (hash_last) {
      last_digest = expected.finish();
      if (last_digest.empty()) {
        r.message = L"SHA-256 Abschluss fehlgeschlagen.";
        r.win32_error = ERROR_CRC;
        return false;
      }
    }
  }
  if (o.verify && size && !ps.empty()) {
    bool ok = false;
    if (ps.back() == pattern::zero) {
      ok = verify_zero(h, b, size);
    } else if (ps.back() == pattern::ones) {
      ok = verify_byte(h, b, size, std::byte{0xFF});
    } else {
      ok = verify_hash(h, b, size, last_digest);
    }
    if (!ok) {
      r.message = L"Readback-Verifikation des finalen Passes fehlgeschlagen.";
      r.win32_error = ERROR_CRC;
      return false;
    }
  }
  return true;
}
bool hardlink_safe(const std::filesystem::path &f, std::wstring &reason) {
  std::vector<wchar_t> vr(32768, L'\0');
  if (!GetVolumePathNameW(f.c_str(), vr.data(),
                          static_cast<DWORD>(vr.size()))) {
    reason = L"Volume-Wurzel nicht bestimmbar.";
    return false;
  }
  std::wstring root = vr.data();
  if (root.size() != 3 || root[1] != L':') {
    reason = L"Shared-Overwrite auf Ordner-Mount-Volumes blockiert.";
    return false;
  }
  std::vector<wchar_t> b(32768);
  DWORD n = static_cast<DWORD>(b.size());
  HANDLE h = FindFirstFileNameW(f.c_str(), 0, &n, b.data());
  if (h == INVALID_HANDLE_VALUE) {
    reason = L"Hardlink-Namensmenge nicht ermittelbar.";
    return false;
  }
  unique_find_handle find_guard{h};
  path_validator v;
  bool ok = true;
  do {
    auto c = std::filesystem::path{root} /
             std::filesystem::path{b.data()}.relative_path();
    auto x = v.validate(c);
    if (!x.allowed) {
      reason = L"Weiterer Hardlink liegt in geschütztem Pfad: " + c.wstring();
      ok = false;
      break;
    }
    n = static_cast<DWORD>(b.size());
  } while (FindNextFileNameW(h, &n, b.data()));
  DWORD e = GetLastError();
  return ok && e == ERROR_HANDLE_EOF;
}
erase_result erase_file(const std::filesystem::path &input,
                        const erase_options &o, const progress_callback &cb) {
  erase_result r;
  try {
  auto f = input;
  DWORD a = attrs(f);
  if (a == INVALID_FILE_ATTRIBUTES) {
    r.win32_error = GetLastError();
    r.message = L"Dateiattribute nicht lesbar.";
    return r;
  }
  if (a & FILE_ATTRIBUTE_REPARSE_POINT) {
    DWORD delete_error = ERROR_SUCCESS;
    DWORD actual_attributes = 0;
    const bool ok = del_link_name(f, delete_error, actual_attributes);
    r.success = ok;
    r.reparse_points_removed = ok ? 1u : 0u;
    r.files_deleted =
        (ok && !(actual_attributes & FILE_ATTRIBUTE_DIRECTORY)) ? 1u : 0u;
    r.directories_deleted =
        (ok && (actual_attributes & FILE_ATTRIBUTE_DIRECTORY)) ? 1u : 0u;
    r.win32_error = delete_error;
    r.message = ok ? L"Reparse Point entfernt, ohne Ziel zu traversieren."
                   : L"Reparse Point konnte nicht entfernt werden.";
    return r;
  }
  if (a & FILE_ATTRIBUTE_SPARSE_FILE)
    r.warnings.push_back(L"Sparse-Datei: physische Historie nicht garantiert.");
  if (a & FILE_ATTRIBUTE_COMPRESSED)
    r.warnings.push_back(L"NTFS-Komprimierung erkannt.");
  if (a & FILE_ATTRIBUTE_ENCRYPTED)
    r.warnings.push_back(L"EFS erkannt.");
  DWORD e = 0;
  unique_win_handle h{open_meta(f, e)};
  if (!h) {
    r.win32_error = e;
    r.message = L"Datei konnte nicht geöffnet werden.";
    if (e == ERROR_SHARING_VIOLATION || e == ERROR_LOCK_VIOLATION ||
        e == ERROR_ACCESS_DENIED)
      r.lock_owners = diagnose_lock_owners(f);
    return r;
  }
  BY_HANDLE_FILE_INFORMATION fi{};
  if (!GetFileInformationByHandle(h.get(), &fi)) {
    r.win32_error = GetLastError();
    r.message = L"Dateiidentität konnte nicht geprüft werden.";
    return r;
  }
  if (fi.nNumberOfLinks > 1) {
    if (o.hardlinks == hardlink_policy::block) {
      h.reset();
      r.hardlinks_blocked = 1;
      r.message = L"Hardlink erkannt; Inhaltsüberschreibung blockiert.";
      return r;
    }
    if (o.hardlinks == hardlink_policy::delete_link_only) {
      h.reset();
      h.reset(open_delete(f, e));
      BY_HANDLE_FILE_INFORMATION delete_information{};
      if (!h) {
        r.win32_error = e;
        r.message = L"Hardlink konnte zum Entfernen nicht geöffnet werden.";
        return r;
      }
      if (!GetFileInformationByHandle(h.get(), &delete_information)) {
        r.win32_error = GetLastError();
        r.message = L"Hardlink-Identität konnte vor dem Entfernen nicht "
                    L"geprüft werden.";
        return r;
      }
      if (!same_identity(fi, delete_information)) {
        r.win32_error = ERROR_FILE_INVALID;
        r.message = L"Hardlink-Identität hat sich vor dem Entfernen geändert.";
        return r;
      }
      if (o.rename_before_delete)
        rename_secure_handle(h.get(), f, o.rename_rounds, r);
      DWORD de = 0;
      if (!delete_handle(h.get(), de)) {
        r.win32_error = de;
        r.message = L"Hardlink-Name konnte nicht entfernt werden.";
        return r;
      }
      h.reset();
      r.success = true;
      r.files_deleted = 1;
      r.message = L"Nur ausgewählter Hardlink-Name entfernt; gemeinsamer "
                  L"Inhalt blieb unverändert.";
      return r;
    }
    std::wstring why;
    if (!hardlink_safe(f, why)) {
      h.reset();
      r.hardlinks_blocked = 1;
      r.message = L"Shared-Hardlink-Overwrite durch Schutzschicht blockiert.";
      r.warnings.push_back(std::move(why));
      return r;
    }
    r.warnings.push_back(
        L"Shared-Hardlink-Inhalt wird überschrieben; betrifft alle Hardlinks.");
  }
  clear_ro(f);
  stream_scan_result initial_streams;
  if (o.erase_alternate_streams) {
    initial_streams = streams(f);
    if (!initial_streams.complete) {
      r.win32_error = initial_streams.error;
      r.message = L"Alternate Data Streams konnten nicht vollständig "
                  L"aufgezählt werden; Datei wird nicht gelöscht.";
      return r;
    }
    for (const auto &s : initial_streams.entries) {
      auto sp = std::filesystem::path{f.wstring() + s.name};
      DWORD se = 0;
      unique_win_handle sh{open_rw(sp, se)};
      if (!sh) {
        r.win32_error = se;
        r.message = L"ADS konnte nicht geöffnet werden: " + s.name;
        return r;
      }
      std::uint64_t stream_size = 0;
      if (!file_size(sh.get(), stream_size, se)) {
        r.win32_error = se;
        r.message = L"ADS-Größe konnte nicht bestimmt werden: " + s.name;
        return r;
      }
      bool ok = overwrite(sp, sh.get(), stream_size,
                          L"Alternate Data Stream", o, r, cb);
      if (!ok)
        return r;
      ++r.alternate_streams_overwritten;
    }
  }
  e = 0;
  h.reset();
  h.reset(open_rw(f, e, true));
  if (!h) {
    r.win32_error = e;
    r.message = L"Hauptdatenstrom konnte nicht geöffnet werden.";
    r.lock_owners = diagnose_lock_owners(f);
    return r;
  }
  BY_HANDLE_FILE_INFORMATION current_information{};
  if (!GetFileInformationByHandle(h.get(), &current_information)) {
    r.win32_error = GetLastError();
    r.message = L"Dateiidentität konnte vor dem Überschreiben nicht erneut "
                L"geprüft werden.";
    return r;
  }
  if (!same_identity(fi, current_information)) {
    r.win32_error = ERROR_FILE_INVALID;
    r.message = L"Dateiidentität hat sich während der Verarbeitung geändert; "
                L"Hauptdatenstrom wird nicht verändert oder gelöscht.";
    return r;
  }
  if (current_information.nNumberOfLinks > 1) {
    if (o.hardlinks == hardlink_policy::block) {
      r.hardlinks_blocked = 1;
      r.message = L"Hardlink wurde bei der finalen Identitätsprüfung erkannt; "
                  L"Inhaltsüberschreibung blockiert.";
      return r;
    }
    if (o.hardlinks == hardlink_policy::delete_link_only) {
      if (o.rename_before_delete)
        rename_secure_handle(h.get(), f, o.rename_rounds, r);
      DWORD delete_error = ERROR_SUCCESS;
      if (!delete_handle(h.get(), delete_error)) {
        r.win32_error = delete_error;
        r.message = L"Hardlink-Name konnte nicht entfernt werden.";
        return r;
      }
      h.reset();
      r.success = true;
      r.files_deleted = 1;
      r.message = L"Nur ausgewählter Hardlink-Name entfernt; gemeinsamer "
                  L"Inhalt blieb unverändert.";
      return r;
    }
    std::wstring why;
    if (!hardlink_safe(f, why)) {
      r.hardlinks_blocked = 1;
      r.message = L"Shared-Hardlink-Overwrite bei der finalen "
                  L"Identitätsprüfung blockiert.";
      r.warnings.push_back(std::move(why));
      return r;
    }
  }
  if (o.erase_alternate_streams) {
    const auto final_streams = streams(f);
    if (!final_streams.complete) {
      r.win32_error = final_streams.error;
      r.message = L"Alternate Data Streams konnten unmittelbar vor dem "
                  L"Hauptstrom nicht erneut vollständig geprüft werden; "
                  L"Datei wird nicht gelöscht.";
      return r;
    }
    if (!same_stream_set(initial_streams, final_streams)) {
      r.win32_error = ERROR_FILE_INVALID;
      r.message = L"Die Menge oder Größe der Alternate Data Streams hat sich "
                  L"während der Verarbeitung geändert; Hauptdatenstrom wird "
                  L"nicht überschrieben oder gelöscht.";
      return r;
    }
  }
  std::uint64_t sz = 0;
  if (!file_size(h.get(), sz, e)) {
    r.win32_error = e;
    r.message = L"Dateigröße konnte nicht zuverlässig bestimmt werden.";
    return r;
  }
  bool ok = overwrite(f, h.get(), sz, L"Hauptdatenstrom", o, r, cb);
  if (!ok)
    return r;
  if (o.rename_before_delete)
    rename_secure_handle(h.get(), f, o.rename_rounds, r);
  DWORD delete_error = ERROR_SUCCESS;
  if (!delete_handle(h.get(), delete_error)) {
    r.win32_error = delete_error;
    r.message = L"Überschrieben, aber Löschen fehlgeschlagen.";
    return r;
  }
  h.reset();
  r.success = true;
  r.files_deleted = 1;
  r.message = L"Datei und erkannte Datenströme verarbeitet und gelöscht.";
  return r;
  } catch (const std::bad_alloc &) {
    r.success = false;
    r.win32_error = ERROR_NOT_ENOUGH_MEMORY;
    return r;
  } catch (...) {
    r.success = false;
    r.win32_error = ERROR_UNHANDLED_EXCEPTION;
    return r;
  }
}
erase_result erase_dir(const std::filesystem::path &d, const erase_options &o,
                        const progress_callback &cb,
                        const std::size_t depth = 0) {
  erase_result a;
  a.success = true;
  try {
  constexpr std::size_t max_directory_depth = 256;
  if (depth > max_directory_depth) {
    a.success = false;
    a.win32_error = ERROR_DIRECTORY;
    a.message = L"Maximale sichere Verzeichnistiefe überschritten; "
                L"Verzeichnis wird nicht weiter verarbeitet.";
    return a;
  }
  unique_win_handle directory_handle{CreateFileW(
      d.c_str(), FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | DELETE,
      FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
  if (!directory_handle) {
    a.success = false;
    a.win32_error = GetLastError();
    a.message = L"Verzeichnis konnte nicht sicher gesperrt werden.";
    return a;
  }
  FILE_ATTRIBUTE_TAG_INFO directory_attributes{};
  if (!GetFileInformationByHandleEx(
          directory_handle.get(), FileAttributeTagInfo, &directory_attributes,
          sizeof(directory_attributes))) {
    a.success = false;
    a.win32_error = GetLastError();
    a.message = L"Verzeichnisattribute konnten nicht handlegebunden geprüft "
                L"werden.";
    return a;
  }
  if ((directory_attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) !=
      0) {
    DWORD delete_error = ERROR_SUCCESS;
    const bool deleted = delete_handle(directory_handle.get(), delete_error);
    directory_handle.reset();
    a.success = deleted;
    a.win32_error = delete_error;
    a.reparse_points_removed = deleted ? 1u : 0u;
    a.directories_deleted = deleted ? 1u : 0u;
    a.message = deleted
                    ? L"Verzeichnis-Reparse-Point ohne Traversierung entfernt."
                    : L"Verzeichnis-Reparse-Point konnte nicht entfernt werden.";
    return a;
  }
  if ((directory_attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
    a.success = false;
    a.win32_error = ERROR_DIRECTORY;
    a.message = L"Ziel ist kein Verzeichnis mehr.";
    return a;
  }
  std::error_code ec;
  std::filesystem::directory_iterator it(d, ec), end;
  if (ec) {
    a.success = false;
    a.win32_error = static_cast<DWORD>(ec.value());
    if (a.win32_error == ERROR_SUCCESS)
      a.win32_error = ERROR_CANT_ACCESS_FILE;
    a.message = L"Verzeichnis nicht enumerierbar.";
    return a;
  }
  while (it != end) {
    auto p = it->path();
    DWORD ca = attrs(p);
    if (ca == INVALID_FILE_ATTRIBUTES) {
      a.success = false;
      if (a.win32_error == ERROR_SUCCESS)
        a.win32_error = GetLastError();
    } else {
      std::uint64_t base = a.bytes_written;
      progress_callback child;
      if (cb)
        child = [cb, base](const progress_info &i) {
          auto x = i;
          x.bytes_written_total = sadd(base, i.bytes_written_total);
          return cb(x);
        };
      erase_result r = ((ca & FILE_ATTRIBUTE_DIRECTORY) &&
                        !(ca & FILE_ATTRIBUTE_REPARSE_POINT))
                           ? erase_dir(p, o, child, depth + 1u)
                           : erase_file(p, o, child);
      merge(a, r);
      if (r.cancelled) {
        a.message = L"Abgebrochen.";
        return a;
      }
    }
    it.increment(ec);
    if (ec) {
      a.success = false;
      if (a.win32_error == ERROR_SUCCESS)
        a.win32_error = static_cast<DWORD>(ec.value());
      a.warnings.push_back(L"Enumerierungsfehler: " + d.wstring());
      break;
    }
  }
  if (!a.success) {
    a.message = L"Verzeichnis nur teilweise bearbeitet; Name beibehalten.";
    return a;
  }
  std::error_code empty_ec;
  if (!std::filesystem::is_empty(d, empty_ec) || empty_ec) {
    a.success = false;
    a.win32_error = empty_ec ? static_cast<DWORD>(empty_ec.value())
                             : ERROR_DIR_NOT_EMPTY;
    a.message =
        L"Verzeichnis ist nach der Bearbeitung nicht leer; Name beibehalten.";
    return a;
  }
  auto m = d;
  if (o.rename_before_delete)
    rename_secure_handle(directory_handle.get(), m, o.rename_rounds, a);
  DWORD delete_error = ERROR_SUCCESS;
  if (!delete_handle(directory_handle.get(), delete_error)) {
    a.success = false;
    a.win32_error = delete_error;
    a.message = L"Verzeichnis konnte nicht entfernt werden.";
  } else {
    directory_handle.reset();
    ++a.directories_deleted;
    a.message = L"Verzeichnis vollständig verarbeitet und entfernt.";
  }
  return a;
  } catch (const std::bad_alloc &) {
    a.success = false;
    a.win32_error = ERROR_NOT_ENOUGH_MEMORY;
    return a;
  } catch (...) {
    a.success = false;
    a.win32_error = ERROR_UNHANDLED_EXCEPTION;
    return a;
  }
}
} // namespace
bool valid_erase_options(const erase_options &options) noexcept {
  return valid_options_impl(options);
}

erase_result erase_engine::erase(const std::filesystem::path &t,
                                  const erase_options &o,
                                  const progress_callback &cb) const noexcept {
  return erase_impl(t, o, cb, false);
}

erase_result
erase_engine::erase_recycle_bin_item(const std::filesystem::path &t,
                                     const erase_options &o,
                                     const progress_callback &cb) const noexcept {
  return erase_impl(t, o, cb, true);
}

erase_result erase_engine::erase_impl(const std::filesystem::path &t,
                                      const erase_options &o,
                                      const progress_callback &cb,
                                      bool allow_recycle_bin_items) const
    noexcept try {
  if (!valid_erase_options(o)) {
    erase_result result;
    result.win32_error = ERROR_INVALID_PARAMETER;
    result.message = L"Ungültige oder unbeschränkte Engine-Optionen.";
    return result;
  }
  const auto validation =
      path_validator{false, allow_recycle_bin_items}.validate(t);
  if (!validation.allowed) {
    erase_result r;
    r.win32_error = ERROR_ACCESS_DENIED;
    r.message = L"Engine-Schutz hat das Ziel blockiert: " + validation.reason;
    return r;
  }
  const auto &target = validation.normalized;
  std::vector<unique_win_handle> ancestor_locks;
  DWORD ancestor_error = ERROR_SUCCESS;
  if (!lock_non_reparse_ancestors(target, ancestor_locks, ancestor_error)) {
    erase_result r;
    r.win32_error = ancestor_error;
    r.message = L"Zielvorfahren konnten nicht race-sicher als echte "
                L"Verzeichnisse gesperrt werden.";
    return r;
  }
  DWORD a = attrs(target);
  if (a == INVALID_FILE_ATTRIBUTES) {
    erase_result r;
    r.win32_error = GetLastError();
    r.message = L"Ziel nicht zugreifbar.";
    return r;
  }
  return ((a & FILE_ATTRIBUTE_DIRECTORY) && !(a & FILE_ATTRIBUTE_REPARSE_POINT))
             ? erase_dir(target, o, cb)
             : erase_file(target, o, cb);
} catch (const std::bad_alloc &) {
  erase_result result;
  result.win32_error = ERROR_NOT_ENOUGH_MEMORY;
  result.message = L"Nicht genügend Arbeitsspeicher.";
  return result;
} catch (...) {
  erase_result result;
  result.win32_error = ERROR_UNHANDLED_EXCEPTION;
  result.message = L"Unerwarteter interner Engine-Fehler.";
  return result;
}
} // namespace oblivion
