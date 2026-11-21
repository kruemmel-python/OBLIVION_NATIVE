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
#include <filesystem>
#include <limits>
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
class hash256 {
  BCRYPT_ALG_HANDLE a_{nullptr};
  BCRYPT_HASH_HANDLE h_{nullptr};
  std::vector<std::byte> o_;
  ULONG n_{0};
  bool ok_{false};

public:
  hash256() {
    DWORD ol = 0, n = 0;
    if (BCryptOpenAlgorithmProvider(&a_, BCRYPT_SHA256_ALGORITHM, nullptr, 0) <
        0)
      return;
    if (BCryptGetProperty(a_, BCRYPT_OBJECT_LENGTH,
                          reinterpret_cast<PUCHAR>(&ol), sizeof(ol), &n,
                          0) < 0 ||
        BCryptGetProperty(a_, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&n_),
                          sizeof(n_), &n, 0) < 0)
      return;
    o_.resize(ol);
    if (BCryptCreateHash(a_, &h_, reinterpret_cast<PUCHAR>(o_.data()), ol,
                         nullptr, 0, 0) < 0)
      return;
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
  std::vector<std::byte> finish() {
    if (!ok_ || !h_)
      return {};
    std::vector<std::byte> d(n_);
    if (BCryptFinishHash(h_, reinterpret_cast<PUCHAR>(d.data()), n_, 0) < 0)
      d.clear();
    BCryptDestroyHash(h_);
    h_ = nullptr;
    ok_ = false;
    return d;
  }
};
void merge(erase_result &a, const erase_result &b) {
  a.bytes_written += b.bytes_written;
  a.files_deleted += b.files_deleted;
  a.directories_deleted += b.directories_deleted;
  a.alternate_streams_overwritten += b.alternate_streams_overwritten;
  a.reparse_points_removed += b.reparse_points_removed;
  a.hardlinks_blocked += b.hardlinks_blocked;
  a.warnings.insert(a.warnings.end(), b.warnings.begin(), b.warnings.end());
  a.lock_owners.insert(a.lock_owners.end(), b.lock_owners.begin(),
                       b.lock_owners.end());
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
bool del_file(const std::filesystem::path &p) {
  clear_ro(p);
  return DeleteFileW(p.c_str()) != FALSE;
}
bool del_dir(const std::filesystem::path &p) {
  clear_ro(p);
  return RemoveDirectoryW(p.c_str()) != FALSE;
}
bool del_link_name(const std::filesystem::path &p, DWORD &e) {
  unique_win_handle h{CreateFileW(
      p.c_str(), DELETE | FILE_READ_ATTRIBUTES,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
      OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
  if (!h) {
    e = GetLastError();
    return false;
  }
  FILE_DISPOSITION_INFO_EX i{};
  i.Flags = FILE_DISPOSITION_FLAG_DELETE |
            FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE;
  bool ok = SetFileInformationByHandle(h.get(), FileDispositionInfoEx, &i,
                                       sizeof(i)) != FALSE;
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
bool rename_once(std::filesystem::path &p) {
  auto par = p.parent_path();
  for (unsigned i = 0; i < 32; ++i) {
    std::filesystem::path c;
    try {
      c = par / rndname();
    } catch (const std::exception &) {
      return false;
    }
    std::error_code ec;
    if (std::filesystem::exists(c, ec))
      continue;
    std::filesystem::rename(p, c, ec);
    if (!ec) {
      p = c;
      return true;
    }
  }
  return false;
}
void rename_secure(std::filesystem::path &p, unsigned rounds, erase_result &r) {
  for (unsigned i = 0; i < rounds; ++i)
    if (!rename_once(p)) {
      r.warnings.push_back(L"Metadaten-Umbenennung unvollständig: " +
                           p.wstring());
      break;
    }
}
HANDLE open_meta(const std::filesystem::path &p, DWORD &e) {
  HANDLE h =
      CreateFileW(p.c_str(), FILE_READ_ATTRIBUTES,
                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                  nullptr, OPEN_EXISTING,
                  FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                  nullptr);
  if (h == INVALID_HANDLE_VALUE)
    e = GetLastError();
  return h;
}
HANDLE open_rw(const std::filesystem::path &p, DWORD &e) {
  HANDLE h = CreateFileW(p.c_str(), GENERIC_READ | GENERIC_WRITE,
                         FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH |
                             FILE_FLAG_SEQUENTIAL_SCAN |
                             FILE_FLAG_OPEN_REPARSE_POINT,
                         nullptr);
  if (h == INVALID_HANDLE_VALUE)
    e = GetLastError();
  return h;
}
std::uint64_t fsize(HANDLE h) {
  LARGE_INTEGER s{};
  return GetFileSizeEx(h, &s) && s.QuadPart >= 0
             ? static_cast<std::uint64_t>(s.QuadPart)
             : 0;
}
bool seek0(HANDLE h) {
  LARGE_INTEGER z{};
  return SetFilePointerEx(h, z, nullptr, FILE_BEGIN) != FALSE;
}
std::vector<stream_entry> streams(const std::filesystem::path &p) {
  std::vector<stream_entry> r;
  WIN32_FIND_STREAM_DATA d{};
  HANDLE h = FindFirstStreamW(p.c_str(), FindStreamInfoStandard, &d, 0);
  if (h == INVALID_HANDLE_VALUE)
    return r;
  do {
    std::wstring n = d.cStreamName;
    if (!n.empty() && n != L"::$DATA")
      r.push_back({n, d.StreamSize.QuadPart > 0
                          ? static_cast<std::uint64_t>(d.StreamSize.QuadPart)
                          : 0});
  } while (FindNextStreamW(h, &d));
  FindClose(h);
  return r;
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
              std::uint64_t bytes) {
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
  std::array<wchar_t, 32768> vr{};
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
  FindClose(h);
  return ok && e == ERROR_HANDLE_EOF;
}
erase_result erase_file(const std::filesystem::path &input,
                        const erase_options &o, const progress_callback &cb) {
  erase_result r;
  auto f = input;
  DWORD a = attrs(f);
  if (a == INVALID_FILE_ATTRIBUTES) {
    r.win32_error = GetLastError();
    r.message = L"Dateiattribute nicht lesbar.";
    return r;
  }
  if (a & FILE_ATTRIBUTE_REPARSE_POINT) {
    bool ok = (a & FILE_ATTRIBUTE_DIRECTORY) ? del_dir(f) : del_file(f);
    r.success = ok;
    r.reparse_points_removed = ok ? 1u : 0u;
    r.files_deleted = (ok && !(a & FILE_ATTRIBUTE_DIRECTORY)) ? 1u : 0u;
    r.directories_deleted = (ok && (a & FILE_ATTRIBUTE_DIRECTORY)) ? 1u : 0u;
    r.win32_error = ok ? 0 : GetLastError();
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
  if (GetFileInformationByHandle(h.get(), &fi) && fi.nNumberOfLinks > 1) {
    if (o.hardlinks == hardlink_policy::block) {
      h.reset();
      r.hardlinks_blocked = 1;
      r.message = L"Hardlink erkannt; Inhaltsüberschreibung blockiert.";
      return r;
    }
    if (o.hardlinks == hardlink_policy::delete_link_only) {
      h.reset();
      if (o.rename_before_delete)
        rename_secure(f, o.rename_rounds, r);
      DWORD de = 0;
      if (!del_link_name(f, de)) {
        r.win32_error = de;
        r.message = L"Hardlink-Name konnte nicht entfernt werden.";
        return r;
      }
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
  h.reset();
  clear_ro(f);
  if (o.erase_alternate_streams)
    for (const auto &s : streams(f)) {
      auto sp = std::filesystem::path{f.wstring() + s.name};
      DWORD se = 0;
      unique_win_handle sh{open_rw(sp, se)};
      if (!sh) {
        r.win32_error = se;
        r.message = L"ADS konnte nicht geöffnet werden: " + s.name;
        return r;
      }
      bool ok = overwrite(sp, sh.get(), s.size, L"Alternate Data Stream", o,
                          r, cb);
      if (!ok)
        return r;
      ++r.alternate_streams_overwritten;
    }
  e = 0;
  h.reset(open_rw(f, e));
  if (!h) {
    r.win32_error = e;
    r.message = L"Hauptdatenstrom konnte nicht geöffnet werden.";
    r.lock_owners = diagnose_lock_owners(f);
    return r;
  }
  auto sz = fsize(h.get());
  bool ok = overwrite(f, h.get(), sz, L"Hauptdatenstrom", o, r, cb);
  h.reset();
  if (!ok)
    return r;
  if (o.rename_before_delete)
    rename_secure(f, o.rename_rounds, r);
  if (!del_file(f)) {
    r.win32_error = GetLastError();
    r.message = L"Überschrieben, aber Löschen fehlgeschlagen.";
    return r;
  }
  r.success = true;
  r.files_deleted = 1;
  r.message = L"Datei und erkannte Datenströme verarbeitet und gelöscht.";
  return r;
}
erase_result erase_dir(const std::filesystem::path &d, const erase_options &o,
                       const progress_callback &cb) {
  erase_result a;
  a.success = true;
  DWORD at = attrs(d);
  if (at == INVALID_FILE_ATTRIBUTES) {
    a.success = false;
    a.win32_error = GetLastError();
    a.message = L"Verzeichnisattribute nicht lesbar.";
    return a;
  }
  if (at & FILE_ATTRIBUTE_REPARSE_POINT)
    return erase_file(d, o, cb);
  std::error_code ec;
  std::filesystem::directory_iterator it(d, ec), end;
  if (ec) {
    a.success = false;
    a.message = L"Verzeichnis nicht enumerierbar.";
    return a;
  }
  while (it != end) {
    auto p = it->path();
    DWORD ca = attrs(p);
    if (ca == INVALID_FILE_ATTRIBUTES) {
      a.success = false;
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
                           ? erase_dir(p, o, child)
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
    a.message =
        L"Verzeichnis ist nach der Bearbeitung nicht leer; Name beibehalten.";
    return a;
  }
  auto m = d;
  if (o.rename_before_delete)
    rename_secure(m, o.rename_rounds, a);
  if (!del_dir(m)) {
    a.success = false;
    a.win32_error = GetLastError();
    a.message = L"Verzeichnis konnte nicht entfernt werden.";
  } else {
    ++a.directories_deleted;
    a.message = L"Verzeichnis vollständig verarbeitet und entfernt.";
  }
  return a;
}
} // namespace
erase_result erase_engine::erase(const std::filesystem::path &t,
                                 const erase_options &o,
                                 const progress_callback &cb) const {
  return erase_impl(t, o, cb, false);
}

erase_result
erase_engine::erase_recycle_bin_item(const std::filesystem::path &t,
                                     const erase_options &o,
                                     const progress_callback &cb) const {
  return erase_impl(t, o, cb, true);
}

erase_result erase_engine::erase_impl(const std::filesystem::path &t,
                                      const erase_options &o,
                                      const progress_callback &cb,
                                      bool allow_recycle_bin_items) const {
  const auto validation =
      path_validator{false, allow_recycle_bin_items}.validate(t);
  if (!validation.allowed) {
    erase_result r;
    r.win32_error = ERROR_ACCESS_DENIED;
    r.message = L"Engine-Schutz hat das Ziel blockiert: " + validation.reason;
    return r;
  }
  const auto &target = validation.normalized;
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
}
} // namespace oblivion
