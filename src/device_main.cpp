#include "oblivion/audit.hpp"
#include "oblivion/audit_integrity.hpp"
#include "oblivion/elevation.hpp"
#include "oblivion/runtime_guard.hpp"
#include "oblivion/win_handle.hpp"
#include <Windows.h>
// clang-format off: ntddstor.h requires storage types declared by winioctl.h.
#include <winioctl.h>
#include <ntddstor.h>
// clang-format on
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <iostream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
namespace {
class unique_volume_enumerator {
  HANDLE value_{INVALID_HANDLE_VALUE};

public:
  explicit unique_volume_enumerator(HANDLE value) : value_(value) {}
  ~unique_volume_enumerator() {
    if (value_ != INVALID_HANDLE_VALUE)
      FindVolumeClose(value_);
  }
  unique_volume_enumerator(const unique_volume_enumerator &) = delete;
  unique_volume_enumerator &operator=(const unique_volume_enumerator &) =
      delete;
  HANDLE get() const noexcept { return value_; }
  explicit operator bool() const noexcept {
    return value_ != INVALID_HANDLE_VALUE;
  }
};
struct info {
  unsigned n{0};
  std::wstring model, serial;
  STORAGE_BUS_TYPE bus{BusTypeUnknown};
  std::uint64_t size{0};
};
enum class method { def, block, crypto };
bool device_audit(const info &i, method m, bool success, DWORD error) noexcept;
std::wstring bname(STORAGE_BUS_TYPE b) {
  return b == BusTypeNvme   ? L"NVMe"
         : b == BusTypeSata ? L"SATA"
         : b == BusTypeAta  ? L"ATA"
         : b == BusTypeUsb  ? L"USB"
         : b == BusTypeScsi ? L"SCSI"
                            : L"Other";
}
std::wstring fld(const std::vector<std::byte> &d, const DWORD returned,
                 const DWORD off) {
  const auto valid =
      (std::min)(d.size(), static_cast<std::size_t>(returned));
  if (!off || static_cast<std::size_t>(off) >= valid)
    return {};
  const char *v = reinterpret_cast<const char *>(d.data() + off);
  const auto avail = valid - static_cast<std::size_t>(off);
  const auto n = strnlen_s(v, avail);
  if (!n || n >= avail)
    return {};
  int need = MultiByteToWideChar(CP_ACP, 0, v, static_cast<int>(n), nullptr, 0);
  if (need <= 0)
    return {};
  std::wstring w(static_cast<std::size_t>(need), L'\0');
  MultiByteToWideChar(CP_ACP, 0, v, static_cast<int>(n), w.data(), need);
  while (!w.empty() && w.back() == L' ')
    w.pop_back();
  return w;
}
std::optional<info> inspect_handle(const HANDLE h, const unsigned n) {
  info i;
  i.n = n;
  DWORD r = 0;
  std::array<std::byte, sizeof(DISK_GEOMETRY_EX) + 1024> gb{};
  if (!DeviceIoControl(h, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, nullptr, 0,
                       gb.data(), static_cast<DWORD>(gb.size()), &r, nullptr) ||
      r < sizeof(DISK_GEOMETRY_EX))
    return {};
  const auto *g = reinterpret_cast<const DISK_GEOMETRY_EX *>(gb.data());
  if (g->DiskSize.QuadPart <= 0)
    return {};
  i.size = static_cast<std::uint64_t>(g->DiskSize.QuadPart);
  STORAGE_PROPERTY_QUERY q{};
  q.PropertyId = StorageDeviceProperty;
  q.QueryType = PropertyStandardQuery;
  std::vector<std::byte> b(8192);
  if (!DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &q, sizeof(q), b.data(),
                       static_cast<DWORD>(b.size()), &r, nullptr) ||
      r < sizeof(STORAGE_DEVICE_DESCRIPTOR))
    return {};
  const auto *d = reinterpret_cast<const STORAGE_DEVICE_DESCRIPTOR *>(b.data());
  auto v = fld(b, r, d->VendorIdOffset), pdt = fld(b, r, d->ProductIdOffset);
  i.model = v;
  if (!pdt.empty()) {
    if (!i.model.empty())
      i.model += L" ";
    i.model += pdt;
  }
  i.serial = fld(b, r, d->SerialNumberOffset);
  i.bus = d->BusType;
  return i;
}
std::optional<info> inspect(unsigned n) {
  auto p = L"\\\\.\\PhysicalDrive" + std::to_wstring(n);
  oblivion::unique_win_handle h{CreateFileW(
      p.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      nullptr, OPEN_EXISTING, 0, nullptr)};
  if (!h)
    return {};
  return inspect_handle(h.get(), n);
}
bool identifiable(const info &i) {
  return i.size != 0 && !i.model.empty() && !i.serial.empty();
}
bool same_device(const info &left, const info &right) {
  return left.n == right.n && left.size == right.size &&
         left.bus == right.bus && left.model == right.model &&
         left.serial == right.serial;
}
std::optional<unsigned> system_disk() {
  std::array<wchar_t, MAX_PATH + 1> w{}, root{};
  if (!GetWindowsDirectoryW(w.data(), static_cast<UINT>(w.size())) ||
      !GetVolumePathNameW(w.data(), root.data(),
                          static_cast<DWORD>(root.size())) ||
      wcslen(root.data()) < 2)
    return {};
  std::wstring v = L"\\\\.\\" + std::wstring{root.data(), 2};
  oblivion::unique_win_handle h{CreateFileW(
      v.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      nullptr, OPEN_EXISTING, 0, nullptr)};
  if (!h)
    return {};
  STORAGE_DEVICE_NUMBER d{};
  DWORD r = 0;
  bool ok = DeviceIoControl(h.get(), IOCTL_STORAGE_GET_DEVICE_NUMBER, nullptr,
                            0, &d, sizeof(d), &r, nullptr) != FALSE;
  return ok ? std::optional<unsigned>{d.DeviceNumber} : std::nullopt;
}
std::optional<bool> belongs(HANDLE h, unsigned disk) {
  constexpr std::size_t max_extent_bytes = 1024u * 1024u;
  std::vector<std::byte> buffer(sizeof(VOLUME_DISK_EXTENTS) +
                                sizeof(DISK_EXTENT) * 31u);
  for (;;) {
    DWORD returned = 0;
    if (DeviceIoControl(h, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, nullptr, 0,
                        buffer.data(), static_cast<DWORD>(buffer.size()),
                        &returned, nullptr)) {
      constexpr std::size_t header_bytes =
          offsetof(VOLUME_DISK_EXTENTS, Extents);
      if (static_cast<std::size_t>(returned) < header_bytes)
        return std::nullopt;
      const auto *extents =
          reinterpret_cast<const VOLUME_DISK_EXTENTS *>(buffer.data());
      const auto available =
          (static_cast<std::size_t>(returned) - header_bytes) /
          sizeof(DISK_EXTENT);
      if (static_cast<std::size_t>(extents->NumberOfDiskExtents) > available)
        return std::nullopt;
      for (DWORD i = 0; i < extents->NumberOfDiskExtents; ++i)
        if (extents->Extents[i].DiskNumber == disk)
          return true;
      return false;
    }
    if (GetLastError() != ERROR_MORE_DATA ||
        buffer.size() >= max_extent_bytes)
      return std::nullopt;
    buffer.resize((std::min)(buffer.size() * 2u, max_extent_bytes));
  }
}
std::vector<std::wstring> mounts(unsigned disk, bool &complete) {
  constexpr DWORD max_mount_path_characters = 1024u * 1024u;
  complete = false;
  std::vector<std::wstring> out;
  std::array<wchar_t, 1024> vn{};
  unique_volume_enumerator f{
      FindFirstVolumeW(vn.data(), static_cast<DWORD>(vn.size()))};
  if (!f)
    return out;
  DWORD enumeration_error = ERROR_SUCCESS;
  for (;;) {
    std::wstring v = vn.data(), open = v;
    if (!open.empty() && open.back() == L'\\')
      open.pop_back();
    oblivion::unique_win_handle h{CreateFileW(
        open.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, 0, nullptr)};
    if (!h) {
      enumeration_error = GetLastError();
      break;
    }
    const auto membership = belongs(h.get(), disk);
    if (!membership.has_value()) {
      enumeration_error = ERROR_INVALID_DATA;
      break;
    }
    if (*membership) {
      DWORD need = 0;
      SetLastError(ERROR_SUCCESS);
      const BOOL initial =
          GetVolumePathNamesForVolumeNameW(v.c_str(), nullptr, 0, &need);
      const DWORD path_error = GetLastError();
      if (!initial && (path_error != ERROR_MORE_DATA || need == 0)) {
        enumeration_error = path_error ? path_error : ERROR_INVALID_DATA;
        break;
      }
      if (need > max_mount_path_characters) {
        enumeration_error = ERROR_BUFFER_OVERFLOW;
        break;
      }
      if (need > 1) {
        std::vector<wchar_t> b(need);
        if (!GetVolumePathNamesForVolumeNameW(v.c_str(), b.data(), need,
                                              &need)) {
          enumeration_error = GetLastError();
          break;
        }
        std::size_t offset = 0;
        bool paths_valid = true;
        while (offset < b.size() && b[offset] != L'\0') {
          std::size_t end = offset;
          while (end < b.size() && b[end] != L'\0')
            ++end;
          if (end == b.size()) {
            paths_valid = false;
            break;
          }
          out.emplace_back(b.data() + offset, end - offset);
          offset = end + 1u;
        }
        if (!paths_valid) {
          enumeration_error = ERROR_INVALID_DATA;
          break;
        }
      }
    }
    if (!FindNextVolumeW(f.get(), vn.data(), static_cast<DWORD>(vn.size()))) {
      enumeration_error = GetLastError();
      break;
    }
  }
  if (enumeration_error != ERROR_NO_MORE_FILES) {
    out.clear();
    return out;
  }
  complete = true;
  return out;
}
bool lock_volumes(unsigned disk, std::vector<HANDLE> &hs, std::wstring &err) {
  std::array<wchar_t, 1024> vn{};
  unique_volume_enumerator f{
      FindFirstVolumeW(vn.data(), static_cast<DWORD>(vn.size()))};
  if (!f) {
    err = L"Volumes nicht enumerierbar.";
    return false;
  }
  bool ok = true;
  DWORD enumeration_error = ERROR_SUCCESS;
  for (;;) {
    std::wstring v = vn.data();
    if (!v.empty() && v.back() == L'\\')
      v.pop_back();
    oblivion::unique_win_handle p{CreateFileW(
        v.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, 0, nullptr)};
    if (!p) {
      err = L"Volume konnte für die Datenträgerzuordnung nicht geöffnet werden: " +
            v;
      ok = false;
      break;
    }
    const auto membership = belongs(p.get(), disk);
    if (!membership.has_value()) {
      err = L"Volume-Datenträgerzuordnung konnte nicht vollständig geprüft "
            L"werden: " +
            v;
      ok = false;
      break;
    }
    if (*membership) {
      oblivion::unique_win_handle h{CreateFileW(
          v.c_str(), GENERIC_READ | GENERIC_WRITE,
          FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0,
          nullptr)};
      DWORD r = 0;
      if (!h ||
          !DeviceIoControl(h.get(), FSCTL_LOCK_VOLUME, nullptr, 0, nullptr, 0,
                           &r, nullptr)) {
        err = L"FSCTL_LOCK_VOLUME fehlgeschlagen: " + v;
        ok = false;
        break;
      }
      try {
        hs.push_back(h.get());
        (void)h.release();
      } catch (...) {
        err = L"Arbeitsspeicher für Volume-Locks konnte nicht reserviert "
              L"werden.";
        ok = false;
        break;
      }
    }
    if (!FindNextVolumeW(f.get(), vn.data(), static_cast<DWORD>(vn.size()))) {
      enumeration_error = GetLastError();
      break;
    }
  }
  if (ok && enumeration_error != ERROR_NO_MORE_FILES) {
    err = L"Volume-Aufzählung wurde nicht vollständig abgeschlossen.";
    ok = false;
  }
  if (!ok)
    for (HANDLE h : hs)
      CloseHandle(h);
  if (!ok)
    hs.clear();
  return ok;
}
void unlock(std::vector<HANDLE> &hs) {
  for (HANDLE h : hs) {
    DWORD r = 0;
    (void)DeviceIoControl(h, FSCTL_UNLOCK_VOLUME, nullptr, 0, nullptr, 0, &r,
                          nullptr);
    CloseHandle(h);
  }
  hs.clear();
}
void list() {
  auto sys = system_disk();
  for (unsigned n = 0; n < 64; ++n)
    if (auto i = inspect(n)) {
      std::wcout << L"PhysicalDrive" << n
                 << (sys && *sys == n ? L" [SYSTEMDISK - BLOCKED]" : L"")
                 << L"\n  Model: " << i->model << L"\n  Serial: " << i->serial
                 << L"\n  Bus: " << bname(i->bus) << L"\n  Size: "
                 << static_cast<double>(i->size) / (1024.0 * 1024.0 * 1024.0)
                 << L" GiB\n";
      bool mount_scan_complete = false;
      auto m = mounts(n, mount_scan_complete);
      if (!mount_scan_complete)
        std::wcout << L"  Mounted: [Aufzählung unvollständig]\n";
      if (!m.empty()) {
        std::wcout << L"  Mounted: ";
        for (const auto &p : m)
          std::wcout << p << L" ";
        std::wcout << L"\n";
      }
      std::wcout << L"\n";
    }
}
bool sanitize(unsigned n, method m, const std::wstring &confirm) {
  auto i = inspect(n);
  if (!i) {
    std::wcerr << L"Gerät nicht gefunden.\n";
    return false;
  }
  if (!identifiable(*i)) {
    std::wcerr << L"ABGELEHNT: Gerät besitzt keine belastbare Modell-, Serien- "
                  L"und Größenidentität.\n";
    return false;
  }
  auto sys = system_disk();
  if (!sys) {
    std::wcerr << L"ABGELEHNT: Systemdatenträger konnte nicht sicher "
                  L"ermittelt werden.\n";
    return false;
  }
  if (*sys == n) {
    std::wcerr << L"ABGELEHNT: Systemdatenträger.\n";
    return false;
  }
  if (!oblivion::is_process_elevated()) {
    std::wcerr << L"Administratorrechte erforderlich.\n";
    return false;
  }
  bool mount_scan_complete = false;
  auto mp = mounts(n, mount_scan_complete);
  if (!mount_scan_complete) {
    std::wcerr << L"ABGELEHNT: Mountpoint- und Volume-Aufzählung war "
                  L"unvollständig.\n";
    return false;
  }
  if (!mp.empty()) {
    std::wcerr << L"ABGELEHNT: Ziel besitzt Mountpoints.\n";
    return false;
  }
  if ((m == method::block || m == method::crypto) && i->bus != BusTypeNvme) {
    std::wcerr << L"Block/Crypto-Auswahl nur für NVMe freigegeben.\n";
    return false;
  }
  auto token = L"ERASE-PHYSICALDRIVE" + std::to_wstring(n);
  if (confirm != token) {
    std::wcerr << L"--confirm " << token << L" erforderlich.\n";
    return false;
  }
  std::wcout << L"LETZTE BESTÄTIGUNG: " << i->model << L" / " << i->serial
             << L"\nExakt " << token << L" eingeben: ";
  std::wstring x;
  std::getline(std::wcin, x);
  if (x != token)
    return false;
  const auto prelock_identity = inspect(n);
  const auto prelock_system_disk = system_disk();
  bool prelock_mount_scan_complete = false;
  const auto prelock_mounts = mounts(n, prelock_mount_scan_complete);
  if (!prelock_identity || !identifiable(*prelock_identity) ||
      !same_device(*i, *prelock_identity) || !prelock_system_disk ||
      *prelock_system_disk == n || !prelock_mount_scan_complete ||
      !prelock_mounts.empty()) {
    std::wcerr << L"ABGELEHNT: Geräteidentität, Systemdisk- oder "
                  L"Mountpoint-Zustand hat sich vor dem Volume-Lock geändert.\n";
    return false;
  }
  std::vector<HANDLE> locks;
  std::wstring err;
  if (!lock_volumes(n, locks, err)) {
    std::wcerr << L"ABGELEHNT: " << err << L"\n";
    return false;
  }
  struct volume_lock_guard {
    std::vector<HANDLE> &handles;
    ~volume_lock_guard() { unlock(handles); }
  } release_volume_locks{locks};
  auto p = L"\\\\.\\PhysicalDrive" + std::to_wstring(n);
  oblivion::unique_win_handle h{CreateFileW(
      p.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
      FILE_FLAG_WRITE_THROUGH, nullptr)};
  if (!h) {
    unlock(locks);
    return false;
  }
  const auto opened_identity = inspect_handle(h.get(), n);
  const auto current_system_disk = system_disk();
  if (!opened_identity || !identifiable(*opened_identity) ||
      !same_device(*i, *opened_identity) || !current_system_disk ||
      *current_system_disk == n) {
    std::wcerr << L"ABGELEHNT: Geräteidentität oder Systemdisk-Zustand hat "
                  L"sich vor dem Sanitize geändert.\n";
    h.reset();
    unlock(locks);
    return false;
  }
  STORAGE_REINITIALIZE_MEDIA prm{};
  void *buf = nullptr;
  DWORD sz = 0;
  if (i->bus == BusTypeNvme) {
    prm.Version = static_cast<ULONG>(sizeof(prm));
    prm.Size = static_cast<ULONG>(sizeof(prm));
    prm.TimeoutInSeconds = 0;
    prm.SanitizeOption.SanitizeMethod =
        m == method::block    ? StorageSanitizeMethodBlockErase
        : m == method::crypto ? StorageSanitizeMethodCryptoErase
                              : StorageSanitizeMethodDefault;
    prm.SanitizeOption.DisallowUnrestrictedSanitizeExit = 1;
    buf = &prm;
    sz = static_cast<DWORD>(sizeof(prm));
  }
  DWORD r = 0;
  bool ok = DeviceIoControl(h.get(), IOCTL_STORAGE_REINITIALIZE_MEDIA, buf, sz,
                            nullptr, 0, &r, nullptr) != FALSE;
  DWORD e = ok ? 0 : GetLastError();
  h.reset();
  unlock(locks);
  const bool audited = device_audit(*i, m, ok, e);
  if (!ok)
    std::wcerr << L"Sanitize fehlgeschlagen, Win32Error=" << e << L"\n";
  if (!audited)
    std::wcerr
        << L"Audit konnte nicht integritätsgeschützt geschrieben werden.\n";
  return ok && audited;
}

bool device_audit(const info &i, const method m, const bool success,
                  const DWORD error) noexcept try {
  std::filesystem::path dir;
  if (!oblivion::prepare_audit_directory(dir))
    return false;
  SYSTEMTIME st{};
  GetLocalTime(&st);
  wchar_t name[96]{};
  swprintf_s(
      name,
      L"device_sanitize_%04u-%02u-%02u_%02u-%02u-%02u-%03u_PhysicalDrive%u.log",
      st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
      st.wMilliseconds, i.n);
  const auto file = dir / name;
  std::wostringstream out;
  out << L"OBLIVION DEVICE SANITIZE AUDIT 2\n"
      << L"PhysicalDrive: " << i.n << L"\n"
      << L"ModelRef: " << oblivion::audit_reference(i.model) << L"\n"
      << L"SerialRef: " << oblivion::audit_reference(i.serial) << L"\n"
      << L"Bus: " << bname(i.bus) << L"\n"
      << L"Method: "
      << (m == method::block    ? L"block"
          : m == method::crypto ? L"crypto"
                                : L"default")
      << L"\n"
      << L"ApiRequestAccepted: " << (success ? L"true" : L"false") << L"\n"
      << L"CompletionScope: "
      << (success ? L"windows_storage_stack_ioctl_returned"
                  : L"failed_before_completion")
      << L"\n"
      << L"IndependentPhysicalVerification: not_performed\n"
      << L"Win32Error: " << error << L"\n";
  return out.good() && oblivion::write_sealed_audit_file(file, out.str());
} catch (...) {
  return false;
}
void usage() {
  std::wcout << L"OblivionDevice.exe --diagnostics\nOblivionDevice.exe "
                L"--list\nOblivionDevice.exe --sanitize N "
                L"--method default|block|crypto --confirm ERASE-PHYSICALDRIVEN "
                L"--i-understand-this-erases-the-entire-device\n";
}
} // namespace
int wmain(int argc, wchar_t *argv[]) try {
  const auto hardening = oblivion::harden_current_process();
  if (argc == 2 && std::wstring_view{argv[1]} == L"--diagnostics") {
    std::wcout << oblivion::format_runtime_hardening(hardening) << L'\n';
    return hardening.complete() ? 0 : 7;
  }
  if (!hardening.complete()) {
    std::wcerr << oblivion::format_runtime_hardening(hardening) << L'\n';
    return 7;
  }
  if (argc == 2 && std::wstring_view{argv[1]} == L"--list") {
    list();
    return 0;
  }
  unsigned n = 0;
  bool have = false, under = false, method_seen = false,
       confirmation_seen = false;
  method m = method::def;
  std::wstring c;
  for (int i = 1; i < argc; ++i) {
    std::wstring_view a = argv[i];
    if (a == L"--sanitize" && i + 1 < argc && !have) {
      try {
        const std::wstring value = argv[++i];
        std::size_t consumed = 0;
        const auto x = std::stoul(value, &consumed);
        if (consumed != value.size() || x > 63)
          throw std::out_of_range("disk");
        n = static_cast<unsigned>(x);
        have = true;
      } catch (...) {
        return 1;
      }
    } else if (a == L"--method" && i + 1 < argc && !method_seen) {
      method_seen = true;
      std::wstring_view v = argv[++i];
      if (v == L"default")
        m = method::def;
      else if (v == L"block")
        m = method::block;
      else if (v == L"crypto")
        m = method::crypto;
      else
        return 1;
    } else if (a == L"--confirm" && i + 1 < argc && !confirmation_seen) {
      confirmation_seen = true;
      c = argv[++i];
    } else if (a == L"--i-understand-this-erases-the-entire-device" &&
               !under) {
      under = true;
    } else {
      std::wcerr << L"Unbekanntes oder unvollständiges Argument: " << a
                 << L"\n";
      return 1;
    }
  }
  if (!have || !method_seen || !confirmation_seen || !under) {
    usage();
    return 1;
  }
  return sanitize(n, m, c) ? 0 : 2;
} catch (const std::exception &error) {
  std::cerr << "OBLIVION Device: Unbehandelte C++-Ausnahme: " << error.what()
            << '\n';
  return 10;
} catch (...) {
  std::cerr << "OBLIVION Device: Unbekannte Ausnahme.\n";
  return 10;
}
