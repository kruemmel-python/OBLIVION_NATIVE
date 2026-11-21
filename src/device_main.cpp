#include "oblivion/audit.hpp"
#include "oblivion/audit_integrity.hpp"
#include "oblivion/elevation.hpp"
#include "oblivion/runtime_guard.hpp"
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
#include <fstream>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
namespace {
struct info {
  unsigned n{0};
  std::wstring model, serial;
  STORAGE_BUS_TYPE bus{BusTypeUnknown};
  std::uint64_t size{0};
};
enum class method { def, block, crypto };
bool device_audit(const info &i, method m, bool success, DWORD error);
std::wstring bname(STORAGE_BUS_TYPE b) {
  return b == BusTypeNvme   ? L"NVMe"
         : b == BusTypeSata ? L"SATA"
         : b == BusTypeAta  ? L"ATA"
         : b == BusTypeUsb  ? L"USB"
         : b == BusTypeScsi ? L"SCSI"
                            : L"Other";
}
std::wstring fld(const std::vector<std::byte> &d, DWORD off) {
  if (!off || off >= d.size())
    return {};
  const char *v = reinterpret_cast<const char *>(d.data() + off);
  auto avail = d.size() - off, n = strnlen_s(v, avail);
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
std::optional<info> inspect(unsigned n) {
  auto p = L"\\\\.\\PhysicalDrive" + std::to_wstring(n);
  HANDLE h = CreateFileW(p.c_str(), 0,
                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                         nullptr, OPEN_EXISTING, 0, nullptr);
  if (h == INVALID_HANDLE_VALUE)
    return {};
  info i;
  i.n = n;
  DWORD r = 0;
  std::array<std::byte, sizeof(DISK_GEOMETRY_EX) + 1024> gb{};
  if (DeviceIoControl(h, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, nullptr, 0,
                      gb.data(), static_cast<DWORD>(gb.size()), &r, nullptr) &&
      r >= sizeof(DISK_GEOMETRY_EX)) {
    auto *g = reinterpret_cast<const DISK_GEOMETRY_EX *>(gb.data());
    if (g->DiskSize.QuadPart > 0)
      i.size = static_cast<std::uint64_t>(g->DiskSize.QuadPart);
  }
  STORAGE_PROPERTY_QUERY q{};
  q.PropertyId = StorageDeviceProperty;
  q.QueryType = PropertyStandardQuery;
  std::vector<std::byte> b(8192);
  if (DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &q, sizeof(q), b.data(),
                      static_cast<DWORD>(b.size()), &r, nullptr) &&
      r >= sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
    auto *d = reinterpret_cast<const STORAGE_DEVICE_DESCRIPTOR *>(b.data());
    auto v = fld(b, d->VendorIdOffset), pdt = fld(b, d->ProductIdOffset);
    i.model = v;
    if (!pdt.empty()) {
      if (!i.model.empty())
        i.model += L" ";
      i.model += pdt;
    }
    i.serial = fld(b, d->SerialNumberOffset);
    i.bus = d->BusType;
  }
  CloseHandle(h);
  return i;
}
std::optional<unsigned> system_disk() {
  std::array<wchar_t, MAX_PATH + 1> w{}, root{};
  if (!GetWindowsDirectoryW(w.data(), static_cast<UINT>(w.size())) ||
      !GetVolumePathNameW(w.data(), root.data(),
                          static_cast<DWORD>(root.size())) ||
      wcslen(root.data()) < 2)
    return {};
  std::wstring v = L"\\\\.\\" + std::wstring{root.data(), 2};
  HANDLE h = CreateFileW(v.c_str(), 0,
                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                         nullptr, OPEN_EXISTING, 0, nullptr);
  if (h == INVALID_HANDLE_VALUE)
    return {};
  STORAGE_DEVICE_NUMBER d{};
  DWORD r = 0;
  bool ok = DeviceIoControl(h, IOCTL_STORAGE_GET_DEVICE_NUMBER, nullptr, 0, &d,
                            sizeof(d), &r, nullptr) != FALSE;
  CloseHandle(h);
  return ok ? std::optional<unsigned>{d.DeviceNumber} : std::nullopt;
}
bool belongs(HANDLE h, unsigned disk) {
  std::array<std::byte, sizeof(VOLUME_DISK_EXTENTS) + sizeof(DISK_EXTENT) * 31>
      b{};
  DWORD r = 0;
  if (!DeviceIoControl(h, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, nullptr, 0,
                       b.data(), static_cast<DWORD>(b.size()), &r, nullptr))
    return false;
  auto *e = reinterpret_cast<const VOLUME_DISK_EXTENTS *>(b.data());
  for (DWORD i = 0; i < (std::min)(e->NumberOfDiskExtents, 32ul); ++i)
    if (e->Extents[i].DiskNumber == disk)
      return true;
  return false;
}
std::vector<std::wstring> mounts(unsigned disk) {
  std::vector<std::wstring> out;
  std::array<wchar_t, 1024> vn{};
  HANDLE f = FindFirstVolumeW(vn.data(), static_cast<DWORD>(vn.size()));
  if (f == INVALID_HANDLE_VALUE)
    return out;
  do {
    std::wstring v = vn.data(), open = v;
    if (!open.empty() && open.back() == L'\\')
      open.pop_back();
    HANDLE h = CreateFileW(
        open.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, 0, nullptr);
    bool yes = h != INVALID_HANDLE_VALUE && belongs(h, disk);
    if (h != INVALID_HANDLE_VALUE)
      CloseHandle(h);
    if (yes) {
      DWORD need = 0;
      GetVolumePathNamesForVolumeNameW(v.c_str(), nullptr, 0, &need);
      if (need > 1) {
        std::vector<wchar_t> b(need);
        if (GetVolumePathNamesForVolumeNameW(v.c_str(), b.data(), need,
                                             &need)) {
          const wchar_t *p = b.data();
          while (*p) {
            out.emplace_back(p);
            p += wcslen(p) + 1;
          }
        }
      }
    }
  } while (FindNextVolumeW(f, vn.data(), static_cast<DWORD>(vn.size())));
  FindVolumeClose(f);
  return out;
}
bool lock_volumes(unsigned disk, std::vector<HANDLE> &hs, std::wstring &err) {
  std::array<wchar_t, 1024> vn{};
  HANDLE f = FindFirstVolumeW(vn.data(), static_cast<DWORD>(vn.size()));
  if (f == INVALID_HANDLE_VALUE) {
    err = L"Volumes nicht enumerierbar.";
    return false;
  }
  bool ok = true;
  do {
    std::wstring v = vn.data();
    if (!v.empty() && v.back() == L'\\')
      v.pop_back();
    HANDLE p = CreateFileW(
        v.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, 0, nullptr);
    bool yes = p != INVALID_HANDLE_VALUE && belongs(p, disk);
    if (p != INVALID_HANDLE_VALUE)
      CloseHandle(p);
    if (!yes)
      continue;
    HANDLE h = CreateFileW(v.c_str(), GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_EXISTING, 0, nullptr);
    DWORD r = 0;
    if (h == INVALID_HANDLE_VALUE ||
        !DeviceIoControl(h, FSCTL_LOCK_VOLUME, nullptr, 0, nullptr, 0, &r,
                         nullptr)) {
      if (h != INVALID_HANDLE_VALUE)
        CloseHandle(h);
      err = L"FSCTL_LOCK_VOLUME fehlgeschlagen: " + v;
      ok = false;
      break;
    }
    hs.push_back(h);
  } while (FindNextVolumeW(f, vn.data(), static_cast<DWORD>(vn.size())));
  FindVolumeClose(f);
  if (!ok)
    for (HANDLE h : hs)
      CloseHandle(h);
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
      auto m = mounts(n);
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
  auto sys = system_disk();
  if (sys && *sys == n) {
    std::wcerr << L"ABGELEHNT: Systemdatenträger.\n";
    return false;
  }
  if (!oblivion::is_process_elevated()) {
    std::wcerr << L"Administratorrechte erforderlich.\n";
    return false;
  }
  auto mp = mounts(n);
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
  std::vector<HANDLE> locks;
  std::wstring err;
  if (!lock_volumes(n, locks, err)) {
    std::wcerr << L"ABGELEHNT: " << err << L"\n";
    return false;
  }
  auto p = L"\\\\.\\PhysicalDrive" + std::to_wstring(n);
  HANDLE h = CreateFileW(p.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                         OPEN_EXISTING, FILE_FLAG_WRITE_THROUGH, nullptr);
  if (h == INVALID_HANDLE_VALUE) {
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
  bool ok = DeviceIoControl(h, IOCTL_STORAGE_REINITIALIZE_MEDIA, buf, sz,
                            nullptr, 0, &r, nullptr) != FALSE;
  DWORD e = ok ? 0 : GetLastError();
  CloseHandle(h);
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
                  const DWORD error) {
  std::error_code ec;
  const auto dir = oblivion::audit_directory();
  std::filesystem::create_directories(dir, ec);
  if (ec)
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
  std::wofstream out(file, std::ios::out | std::ios::trunc);
  if (!out)
    return false;
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
  out.close();
  return out.good() && oblivion::seal_audit_file(file);
}
void usage() {
  std::wcout << L"OblivionDevice.exe --diagnostics\nOblivionDevice.exe "
                L"--list\nOblivionDevice.exe --sanitize N "
                L"--method default|block|crypto --confirm ERASE-PHYSICALDRIVEN "
                L"--i-understand-this-erases-the-entire-device\n";
}
} // namespace
int wmain(int argc, wchar_t *argv[]) {
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
  bool have = false, under = false, go = false;
  method m = method::def;
  std::wstring c;
  for (int i = 1; i < argc; ++i) {
    std::wstring_view a = argv[i];
    if (a == L"--sanitize" && i + 1 < argc) {
      try {
        auto x = std::stoul(argv[++i]);
        if (x > 63)
          throw std::out_of_range("disk");
        n = static_cast<unsigned>(x);
        have = go = true;
      } catch (...) {
        return 1;
      }
    } else if (a == L"--method" && i + 1 < argc) {
      std::wstring_view v = argv[++i];
      if (v == L"default")
        m = method::def;
      else if (v == L"block")
        m = method::block;
      else if (v == L"crypto")
        m = method::crypto;
      else
        return 1;
    } else if (a == L"--confirm" && i + 1 < argc)
      c = argv[++i];
    else if (a == L"--i-understand-this-erases-the-entire-device")
      under = true;
  }
  if (!go || !have || !under) {
    usage();
    return 1;
  }
  return sanitize(n, m, c) ? 0 : 2;
}
