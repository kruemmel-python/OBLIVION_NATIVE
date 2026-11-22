#include "oblivion/storage_inspector.hpp"
#include "oblivion/win_handle.hpp"
#include <Windows.h>
#include <Wbemidl.h>
#include <OleAuto.h>
#include <winioctl.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cwctype>
#include <limits>
#include <string>
#include <vector>
namespace oblivion { namespace {
template <typename T> class com_ptr {
  T *value_{};

public:
  com_ptr() = default;
  ~com_ptr() {
    if (value_)
      value_->Release();
  }
  com_ptr(const com_ptr &) = delete;
  com_ptr &operator=(const com_ptr &) = delete;
  T *operator->() const noexcept { return value_; }
  T *get() const noexcept { return value_; }
  explicit operator bool() const noexcept { return value_ != nullptr; }
  T **put() noexcept { return &value_; }
};
class unique_bstr {
  BSTR value_{};

public:
  explicit unique_bstr(const wchar_t *value) : value_(SysAllocString(value)) {}
  ~unique_bstr() { SysFreeString(value_); }
  unique_bstr(const unique_bstr &) = delete;
  unique_bstr &operator=(const unique_bstr &) = delete;
  BSTR get() const noexcept { return value_; }
  explicit operator bool() const noexcept { return value_ != nullptr; }
};
class unique_variant {
  VARIANT value_{};

public:
  unique_variant() { VariantInit(&value_); }
  ~unique_variant() { VariantClear(&value_); }
  VARIANT *get() noexcept { return &value_; }
  const VARIANT &value() const noexcept { return value_; }
};
class com_uninitializer {
  bool active_{};

public:
  explicit com_uninitializer(const bool active) : active_(active) {}
  ~com_uninitializer() {
    if (active_)
      CoUninitialize();
  }
};
std::wstring root_for(const std::filesystem::path&p){std::vector<wchar_t>b(32768,L'\0');return GetVolumePathNameW(p.c_str(),b.data(),static_cast<DWORD>(b.size()))?std::wstring{b.data()}:L"";}
std::wstring dev_for(const std::wstring&r){return r.size()>=2&&r[1]==L':'?L"\\\\.\\"+r.substr(0,2):L"";}
std::wstring guid_for(const std::wstring&r){std::array<wchar_t,1024>b{};return GetVolumeNameForVolumeMountPointW(r.c_str(),b.data(),static_cast<DWORD>(b.size()))?std::wstring{b.data()}:L"";}
std::wstring bus(STORAGE_BUS_TYPE b){switch(b){case BusTypeAta:return L"ATA";case BusTypeSata:return L"SATA";case BusTypeNvme:return L"NVMe";case BusTypeUsb:return L"USB";case BusTypeScsi:return L"SCSI";case BusTypeSas:return L"SAS";case BusTypeRAID:return L"RAID";case BusTypeSpaces:return L"Storage Spaces";default:return L"Unbekannt";}}
std::wstring field(const std::vector<std::byte>&buf,DWORD returned,DWORD off){auto valid=(std::min)(buf.size(),static_cast<std::size_t>(returned)),i=static_cast<std::size_t>(off);if(!off||i>=valid)return{};const char*v=reinterpret_cast<const char*>(buf.data()+i);std::size_t n=0;while(i+n<valid&&v[n]!='\0')++n;while(n&&v[n-1]==' ')--n;if(!n||n>static_cast<std::size_t>((std::numeric_limits<int>::max)()))return{};int in=static_cast<int>(n),need=MultiByteToWideChar(CP_ACP,0,v,in,nullptr,0);if(need<=0)return{};std::wstring w(static_cast<std::size_t>(need),L'\0');MultiByteToWideChar(CP_ACP,0,v,in,w.data(),need);return w;}
bool usn(const std::wstring&d){unique_win_handle h{CreateFileW(d.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,0,nullptr)};if(!h)return false;USN_JOURNAL_DATA_V0 x{};DWORD n=0;return DeviceIoControl(h.get(),FSCTL_QUERY_USN_JOURNAL,nullptr,0,&x,sizeof(x),&n,nullptr)!=FALSE;}
std::wstring lower(std::wstring s){std::transform(s.begin(),s.end(),s.begin(),[](wchar_t c){return static_cast<wchar_t>(std::towlower(c));});return s;}
void shadows(storage_info &i) try {
  if (i.volume_guid.empty())
    return;
  const HRESULT initialized = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
  const bool uninitialize = SUCCEEDED(initialized);
  com_uninitializer cleanup_com{uninitialize};
  if (FAILED(initialized) && initialized != RPC_E_CHANGED_MODE)
    return;
  const HRESULT security = CoInitializeSecurity(
      nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT,
      RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);
  if (FAILED(security) && security != RPC_E_TOO_LATE) {
    return;
  }
  com_ptr<IWbemLocator> locator;
  com_ptr<IWbemServices> services;
  com_ptr<IEnumWbemClassObject> enumerator;
  HRESULT result = CoCreateInstance(
      CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_IWbemLocator,
      reinterpret_cast<void **>(locator.put()));
  if (SUCCEEDED(result)) {
    unique_bstr name_space{L"ROOT\\CIMV2"};
    if (!name_space)
      result = E_OUTOFMEMORY;
    else {
      result = locator->ConnectServer(name_space.get(), nullptr, nullptr,
                                      nullptr, 0, nullptr, nullptr,
                                      services.put());
    }
  }
  if (SUCCEEDED(result))
    result = CoSetProxyBlanket(
        services.get(), RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr,
        EOAC_NONE);
  if (SUCCEEDED(result)) {
    unique_bstr language{L"WQL"};
    unique_bstr query{L"SELECT VolumeName FROM Win32_ShadowCopy"};
    if (!language || !query)
      result = E_OUTOFMEMORY;
    else
      result = services->ExecQuery(
          language.get(), query.get(),
          WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr,
          enumerator.put());
  }
  if (SUCCEEDED(result) && enumerator) {
    constexpr std::uint32_t max_shadow_copies = 10000;
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(5);
    auto target = lower(i.volume_guid);
    if (!target.empty() && target.back() != L'\\')
      target.push_back(L'\\');
    bool complete = false;
    for (std::uint32_t count = 0;
         count < max_shadow_copies &&
         std::chrono::steady_clock::now() < deadline;
         ++count) {
      com_ptr<IWbemClassObject> object;
      ULONG received = 0;
      const HRESULT next = enumerator->Next(250, 1, object.put(), &received);
      if (next == S_FALSE) {
        complete = true;
        break;
      }
      if (next != S_OK || received != 1 || !object)
        break;
      unique_variant value;
      if (SUCCEEDED(object->Get(L"VolumeName", 0, value.get(), nullptr,
                                nullptr)) &&
          value.value().vt == VT_BSTR && value.value().bstrVal) {
        std::wstring current = lower(value.value().bstrVal);
        if (!current.empty() && current.back() != L'\\')
          current.push_back(L'\\');
        if (current == target)
          ++i.shadow_copy_count;
      }
    }
    i.shadow_copy_query_succeeded = complete;
    if (!complete)
      i.shadow_copy_count = 0;
  }
} catch (...) {
  i.shadow_copy_count = 0;
  i.shadow_copy_query_succeeded = false;
}
}
storage_info storage_inspector::inspect(const std::filesystem::path&p)const{storage_info i;i.volume_root=root_for(p);if(i.volume_root.empty()){i.description=L"Datenträger konnte nicht bestimmt werden.";return i;}i.volume_guid=guid_for(i.volume_root);std::array<wchar_t,MAX_PATH+1>fs{};if(GetVolumeInformationW(i.volume_root.c_str(),nullptr,0,nullptr,nullptr,nullptr,fs.data(),static_cast<DWORD>(fs.size())))i.filesystem=fs.data();auto dp=dev_for(i.volume_root);if(dp.empty())return i;i.usn_journal_active=usn(dp);unique_win_handle h{CreateFileW(dp.c_str(),0,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,0,nullptr)};if(!h){shadows(i);return i;}DWORD n=0;STORAGE_DEVICE_NUMBER dn{};if(DeviceIoControl(h.get(),IOCTL_STORAGE_GET_DEVICE_NUMBER,nullptr,0,&dn,sizeof(dn),&n,nullptr))i.physical_drive_number=dn.DeviceNumber;STORAGE_PROPERTY_QUERY q{};q.PropertyId=StorageDeviceSeekPenaltyProperty;q.QueryType=PropertyStandardQuery;DEVICE_SEEK_PENALTY_DESCRIPTOR sp{};if(DeviceIoControl(h.get(),IOCTL_STORAGE_QUERY_PROPERTY,&q,sizeof(q),&sp,sizeof(sp),&n,nullptr))i.kind=sp.IncursSeekPenalty?media_kind::rotational:media_kind::solid_state;q.PropertyId=StorageDeviceTrimProperty;DEVICE_TRIM_DESCRIPTOR td{};if(DeviceIoControl(h.get(),IOCTL_STORAGE_QUERY_PROPERTY,&q,sizeof(q),&td,sizeof(td),&n,nullptr))i.trim_enabled=td.TrimEnabled!=FALSE;q.PropertyId=StorageDeviceProperty;std::vector<std::byte>b(8192);if(DeviceIoControl(h.get(),IOCTL_STORAGE_QUERY_PROPERTY,&q,sizeof(q),b.data(),static_cast<DWORD>(b.size()),&n,nullptr)&&n>=sizeof(STORAGE_DEVICE_DESCRIPTOR)){auto*d=reinterpret_cast<const STORAGE_DEVICE_DESCRIPTOR*>(b.data());auto v=field(b,n,d->VendorIdOffset),prod=field(b,n,d->ProductIdOffset);i.device_model=v;if(!prod.empty()){if(!i.device_model.empty())i.device_model+=L" ";i.device_model+=prod;}i.device_serial=field(b,n,d->SerialNumberOffset);i.bus_type=bus(d->BusType);}h.reset();shadows(i);i.description=i.kind==media_kind::solid_state?(i.trim_enabled?L"SSD/NVMe, TRIM aktiv":L"SSD/NVMe"):i.kind==media_kind::rotational?L"HDD":L"Unbekannter Datenträgertyp";return i;}
}
