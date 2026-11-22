#include <Windows.h>
#include "oblivion/cotaskmem_string.hpp"
#include <shellapi.h>
#include <shobjidl.h>
#include <algorithm>
#include <atomic>
#include <cstring>
#include <cstddef>
#include <filesystem>
#include <limits>
#include <new>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
namespace {
using oblivion::unique_cotaskmem_string;
const CLSID ROOT={0xb7bc56b2,0x689f,0x4e78,{0x9a,0x59,0x63,0xf1,0x80,0x11,0xe6,0xb0}};
const CLSID ERASE={0xa54e1b58,0x55dd,0x4a99,{0x99,0xf7,0x2d,0x2e,0xe2,0xba,0x12,0x41}};
const CLSID ANALYZE={0x4f3cbf3c,0x1a66,0x4650,{0x9c,0x24,0xe1,0x92,0x27,0xc0,0x58,0x72}};
const CLSID SETTINGS={0x8f2d6123,0xef72,0x4a6d,{0xbd,0x22,0xec,0x04,0x2c,0x5d,0x3d,0xf1}};
enum class mode{root,erase,analyze,settings};HMODULE g_mod=nullptr;std::atomic<long>g_obj{0},g_lock{0};
HRESULT dup(const std::wstring_view value, LPWSTR *out) noexcept {
  if (!out)
    return E_POINTER;
  *out = nullptr;
  if (value.size() >
      ((std::numeric_limits<std::size_t>::max)() / sizeof(wchar_t)) - 1u)
    return E_OUTOFMEMORY;
  const auto bytes = (value.size() + 1u) * sizeof(wchar_t);
  auto *copy = static_cast<wchar_t *>(CoTaskMemAlloc(bytes));
  if (!copy)
    return E_OUTOFMEMORY;
  if (!value.empty())
    std::memcpy(copy, value.data(), value.size() * sizeof(wchar_t));
  copy[value.size()] = L'\0';
  *out = copy;
  return S_OK;
}
std::filesystem::path dir() {
  std::wstring buffer(32768, L'\0');
  const DWORD length = GetModuleFileNameW(
      g_mod, buffer.data(), static_cast<DWORD>(buffer.size()));
  if (!length || static_cast<std::size_t>(length) >= buffer.size())
    return {};
  buffer.resize(length);
  return std::filesystem::path{buffer}.parent_path();
}
std::wstring quote(const std::wstring &value) {
  std::wstring result = L"\"";
  unsigned slashes = 0;
  for (const wchar_t character : value) {
    if (character == L'\\') {
      ++slashes;
      continue;
    }
    if (character == L'\"') {
      result.append(slashes * 2u + 1u, L'\\');
      result.push_back(character);
      slashes = 0;
      continue;
    }
    result.append(slashes, L'\\');
    slashes = 0;
    result.push_back(character);
  }
  result.append(slashes * 2u, L'\\');
  result.push_back(L'\"');
  return result;
}
const CLSID &cid(const mode value) {
  return value == mode::erase      ? ERASE
         : value == mode::analyze ? ANALYZE
         : value == mode::settings ? SETTINGS
                                   : ROOT;
}
HRESULT launch(IShellItemArray *items, mode m) noexcept {
  try {
    if (m == mode::root)
      return E_NOTIMPL;
    const auto directory = dir();
    const auto executable = directory / L"Oblivion.exe";
    std::error_code existence_error;
    if (!std::filesystem::exists(executable, existence_error) ||
        existence_error)
      return HRESULT_FROM_WIN32(existence_error
                                    ? static_cast<DWORD>(existence_error.value())
                                    : ERROR_FILE_NOT_FOUND);
    std::wstring arguments;
    if (m == mode::settings) {
      arguments = L"--settings";
    } else {
      if (!items)
        return E_INVALIDARG;
      DWORD count = 0;
      HRESULT result = items->GetCount(&count);
      if (FAILED(result) || count == 0)
        return FAILED(result) ? result : E_INVALIDARG;
      arguments = m == mode::erase ? L"--shell" : L"--analyze --shell";
      for (DWORD index = 0; index < count; ++index) {
        IShellItem *item = nullptr;
        result = items->GetItemAt(index, &item);
        if (FAILED(result) || !item)
          return FAILED(result) ? result : E_FAIL;
        unique_cotaskmem_string path;
        result = item->GetDisplayName(SIGDN_FILESYSPATH, path.put());
        item->Release();
        if (FAILED(result) || !path) {
          return FAILED(result) ? result
                                : HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND);
        }
        arguments += L" " + quote(path.get());
        if (arguments.size() >= 32767u)
          return HRESULT_FROM_WIN32(ERROR_FILENAME_EXCED_RANGE);
      }
    }
    SHELLEXECUTEINFOW execute{};
    execute.cbSize = sizeof(execute);
    execute.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC |
                    SEE_MASK_FLAG_NO_UI;
    execute.lpFile = executable.c_str();
    execute.lpParameters = arguments.c_str();
    execute.lpDirectory = directory.c_str();
    execute.nShow = SW_SHOWNORMAL;
    if (!ShellExecuteExW(&execute))
      return HRESULT_FROM_WIN32(GetLastError());
    if (execute.hProcess)
      CloseHandle(execute.hProcess);
    return S_OK;
  } catch (const std::bad_alloc &) {
    return E_OUTOFMEMORY;
  } catch (...) {
    return E_FAIL;
  }
}
class Command;
class DropHandler final:public IDropTarget{std::atomic<long>r_{1};mode m_;public:explicit DropHandler(mode m) noexcept:m_(m){++g_obj;}~DropHandler(){--g_obj;}HRESULT STDMETHODCALLTYPE QueryInterface(REFIID q,void**p) noexcept override{if(!p)return E_POINTER;*p=nullptr;if(q==IID_IUnknown||q==IID_IDropTarget){*p=this;AddRef();return S_OK;}return E_NOINTERFACE;}ULONG STDMETHODCALLTYPE AddRef() noexcept override{return static_cast<ULONG>(++r_);}ULONG STDMETHODCALLTYPE Release() noexcept override{ULONG n=static_cast<ULONG>(--r_);if(!n)delete this;return n;}HRESULT STDMETHODCALLTYPE DragEnter(IDataObject*,DWORD,POINTL,DWORD*effect) noexcept override{if(effect)*effect=DROPEFFECT_COPY;return S_OK;}HRESULT STDMETHODCALLTYPE DragOver(DWORD,POINTL,DWORD*effect) noexcept override{if(effect)*effect=DROPEFFECT_COPY;return S_OK;}HRESULT STDMETHODCALLTYPE DragLeave() noexcept override{return S_OK;}HRESULT STDMETHODCALLTYPE Drop(IDataObject*data,DWORD,POINTL,DWORD*effect) noexcept override{if(effect)*effect=DROPEFFECT_NONE;if(!data||m_==mode::root||m_==mode::settings)return E_INVALIDARG;IShellItemArray*items=nullptr;HRESULT hr=SHCreateShellItemArrayFromDataObject(data,IID_PPV_ARGS(&items));if(SUCCEEDED(hr)){hr=launch(items,m_);items->Release();}if(SUCCEEDED(hr)&&effect)*effect=DROPEFFECT_COPY;return hr;}};
class Enum final : public IEnumExplorerCommand {
  std::atomic<long> references_{1};
  std::vector<mode> modes_;
  std::size_t index_{0};

public:
  Enum(std::vector<mode> modes, const std::size_t index = 0)
      : modes_(std::move(modes)), index_(index) {
    ++g_obj;
  }
  ~Enum() { --g_obj; }
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID requested,
                                           void **result) noexcept override {
    if (!result)
      return E_POINTER;
    *result = nullptr;
    if (requested == IID_IUnknown || requested == IID_IEnumExplorerCommand) {
      *result = this;
      AddRef();
      return S_OK;
    }
    return E_NOINTERFACE;
  }
  ULONG STDMETHODCALLTYPE AddRef() noexcept override {
    return static_cast<ULONG>(++references_);
  }
  ULONG STDMETHODCALLTYPE Release() noexcept override {
    const ULONG remaining = static_cast<ULONG>(--references_);
    if (!remaining)
      delete this;
    return remaining;
  }
  HRESULT STDMETHODCALLTYPE Next(ULONG count, IExplorerCommand **out,
                                 ULONG *fetched) noexcept override;
  HRESULT STDMETHODCALLTYPE Skip(const ULONG count) noexcept override {
    const auto remaining = modes_.size() - index_;
    const auto skipped =
        (std::min)(static_cast<std::size_t>(count), remaining);
    index_ += skipped;
    return skipped == count ? S_OK : S_FALSE;
  }
  HRESULT STDMETHODCALLTYPE Reset() noexcept override {
    index_ = 0;
    return S_OK;
  }
  HRESULT STDMETHODCALLTYPE Clone(IEnumExplorerCommand **out) noexcept override {
    if (!out)
      return E_POINTER;
    *out = nullptr;
    try {
      *out = new (std::nothrow) Enum(modes_, index_);
      return *out ? S_OK : E_OUTOFMEMORY;
    } catch (const std::bad_alloc &) {
      return E_OUTOFMEMORY;
    } catch (...) {
      return E_FAIL;
    }
  }
};
class Command final : public IExplorerCommand {
  std::atomic<long> references_{1};
  mode mode_;

public:
  explicit Command(const mode value) noexcept : mode_(value) { ++g_obj; }
  ~Command() { --g_obj; }
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID requested,
                                           void **result) noexcept override {
    if (!result)
      return E_POINTER;
    *result = nullptr;
    if (requested == IID_IUnknown || requested == IID_IExplorerCommand) {
      *result = this;
      AddRef();
      return S_OK;
    }
    return E_NOINTERFACE;
  }
  ULONG STDMETHODCALLTYPE AddRef() noexcept override {
    return static_cast<ULONG>(++references_);
  }
  ULONG STDMETHODCALLTYPE Release() noexcept override {
    const ULONG remaining = static_cast<ULONG>(--references_);
    if (!remaining)
      delete this;
    return remaining;
  }
  HRESULT STDMETHODCALLTYPE GetTitle(IShellItemArray *,
                                     LPWSTR *title) noexcept override {
    return dup(mode_ == mode::root      ? L"Oblivion"
               : mode_ == mode::erase  ? L"Sicher löschen"
               : mode_ == mode::analyze ? L"Analysieren (Dry Run)"
                                         : L"Optionen",
               title);
  }
  HRESULT STDMETHODCALLTYPE GetIcon(IShellItemArray *,
                                    LPWSTR *icon) noexcept override {
    try {
      return dup((dir() / L"Oblivion.exe").wstring(), icon);
    } catch (const std::bad_alloc &) {
      return E_OUTOFMEMORY;
    } catch (...) {
      return E_FAIL;
    }
  }
  HRESULT STDMETHODCALLTYPE GetToolTip(IShellItemArray *,
                                       LPWSTR *tip) noexcept override {
    return dup(mode_ == mode::erase      ? L"Mit OBLIVION sicher löschen"
               : mode_ == mode::analyze ? L"Auswahl analysieren ohne zu löschen"
               : mode_ == mode::settings ? L"OBLIVION konfigurieren"
                                          : L"OBLIVION",
               tip);
  }
  HRESULT STDMETHODCALLTYPE GetCanonicalName(GUID *name) noexcept override {
    if (!name)
      return E_POINTER;
    *name = cid(mode_);
    return S_OK;
  }
  HRESULT STDMETHODCALLTYPE GetState(IShellItemArray *, BOOL,
                                     EXPCMDSTATE *state) noexcept override {
    if (!state)
      return E_POINTER;
    *state = ECS_ENABLED;
    return S_OK;
  }
  HRESULT STDMETHODCALLTYPE Invoke(IShellItemArray *items,
                                   IBindCtx *) noexcept override {
    return launch(items, mode_);
  }
  HRESULT STDMETHODCALLTYPE GetFlags(EXPCMDFLAGS *flags) noexcept override {
    if (!flags)
      return E_POINTER;
    *flags = mode_ == mode::root ? ECF_HASSUBCOMMANDS : ECF_DEFAULT;
    return S_OK;
  }
  HRESULT STDMETHODCALLTYPE
  EnumSubCommands(IEnumExplorerCommand **out) noexcept override {
    if (!out)
      return E_POINTER;
    *out = nullptr;
    if (mode_ != mode::root)
      return E_NOTIMPL;
    try {
      *out = new (std::nothrow)
          Enum({mode::erase, mode::analyze, mode::settings});
      return *out ? S_OK : E_OUTOFMEMORY;
    } catch (const std::bad_alloc &) {
      return E_OUTOFMEMORY;
    } catch (...) {
      return E_FAIL;
    }
  }
};
HRESULT Enum::Next(const ULONG count, IExplorerCommand **out,
                   ULONG *fetched) noexcept {
  if (!out || (count != 1 && !fetched))
    return E_POINTER;
  if (fetched)
    *fetched = 0;
  ULONG produced = 0;
  while (produced < count && index_ < modes_.size()) {
    auto *command = new (std::nothrow) Command(modes_[index_]);
    if (!command) {
      for (ULONG index = 0; index < produced; ++index) {
        out[index]->Release();
        out[index] = nullptr;
      }
      index_ -= produced;
      return E_OUTOFMEMORY;
    }
    ++index_;
    out[produced++] = command;
  }
  if (fetched)
    *fetched = produced;
  return produced == count ? S_OK : S_FALSE;
}
class Factory final:public IClassFactory{std::atomic<long>r_{1};mode m_;public:explicit Factory(mode m) noexcept:m_(m){++g_obj;}~Factory(){--g_obj;}HRESULT STDMETHODCALLTYPE QueryInterface(REFIID q,void**p) noexcept override{if(!p)return E_POINTER;*p=nullptr;if(q==IID_IUnknown||q==IID_IClassFactory){*p=this;AddRef();return S_OK;}return E_NOINTERFACE;}ULONG STDMETHODCALLTYPE AddRef() noexcept override{return static_cast<ULONG>(++r_);}ULONG STDMETHODCALLTYPE Release() noexcept override{ULONG n=static_cast<ULONG>(--r_);if(!n)delete this;return n;}HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown*o,REFIID q,void**p) noexcept override{if(!p)return E_POINTER;*p=nullptr;if(o)return CLASS_E_NOAGGREGATION;if(q==IID_IDropTarget){auto*x=new(std::nothrow)DropHandler(m_);if(!x)return E_OUTOFMEMORY;HRESULT hr=x->QueryInterface(q,p);x->Release();return hr;}auto*x=new(std::nothrow)Command(m_);if(!x)return E_OUTOFMEMORY;HRESULT hr=x->QueryInterface(q,p);x->Release();return hr;}HRESULT STDMETHODCALLTYPE LockServer(BOOL x) noexcept override{if(x)++g_lock;else --g_lock;return S_OK;}};
}
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID)
{
    if (r == DLL_PROCESS_ATTACH)
    {
        g_mod = h;
        DisableThreadLibraryCalls(h);
    }
    return TRUE;
}

_Check_return_ STDAPI DllGetClassObject(_In_ REFCLSID c, _In_ REFIID q,
                                        _Outptr_ LPVOID* p)
{
    if (!p)
        return E_POINTER;
    *p = nullptr;
    mode m{};
    if (IsEqualCLSID(c, ROOT))
        m = mode::root;
    else if (IsEqualCLSID(c, ERASE))
        m = mode::erase;
    else if (IsEqualCLSID(c, ANALYZE))
        m = mode::analyze;
    else if (IsEqualCLSID(c, SETTINGS))
        m = mode::settings;
    else
        return CLASS_E_CLASSNOTAVAILABLE;

    auto* f = new (std::nothrow) Factory(m);
    if (!f)
        return E_OUTOFMEMORY;

    const HRESULT hr = f->QueryInterface(q, p);
    f->Release();
    return hr;
}

__control_entrypoint(DllExport) STDAPI DllCanUnloadNow(void)
{
    return g_obj.load() == 0 && g_lock.load() == 0 ? S_OK : S_FALSE;
}
