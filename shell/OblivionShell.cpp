#include <Windows.h>
#include <shellapi.h>
#include <shobjidl.h>
#include <algorithm>
#include <atomic>
#include <cstring>
#include <cstddef>
#include <filesystem>
#include <new>
#include <string>
#include <utility>
#include <vector>
namespace {
const CLSID ROOT={0xb7bc56b2,0x689f,0x4e78,{0x9a,0x59,0x63,0xf1,0x80,0x11,0xe6,0xb0}};
const CLSID ERASE={0xa54e1b58,0x55dd,0x4a99,{0x99,0xf7,0x2d,0x2e,0xe2,0xba,0x12,0x41}};
const CLSID ANALYZE={0x4f3cbf3c,0x1a66,0x4650,{0x9c,0x24,0xe1,0x92,0x27,0xc0,0x58,0x72}};
const CLSID SETTINGS={0x8f2d6123,0xef72,0x4a6d,{0xbd,0x22,0xec,0x04,0x2c,0x5d,0x3d,0xf1}};
enum class mode{root,erase,analyze,settings};HMODULE g_mod=nullptr;std::atomic<long>g_obj{0},g_lock{0};
HRESULT dup(const std::wstring&s,LPWSTR*out){if(!out)return E_POINTER;*out=nullptr;auto bytes=(s.size()+1)*sizeof(wchar_t);auto*p=static_cast<wchar_t*>(CoTaskMemAlloc(bytes));if(!p)return E_OUTOFMEMORY;std::memcpy(p,s.c_str(),bytes);*out=p;return S_OK;}std::filesystem::path dir(){std::wstring b(32768,L'\0');DWORD n=GetModuleFileNameW(g_mod,b.data(),static_cast<DWORD>(b.size()));if(!n||static_cast<std::size_t>(n)>=b.size())return{};b.resize(n);return std::filesystem::path{b}.parent_path();}std::wstring quote(const std::wstring&v){std::wstring r=L"\"";unsigned s=0;for(wchar_t c:v){if(c==L'\\'){++s;continue;}if(c==L'\"'){r.append(s*2+1,L'\\');r.push_back(c);s=0;continue;}r.append(s,L'\\');s=0;r.push_back(c);}r.append(s*2,L'\\');r.push_back(L'\"');return r;}const CLSID&cid(mode m){return m==mode::erase?ERASE:m==mode::analyze?ANALYZE:m==mode::settings?SETTINGS:ROOT;}
HRESULT launch(IShellItemArray*items,mode m){if(m==mode::root)return E_NOTIMPL;auto d=dir(),exe=d/L"Oblivion.exe";if(!std::filesystem::exists(exe))return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);std::wstring args;if(m==mode::settings)args=L"--settings";else{if(!items)return E_INVALIDARG;DWORD count=0;HRESULT hr=items->GetCount(&count);if(FAILED(hr)||!count)return FAILED(hr)?hr:E_INVALIDARG;args=m==mode::erase?L"--shell":L"--analyze --shell";DWORD paths=0;for(DWORD i=0;i<count;++i){IShellItem*it=nullptr;if(FAILED(items->GetItemAt(i,&it))||!it)continue;PWSTR p=nullptr;if(SUCCEEDED(it->GetDisplayName(SIGDN_FILESYSPATH,&p))&&p){args+=L" "+quote(p);++paths;CoTaskMemFree(p);}it->Release();}if(!paths)return HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND);}SHELLEXECUTEINFOW si{};si.cbSize=sizeof(si);si.fMask=SEE_MASK_NOCLOSEPROCESS|SEE_MASK_NOASYNC|SEE_MASK_FLAG_NO_UI;si.lpFile=exe.c_str();si.lpParameters=args.c_str();si.lpDirectory=d.c_str();si.nShow=SW_SHOWNORMAL;if(!ShellExecuteExW(&si))return HRESULT_FROM_WIN32(GetLastError());if(si.hProcess)CloseHandle(si.hProcess);return S_OK;}
class Command;
class DropHandler final:public IDropTarget{std::atomic<long>r_{1};mode m_;public:explicit DropHandler(mode m):m_(m){++g_obj;}~DropHandler(){--g_obj;}HRESULT STDMETHODCALLTYPE QueryInterface(REFIID q,void**p)override{if(!p)return E_POINTER;*p=nullptr;if(q==IID_IUnknown||q==IID_IDropTarget){*p=this;AddRef();return S_OK;}return E_NOINTERFACE;}ULONG STDMETHODCALLTYPE AddRef()override{return static_cast<ULONG>(++r_);}ULONG STDMETHODCALLTYPE Release()override{ULONG n=static_cast<ULONG>(--r_);if(!n)delete this;return n;}HRESULT STDMETHODCALLTYPE DragEnter(IDataObject*,DWORD,POINTL,DWORD*effect)override{if(effect)*effect=DROPEFFECT_COPY;return S_OK;}HRESULT STDMETHODCALLTYPE DragOver(DWORD,POINTL,DWORD*effect)override{if(effect)*effect=DROPEFFECT_COPY;return S_OK;}HRESULT STDMETHODCALLTYPE DragLeave()override{return S_OK;}HRESULT STDMETHODCALLTYPE Drop(IDataObject*data,DWORD,POINTL,DWORD*effect)override{if(effect)*effect=DROPEFFECT_NONE;if(!data||m_==mode::root||m_==mode::settings)return E_INVALIDARG;IShellItemArray*items=nullptr;HRESULT hr=SHCreateShellItemArrayFromDataObject(data,IID_PPV_ARGS(&items));if(SUCCEEDED(hr)){hr=launch(items,m_);items->Release();}if(SUCCEEDED(hr)&&effect)*effect=DROPEFFECT_COPY;return hr;}};
class Enum final:public IEnumExplorerCommand{std::atomic<long>r_{1};std::vector<mode>m_;std::size_t i_{0};public:Enum(std::vector<mode>m,std::size_t i=0):m_(std::move(m)),i_(i){++g_obj;}~Enum(){--g_obj;}HRESULT STDMETHODCALLTYPE QueryInterface(REFIID q,void**p)override{if(!p)return E_POINTER;*p=nullptr;if(q==IID_IUnknown||q==IID_IEnumExplorerCommand){*p=this;AddRef();return S_OK;}return E_NOINTERFACE;}ULONG STDMETHODCALLTYPE AddRef()override{return static_cast<ULONG>(++r_);}ULONG STDMETHODCALLTYPE Release()override{ULONG n=static_cast<ULONG>(--r_);if(!n)delete this;return n;}HRESULT STDMETHODCALLTYPE Next(ULONG c,IExplorerCommand**out,ULONG*f)override;HRESULT STDMETHODCALLTYPE Skip(ULONG c)override{auto n=(std::min)(static_cast<std::size_t>(c),m_.size()-i_);i_+=n;return n==c?S_OK:S_FALSE;}HRESULT STDMETHODCALLTYPE Reset()override{i_=0;return S_OK;}HRESULT STDMETHODCALLTYPE Clone(IEnumExplorerCommand**o)override{if(!o)return E_POINTER;*o=new(std::nothrow)Enum(m_,i_);return *o?S_OK:E_OUTOFMEMORY;}};
class Command final:public IExplorerCommand{std::atomic<long>r_{1};mode m_;public:explicit Command(mode m):m_(m){++g_obj;}~Command(){--g_obj;}HRESULT STDMETHODCALLTYPE QueryInterface(REFIID q,void**p)override{if(!p)return E_POINTER;*p=nullptr;if(q==IID_IUnknown||q==IID_IExplorerCommand){*p=this;AddRef();return S_OK;}return E_NOINTERFACE;}ULONG STDMETHODCALLTYPE AddRef()override{return static_cast<ULONG>(++r_);}ULONG STDMETHODCALLTYPE Release()override{ULONG n=static_cast<ULONG>(--r_);if(!n)delete this;return n;}HRESULT STDMETHODCALLTYPE GetTitle(IShellItemArray*,LPWSTR*n)override{return dup(m_==mode::root?L"Oblivion":m_==mode::erase?L"Sicher löschen":m_==mode::analyze?L"Analysieren (Dry Run)":L"Optionen",n);}HRESULT STDMETHODCALLTYPE GetIcon(IShellItemArray*,LPWSTR*i)override{return dup((dir()/L"Oblivion.exe").wstring(),i);}HRESULT STDMETHODCALLTYPE GetToolTip(IShellItemArray*,LPWSTR*t)override{return dup(m_==mode::erase?L"Mit OBLIVION sicher löschen":m_==mode::analyze?L"Auswahl analysieren ohne zu löschen":m_==mode::settings?L"OBLIVION konfigurieren":L"OBLIVION",t);}HRESULT STDMETHODCALLTYPE GetCanonicalName(GUID*g)override{if(!g)return E_POINTER;*g=cid(m_);return S_OK;}HRESULT STDMETHODCALLTYPE GetState(IShellItemArray*,BOOL,EXPCMDSTATE*s)override{if(!s)return E_POINTER;*s=ECS_ENABLED;return S_OK;}HRESULT STDMETHODCALLTYPE Invoke(IShellItemArray*i,IBindCtx*)override{return launch(i,m_);}HRESULT STDMETHODCALLTYPE GetFlags(EXPCMDFLAGS*f)override{if(!f)return E_POINTER;*f=m_==mode::root?ECF_HASSUBCOMMANDS:ECF_DEFAULT;return S_OK;}HRESULT STDMETHODCALLTYPE EnumSubCommands(IEnumExplorerCommand**o)override{if(!o)return E_POINTER;*o=nullptr;if(m_!=mode::root)return E_NOTIMPL;*o=new(std::nothrow)Enum({mode::erase,mode::analyze,mode::settings});return *o?S_OK:E_OUTOFMEMORY;}};
HRESULT Enum::Next(ULONG c,IExplorerCommand**out,ULONG*f){if(!out)return E_POINTER;if(c!=1&&!f)return E_POINTER;if(f)*f=0;ULONG n=0;while(n<c&&i_<m_.size()){auto*x=new(std::nothrow)Command(m_[i_++]);if(!x)return E_OUTOFMEMORY;out[n++]=x;}if(f)*f=n;return n==c?S_OK:S_FALSE;}
class Factory final:public IClassFactory{std::atomic<long>r_{1};mode m_;public:explicit Factory(mode m):m_(m){++g_obj;}~Factory(){--g_obj;}HRESULT STDMETHODCALLTYPE QueryInterface(REFIID q,void**p)override{if(!p)return E_POINTER;*p=nullptr;if(q==IID_IUnknown||q==IID_IClassFactory){*p=this;AddRef();return S_OK;}return E_NOINTERFACE;}ULONG STDMETHODCALLTYPE AddRef()override{return static_cast<ULONG>(++r_);}ULONG STDMETHODCALLTYPE Release()override{ULONG n=static_cast<ULONG>(--r_);if(!n)delete this;return n;}HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown*o,REFIID q,void**p)override{if(o)return CLASS_E_NOAGGREGATION;if(!p)return E_POINTER;if(q==IID_IDropTarget){auto*x=new(std::nothrow)DropHandler(m_);if(!x)return E_OUTOFMEMORY;HRESULT hr=x->QueryInterface(q,p);x->Release();return hr;}auto*x=new(std::nothrow)Command(m_);if(!x)return E_OUTOFMEMORY;HRESULT hr=x->QueryInterface(q,p);x->Release();return hr;}HRESULT STDMETHODCALLTYPE LockServer(BOOL x)override{if(x)++g_lock;else --g_lock;return S_OK;}};
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

STDAPI DllGetClassObject(REFCLSID c, REFIID q, LPVOID* p)
{
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

STDAPI DllCanUnloadNow()
{
    return g_obj.load() == 0 && g_lock.load() == 0 ? S_OK : S_FALSE;
}
