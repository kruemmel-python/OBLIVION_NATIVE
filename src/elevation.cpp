#include "oblivion/elevation.hpp"
#include <Windows.h>
#include <shellapi.h>
namespace oblivion { namespace { std::wstring quote(const std::wstring& v){std::wstring r=L"\""; unsigned bs=0; for(wchar_t c:v){ if(c==L'\\'){++bs;continue;} if(c==L'\"'){r.append(bs*2+1,L'\\');r.push_back(c);bs=0;continue;} r.append(bs,L'\\');bs=0;r.push_back(c);} r.append(bs*2,L'\\');r.push_back(L'\"');return r;} }
bool is_process_elevated(){HANDLE t=nullptr;if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&t))return false;TOKEN_ELEVATION e{};DWORD n=0;bool ok=GetTokenInformation(t,TokenElevation,&e,sizeof(e),&n)!=FALSE;CloseHandle(t);return ok&&e.TokenIsElevated!=0;}
bool relaunch_elevated(const std::filesystem::path& exe,const std::vector<std::wstring>& args){std::wstring p;for(const auto&a:args){if(!p.empty())p.push_back(L' ');p+=quote(a);}SHELLEXECUTEINFOW i{};i.cbSize=sizeof(i);i.fMask=SEE_MASK_NOCLOSEPROCESS;i.lpVerb=L"runas";i.lpFile=exe.c_str();i.lpParameters=p.c_str();i.nShow=SW_SHOWNORMAL;bool ok=ShellExecuteExW(&i)!=FALSE;if(i.hProcess)CloseHandle(i.hProcess);return ok;}
}
