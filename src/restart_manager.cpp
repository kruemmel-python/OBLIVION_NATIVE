#include "oblivion/restart_manager.hpp"
#include <Windows.h>
#include <RestartManager.h>
#include <limits>
namespace oblivion {
std::vector<lock_owner>
diagnose_lock_owners(const std::filesystem::path &path) {
  constexpr UINT max_lock_owners = 4096;
  std::vector<lock_owner> owners;
  DWORD session = 0;
  WCHAR key[CCH_RM_SESSION_KEY + 1]{};
  if (RmStartSession(&session, 0, key) != ERROR_SUCCESS)
    return owners;
  const auto close_session = [&] { (void)RmEndSession(session); };
  try {
    const std::wstring value = path.wstring();
    LPCWSTR resources[] = {value.c_str()};
    if (RmRegisterResources(session, 1, resources, 0, nullptr, 0, nullptr) !=
        ERROR_SUCCESS) {
      close_session();
      return owners;
    }
    UINT needed = 0, count = 0;
    DWORD reasons = 0;
    DWORD status = RmGetList(session, &needed, &count, nullptr, &reasons);
    if (status == ERROR_MORE_DATA && needed > 0 &&
        needed <= max_lock_owners) {
      std::vector<RM_PROCESS_INFO> processes(needed);
      count = needed;
      status = RmGetList(session, &needed, &count, processes.data(), &reasons);
      if (status == ERROR_SUCCESS && count <= processes.size()) {
        owners.reserve(count);
        for (UINT index = 0; index < count; ++index)
          owners.push_back({processes[index].Process.dwProcessId,
                            processes[index].strAppName,
                            processes[index].strServiceShortName});
      }
    }
  } catch (...) {
    owners.clear();
  }
  close_session();
  return owners;
}
std::wstring format_lock_owners(const std::vector<lock_owner>& owners){ if(owners.empty()) return L"Kein verantwortlicher Prozess konnte über den Windows Restart Manager ermittelt werden."; std::wstring s=L"Die Datei wird verwendet von:\n"; for(const auto&o:owners){s+=L"\n- "+(o.application_name.empty()?std::wstring{L"Unbekannter Prozess"}:o.application_name)+L" (PID "+std::to_wstring(o.process_id)+L")"; if(!o.service_name.empty())s+=L" [Dienst: "+o.service_name+L"]";} return s; }
}
