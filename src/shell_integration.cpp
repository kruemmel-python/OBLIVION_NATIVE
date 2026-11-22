#include "oblivion/shell_integration.hpp"
#include "oblivion/cotaskmem_string.hpp"
#include "oblivion/elevation.hpp"
#include "oblivion/random.hpp"
#include "oblivion/resource_ids.h"
#include "oblivion/win_handle.hpp"

#include <Windows.h>
#include <shlobj.h>

#include <array>
#include <cstddef>
#include <filesystem>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

namespace oblivion {
namespace {
constexpr wchar_t ROOT[] = L"{B7BC56B2-689F-4E78-9A59-63F18011E6B0}";
constexpr wchar_t ERASE[] = L"{A54E1B58-55DD-4A99-99F7-2D2EE2BA1241}";
constexpr wchar_t ANALYZE[] = L"{4F3CBF3C-1A66-4650-9C24-E19227C05872}";
constexpr wchar_t SETTINGS[] = L"{8F2D6123-EF72-4A6D-BD22-EC042C5D3DF1}";

bool set_string(HKEY root, const std::wstring &key, const wchar_t *name,
                const std::wstring &value) {
  HKEY handle{};
  if (RegCreateKeyExW(root, key.c_str(), 0, nullptr, 0, KEY_SET_VALUE, nullptr,
                      &handle, nullptr) != ERROR_SUCCESS)
    return false;
  if (value.size() >=
      (std::numeric_limits<DWORD>::max)() / sizeof(wchar_t)) {
    RegCloseKey(handle);
    return false;
  }
  const auto bytes = (value.size() + 1u) * sizeof(wchar_t);
  const LONG result =
      RegSetValueExW(handle, name, 0, REG_SZ,
                     reinterpret_cast<const BYTE *>(value.c_str()),
                     static_cast<DWORD>(bytes));
  RegCloseKey(handle);
  return result == ERROR_SUCCESS;
}

bool remove_key(HKEY root, const std::wstring &key) {
  const LONG result = RegDeleteTreeW(root, key.c_str());
  return result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND;
}

bool remove_key(const std::wstring &key) {
  return remove_key(HKEY_CURRENT_USER, key);
}

bool key_exists(HKEY root, const std::wstring &key) noexcept {
  HKEY handle{};
  const LONG result =
      RegOpenKeyExW(root, key.c_str(), 0, KEY_READ, &handle);
  if (handle)
    RegCloseKey(handle);
  return result == ERROR_SUCCESS;
}

bool machine_wide_context_menu_present() noexcept {
  for (const auto *class_root : {L"*", L"Directory"}) {
    const auto base = L"Software\\Classes\\" + std::wstring{class_root} +
                      L"\\shell\\";
    for (const auto *name : {L"Oblivion", L"OblivionErase",
                             L"OblivionAnalyze", L"OblivionSettings"}) {
      if (key_exists(HKEY_LOCAL_MACHINE, base + name))
        return true;
    }
  }
  return key_exists(HKEY_LOCAL_MACHINE,
                    L"Software\\Classes\\Drive\\shell\\OblivionWipeFree") ||
         key_exists(HKEY_LOCAL_MACHINE,
                    L"Software\\Classes\\CLSID\\{645FF040-5081-101B-9F08-"
                    L"00AA002F954E}\\shell\\OblivionEmpty");
}

std::wstring quote_process_argument(const std::wstring_view value) {
  std::wstring result{L"\""};
  unsigned backslashes = 0;
  for (const wchar_t character : value) {
    if (character == L'\\') {
      ++backslashes;
      continue;
    }
    if (character == L'\"') {
      result.append(backslashes * 2u + 1u, L'\\');
      result.push_back(character);
      backslashes = 0;
      continue;
    }
    result.append(backslashes, L'\\');
    backslashes = 0;
    result.push_back(character);
  }
  result.append(backslashes * 2u, L'\\');
  result.push_back(L'\"');
  return result;
}

bool run_powershell_script(const std::filesystem::path &script,
                           const std::vector<std::wstring> &arguments) {
  std::error_code error;
  if (!std::filesystem::is_regular_file(script, error) || error)
    return false;

  std::wstring system_directory(32768, L'\0');
  const UINT length = GetSystemDirectoryW(
      system_directory.data(), static_cast<UINT>(system_directory.size()));
  if (length == 0 || static_cast<std::size_t>(length) >= system_directory.size())
    return false;
  system_directory.resize(length);
  const auto powershell = std::filesystem::path{system_directory} /
                          L"WindowsPowerShell" / L"v1.0" /
                          L"powershell.exe";

  std::wstring command = quote_process_argument(powershell.wstring()) +
                         L" -NoLogo -NoProfile -NonInteractive "
                         L"-WindowStyle Hidden -ExecutionPolicy Bypass -File " +
                         quote_process_argument(script.wstring());
  for (const auto &argument : arguments)
    command += L" " + quote_process_argument(argument);

  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESHOWWINDOW;
  startup.wShowWindow = SW_HIDE;
  PROCESS_INFORMATION process{};
  if (!CreateProcessW(powershell.c_str(), command.data(), nullptr, nullptr,
                      FALSE, CREATE_NO_WINDOW, nullptr,
                      script.parent_path().c_str(), &startup, &process))
    return false;
  unique_win_handle process_handle{process.hProcess};
  unique_win_handle thread_handle{process.hThread};
  const DWORD wait = WaitForSingleObject(process_handle.get(), 60000);
  if (wait != WAIT_OBJECT_0) {
    TerminateProcess(process_handle.get(), ERROR_TIMEOUT);
    WaitForSingleObject(process_handle.get(), 5000);
    return false;
  }
  DWORD exit_code = 1;
  return GetExitCodeProcess(process_handle.get(), &exit_code) != FALSE &&
         exit_code == 0;
}

bool register_modern_context_menu(const std::filesystem::path &source_exe) {
  const auto directory = source_exe.parent_path();
  const auto manifest = directory / L"AppxManifest.xml";
  const auto script = directory / L"Register-Win11ContextMenu.ps1";
  return run_powershell_script(
      script, {L"-Manifest", manifest.wstring(), L"-ExternalLocation",
               directory.wstring()});
}

bool unregister_modern_context_menu() {
  std::wstring executable(32768, L'\0');
  const DWORD length = GetModuleFileNameW(
      nullptr, executable.data(), static_cast<DWORD>(executable.size()));
  if (length == 0 || static_cast<std::size_t>(length) >= executable.size())
    return false;
  executable.resize(length);
  const auto script = std::filesystem::path{executable}.parent_path() /
                      L"Unregister-Win11ContextMenu.ps1";
  return run_powershell_script(script, {});
}

bool remove_legacy_commands() {
  return remove_key(L"Software\\Classes\\*\\shell\\SecureDelete") &&
         remove_key(
             L"Software\\Classes\\*\\shell\\Sicher_löschen_mit_Oblivion");
}

bool random_deployment_name(std::wstring &name) {
  std::array<std::byte, 16> random{};
  if (!try_fill_secure_random(random))
    return false;
  constexpr wchar_t digits[] = L"0123456789abcdef";
  name = L"deploy-";
  name.reserve(name.size() + random.size() * 2);
  for (const auto value : random) {
    const auto byte = std::to_integer<unsigned>(value);
    name.push_back(digits[byte >> 4]);
    name.push_back(digits[byte & 0x0f]);
  }
  return true;
}

bool local_shell_root(std::filesystem::path &root) {
  unique_cotaskmem_string local;
  const HRESULT result =
      SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_CREATE, nullptr,
                           local.put());
  if (FAILED(result) || !local)
    return false;
  root = std::filesystem::path{local.get()} / L"Oblivion" / L"Shell";
  return true;
}

bool prepare_directory_tree(const std::filesystem::path &directory,
                            const bool create, bool &exists) noexcept try {
  exists = true;
  if (directory.empty() || !directory.is_absolute())
    return false;
  std::filesystem::path current = directory.root_path();
  if (current.empty())
    return false;
  for (const auto &component : directory.relative_path()) {
    current /= component;
    DWORD attributes = GetFileAttributesW(current.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
      const DWORD error = GetLastError();
      if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND)
        return false;
      if (!create) {
        exists = false;
        return true;
      }
      if (CreateDirectoryW(current.c_str(), nullptr) == FALSE &&
          GetLastError() != ERROR_ALREADY_EXISTS)
        return false;
      attributes = GetFileAttributesW(current.c_str());
    }
    if (attributes == INVALID_FILE_ATTRIBUTES ||
        (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
        (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
      return false;
  }
  return true;
} catch (...) {
  exists = false;
  return false;
}

bool lock_directory_tree(const std::filesystem::path &directory,
                         std::vector<unique_win_handle> &locks) noexcept try {
  locks.clear();
  auto current = directory.root_path();
  if (current.empty())
    return false;
  for (const auto &component : directory.relative_path()) {
    if (component.empty() || component == L".")
      continue;
    if (component == L"..")
      return false;
    current /= component;
    unique_win_handle handle{CreateFileW(
        current.c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    if (!handle ||
        !GetFileInformationByHandleEx(handle.get(), FileAttributeTagInfo,
                                      &attributes, sizeof(attributes)) ||
        (attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
        (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
      return false;
    locks.push_back(std::move(handle));
  }
  return true;
} catch (...) {
  return false;
}

bool delete_open_handle(HANDLE handle) noexcept {
  FILE_DISPOSITION_INFO_EX extended{};
  extended.Flags = FILE_DISPOSITION_FLAG_DELETE |
                   FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE;
  if (SetFileInformationByHandle(handle, FileDispositionInfoEx, &extended,
                                 sizeof(extended)) != FALSE)
    return true;
  FILE_DISPOSITION_INFO legacy{TRUE};
  return SetFileInformationByHandle(handle, FileDispositionInfo, &legacy,
                                    sizeof(legacy)) != FALSE;
}

void clean_old_deployments(const std::filesystem::path &root,
                           const std::filesystem::path &keep) {
  std::error_code error;
  std::filesystem::directory_iterator it(root, error), end;
  if (error)
    return;
  while (it != end) {
    const auto name = it->path().filename().wstring();
    const bool is_deployment =
        name.starts_with(L"deploy-") || name.starts_with(L"build-");
    if (is_deployment &&
        CompareStringOrdinal(it->path().c_str(), -1, keep.c_str(), -1, TRUE) !=
            CSTR_EQUAL) {
      unique_win_handle deployment{CreateFileW(
          it->path().c_str(), DELETE | FILE_READ_ATTRIBUTES,
          FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
          FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
      FILE_ATTRIBUTE_TAG_INFO deployment_attributes{};
      if (!deployment ||
          !GetFileInformationByHandleEx(
              deployment.get(), FileAttributeTagInfo, &deployment_attributes,
              sizeof(deployment_attributes)))
        return;
      const bool is_directory =
          (deployment_attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
      const bool is_reparse =
          (deployment_attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) !=
          0;
      if (is_directory && !is_reparse) {
        const auto executable = it->path() / L"Oblivion.exe";
        unique_win_handle executable_handle{CreateFileW(
            executable.c_str(), DELETE | FILE_READ_ATTRIBUTES, 0, nullptr,
            OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
        if (executable_handle) {
          FILE_ATTRIBUTE_TAG_INFO executable_attributes{};
          if (!GetFileInformationByHandleEx(
                  executable_handle.get(), FileAttributeTagInfo,
                  &executable_attributes, sizeof(executable_attributes)) ||
              (executable_attributes.FileAttributes &
               (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
              !delete_open_handle(executable_handle.get()))
            return;
          executable_handle.reset();
        } else {
          const DWORD open_error = GetLastError();
          if (open_error != ERROR_FILE_NOT_FOUND &&
              open_error != ERROR_PATH_NOT_FOUND)
            return;
        }
      }
      if (!delete_open_handle(deployment.get()) &&
          GetLastError() != ERROR_DIR_NOT_EMPTY)
        return;
    }
    it.increment(error);
    if (error)
      return;
  }
}

bool deploy_shell_exe(const std::filesystem::path &source_exe,
                      std::filesystem::path &installed_exe) {
  std::filesystem::path root;
  if (!local_shell_root(root))
    return false;

  std::error_code error;
  if (!std::filesystem::is_regular_file(source_exe, error) || error)
    return false;
  bool root_exists = false;
  if (!prepare_directory_tree(root, true, root_exists) || !root_exists)
    return false;
  std::vector<unique_win_handle> root_locks;
  if (!lock_directory_tree(root, root_locks))
    return false;

  std::filesystem::path directory;
  for (unsigned attempt = 0; attempt < 16; ++attempt) {
    std::wstring name;
    if (!random_deployment_name(name))
      return false;
    directory = root / name;
    if (CreateDirectoryW(directory.c_str(), nullptr) != FALSE)
      break;
    if (GetLastError() != ERROR_ALREADY_EXISTS)
      return false;
    directory.clear();
  }
  if (directory.empty())
    return false;

  unique_win_handle directory_lock{CreateFileW(
      directory.c_str(), FILE_READ_ATTRIBUTES,
      FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
  FILE_ATTRIBUTE_TAG_INFO directory_attributes{};
  if (!directory_lock ||
      !GetFileInformationByHandleEx(directory_lock.get(), FileAttributeTagInfo,
                                    &directory_attributes,
                                    sizeof(directory_attributes)) ||
      (directory_attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
      (directory_attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
    return false;

  installed_exe = directory / L"Oblivion.exe";
  if (!std::filesystem::copy_file(source_exe, installed_exe,
                                  std::filesystem::copy_options::none,
                                  error) ||
      error) {
    directory_lock.reset();
    std::filesystem::remove(directory, error);
    return false;
  }

  clean_old_deployments(root, directory);
  return true;
}

bool add_static_command(const std::wstring &menu_root, const wchar_t *name,
                        const wchar_t *title, const std::wstring &icon,
                        const std::wstring &command) {
  const auto key = menu_root + L"\\shell\\" + name;
  return set_string(HKEY_CURRENT_USER, key, nullptr, title) &&
         set_string(HKEY_CURRENT_USER, key, L"MUIVerb", title) &&
         set_string(HKEY_CURRENT_USER, key, L"Icon", icon) &&
         set_string(HKEY_CURRENT_USER, key, L"MultiSelectModel", L"Player") &&
         set_string(HKEY_CURRENT_USER, key + L"\\command", nullptr, command);
}

bool add_recycle_bin_menu(const std::filesystem::path &exe) {
  const auto executable = exe.wstring();
  const std::wstring root =
      L"Software\\Classes\\CLSID\\{645FF040-5081-101B-9F08-00AA002F954E}\\shell\\OblivionEmpty";
  const auto quoted_exe = L"\"" + executable + L"\"";
  const auto icon = L"\"" + executable + L"\",-" +
                    std::to_wstring(IDI_OBLIVION_WARNING);
  constexpr wchar_t title[] = L"Papierkorb mit Oblivion sicher leeren";

  return set_string(HKEY_CURRENT_USER, root, nullptr, title) &&
         set_string(HKEY_CURRENT_USER, root, L"MUIVerb", title) &&
         set_string(HKEY_CURRENT_USER, root, L"Icon", icon) &&
         set_string(HKEY_CURRENT_USER, root + L"\\command", nullptr,
                    quoted_exe + L" --empty-recycle-bin");
}

bool add_drive_menu(const std::filesystem::path &exe) {
  const auto executable = exe.wstring();
  const auto quoted_exe = L"\"" + executable + L"\"";
  const auto icon = L"\"" + executable + L"\",-" +
                    std::to_wstring(IDI_OBLIVION_WARNING);
  return add_static_command(
      L"Software\\Classes\\Drive", L"OblivionWipeFree",
      L"Freien Speicherplatz mit Oblivion überschreiben", icon,
      quoted_exe + L" --wipe-free-space \"%1.\"");
}

bool add_static_menu(const std::wstring &class_root,
                     const std::filesystem::path &exe) {
  const auto executable = exe.wstring();
  const auto base = L"Software\\Classes\\" + class_root;
  const auto icon = [&](const int id) {
    return L"\"" + executable + L"\",-" + std::to_wstring(id);
  };
  const auto quoted_exe = L"\"" + executable + L"\"";

  return add_static_command(base, L"OblivionErase",
                            L"Mit Oblivion sicher löschen",
                            icon(IDI_OBLIVION_WARNING),
                            quoted_exe + L" --shell-batch erase \"%1\"") &&
         add_static_command(base, L"OblivionAnalyze",
                            L"Mit Oblivion analysieren (Dry Run)",
                            icon(IDI_OBLIVION_ANALYZE),
                            quoted_exe + L" --shell-batch analyze \"%1\"") &&
         add_static_command(base, L"OblivionSettings", L"Oblivion Optionen",
                            icon(IDI_OBLIVION_SETTINGS),
                            quoted_exe + L" --settings-singleton");
}

bool clean_deployments() {
  std::filesystem::path root;
  if (!local_shell_root(root))
    return false;
  bool root_exists = false;
  if (!prepare_directory_tree(root, false, root_exists))
    return false;
  if (!root_exists)
    return true;
  std::vector<unique_win_handle> root_locks;
  if (!lock_directory_tree(root, root_locks) || root_locks.empty())
    return false;
  root_locks.back().reset();
  root_locks.pop_back();
  unique_win_handle root_handle{CreateFileW(
      root.c_str(), DELETE | FILE_READ_ATTRIBUTES,
      FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
  FILE_ATTRIBUTE_TAG_INFO root_attributes{};
  if (!root_handle ||
      !GetFileInformationByHandleEx(root_handle.get(), FileAttributeTagInfo,
                                    &root_attributes, sizeof(root_attributes)) ||
      (root_attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
      (root_attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
    return false;
  std::error_code error;
  std::filesystem::directory_iterator it(root, error), end;
  if (error)
    return false;
  while (it != end) {
    const auto name = it->path().filename().wstring();
    if (name.starts_with(L"deploy-") || name.starts_with(L"build-")) {
      unique_win_handle deployment{CreateFileW(
          it->path().c_str(), DELETE | FILE_READ_ATTRIBUTES,
          FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
          FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
      FILE_ATTRIBUTE_TAG_INFO attributes{};
      if (!deployment ||
          !GetFileInformationByHandleEx(deployment.get(), FileAttributeTagInfo,
                                        &attributes, sizeof(attributes)))
        return false;
      const bool is_directory =
          (attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
      const bool is_reparse =
          (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
      if (is_directory && !is_reparse) {
        const auto executable = it->path() / L"Oblivion.exe";
        unique_win_handle executable_handle{CreateFileW(
            executable.c_str(), DELETE | FILE_READ_ATTRIBUTES, 0, nullptr,
            OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
        if (executable_handle) {
          FILE_ATTRIBUTE_TAG_INFO executable_attributes{};
          if (!GetFileInformationByHandleEx(
                  executable_handle.get(), FileAttributeTagInfo,
                  &executable_attributes, sizeof(executable_attributes)) ||
              (executable_attributes.FileAttributes &
               (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
              !delete_open_handle(executable_handle.get()))
            return false;
          executable_handle.reset();
        } else {
          const DWORD executable_error = GetLastError();
          if (executable_error != ERROR_FILE_NOT_FOUND &&
              executable_error != ERROR_PATH_NOT_FOUND)
            return false;
        }
      }
      if (!delete_open_handle(deployment.get())) {
        const DWORD delete_error = GetLastError();
        if (delete_error != ERROR_DIR_NOT_EMPTY)
          return false;
      }
    }
    it.increment(error);
    if (error)
      return false;
  }
  if (delete_open_handle(root_handle.get()))
    return true;
  return GetLastError() == ERROR_DIR_NOT_EMPTY;
}

bool remove_com_registration() {
  bool ok = true;
  for (const auto *class_id : {ROOT, ERASE, ANALYZE, SETTINGS})
    ok = remove_key(L"Software\\Classes\\CLSID\\" + std::wstring{class_id}) &&
         ok;
  return ok;
}
bool remove_context_menu_keys(HKEY root) {
  bool ok = true;
  for (const auto *class_root : {L"*", L"Directory"}) {
    const auto base = L"Software\\Classes\\" + std::wstring{class_root} +
                      L"\\shell\\";
    ok = remove_key(root, base + L"Oblivion") && ok;
    ok = remove_key(root, base + L"OblivionErase") && ok;
    ok = remove_key(root, base + L"OblivionAnalyze") && ok;
    ok = remove_key(root, base + L"OblivionSettings") && ok;
  }
  ok = remove_key(root, L"Software\\Classes\\Drive\\shell\\OblivionWipeFree") &&
       ok;
  ok = remove_key(root,
                  L"Software\\Classes\\CLSID\\{645FF040-5081-101B-9F08-"
                  L"00AA002F954E}\\shell\\OblivionEmpty") &&
       ok;
  return ok;
}

bool try_elevated_machine_uninstall() {
  std::wstring current(32768, L'\0');
  const DWORD length = GetModuleFileNameW(
      nullptr, current.data(), static_cast<DWORD>(current.size()));
  std::vector<std::filesystem::path> candidates;
  if (length > 0 && static_cast<std::size_t>(length) < current.size()) {
    current.resize(length);
    candidates.emplace_back(current);
  }
  unique_cotaskmem_string program_files;
  if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_ProgramFiles, KF_FLAG_DONT_VERIFY,
                                     nullptr, program_files.put())) &&
      program_files) {
    const auto installed =
        std::filesystem::path{program_files.get()} / L"Oblivion" / L"Oblivion.exe";
    candidates.push_back(installed);
  }

  for (const auto &candidate : candidates) {
    DWORD exit_code = 1;
    if (relaunch_elevated_and_wait(candidate, {L"--uninstall-shell-quiet"},
                                   exit_code))
      return exit_code == 0;
  }
  return false;
}
} // namespace

shell_result install_context_menu(const std::filesystem::path &exe,
                                  const std::filesystem::path &dll) {
  (void)dll;
  const auto previous = uninstall_context_menu();
  if (!previous.success)
    return {false, L"Vorhandene Kontextmenü-Registrierung konnte nicht "
                   L"vollständig entfernt werden; Neuinstallation wurde "
                   L"abgebrochen."};

  std::filesystem::path installed_exe;
  bool ok = deploy_shell_exe(exe, installed_exe);
  ok = ok && remove_legacy_commands();
  ok = ok && remove_com_registration();
  for (const auto *class_root : {L"*", L"Directory"})
    ok = ok && add_static_menu(class_root, installed_exe);
  ok = ok && add_drive_menu(installed_exe);
  ok = ok && add_recycle_bin_menu(installed_exe);
  ok = ok && register_modern_context_menu(exe);

  if (!ok) {
    const auto rollback = uninstall_context_menu();
    return {false, rollback.success
                       ? L"Kontextmenü konnte nicht vollständig installiert "
                         L"werden; Teilregistrierungen wurden zurückgerollt."
                       : L"Kontextmenü konnte nicht vollständig installiert "
                         L"werden und auch der Rollback blieb unvollständig. "
                         L"Bitte Shellintegration erneut entfernen."};
  }

  SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nullptr, nullptr);
  return {true,
          L"OBLIVION-Untermenü für das moderne und klassische Explorer-Menü "
          L"installiert. Mehrfachauswahl wird nativ unterstützt."};
}

shell_result uninstall_context_menu() {
  bool ok = unregister_modern_context_menu();
  ok = remove_context_menu_keys(HKEY_CURRENT_USER) && ok;
  ok = remove_legacy_commands() && ok;
  ok = remove_com_registration() && ok;
  ok = clean_deployments() && ok;

  bool removed_machine_wide = false;
  if (machine_wide_context_menu_present()) {
    if (is_process_elevated()) {
      const bool machine_ok = remove_context_menu_keys(HKEY_LOCAL_MACHINE);
      ok = machine_ok && ok;
      removed_machine_wide = machine_ok && !machine_wide_context_menu_present();
    } else if (ok && try_elevated_machine_uninstall() &&
               !machine_wide_context_menu_present()) {
      removed_machine_wide = true;
    }
  }

  SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nullptr, nullptr);
  if (!ok)
    return {false, L"Shellintegration konnte nicht vollständig entfernt "
                   L"werden."};
  if (machine_wide_context_menu_present())
    return {true,
            L"Benutzerbezogene OBLIVION-Shellintegration entfernt. "
            L"Systemweit durch den MSI-Installer installierte Einträge bleiben "
            L"bestehen und müssen über die installierte Anwendung entfernt "
            L"oder aktualisiert werden."};
  if (removed_machine_wide)
    return {true,
            L"OBLIVION-Shellintegration (inkl. systemweiter MSI-Einträge) "
            L"entfernt."};
  return {true, L"OBLIVION-Shellintegration entfernt."};
}
} // namespace oblivion
