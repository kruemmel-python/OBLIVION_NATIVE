#include "oblivion/shell_integration.hpp"
#include "oblivion/cotaskmem_string.hpp"
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

bool remove_key(const std::wstring &key) {
  const LONG result = RegDeleteTreeW(HKEY_CURRENT_USER, key.c_str());
  return result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND;
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

  // Register direct top-level verbs instead of SubCommands="" so third-party
  // context-menu replacements (e.g. Nilesoft Shell) and classic Explorer both
  // display them.
  bool ok = add_static_command(
      base, L"OblivionErase", L"Mit Oblivion sicher löschen",
      icon(IDI_OBLIVION_WARNING), quoted_exe + L" --shell-batch erase \"%1\"");
  ok = ok && add_static_command(
                 base, L"OblivionAnalyze",
                 L"Mit Oblivion analysieren (Dry Run)",
                 icon(IDI_OBLIVION_ANALYZE),
                 quoted_exe + L" --shell-batch analyze \"%1\"");
  ok = ok && add_static_command(base, L"OblivionSettings", L"Oblivion: Optionen",
                                icon(IDI_OBLIVION_SETTINGS),
                                quoted_exe + L" --settings-singleton");
  return ok;
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
          L"OBLIVION-Kontextmenü installiert. Mehrfachauswahl wird nativ "
          L"in Oblivion.exe gebündelt; Explorer lädt keine OBLIVION-COM-DLL."};
}

shell_result uninstall_context_menu() {
  bool ok = true;
  for (const auto *class_root : {L"*", L"Directory"}) {
    const auto base = L"Software\\Classes\\" + std::wstring{class_root} +
                      L"\\shell\\";
    ok = remove_key(base + L"Oblivion") && ok;
    ok = remove_key(base + L"OblivionErase") && ok;
    ok = remove_key(base + L"OblivionAnalyze") && ok;
    ok = remove_key(base + L"OblivionSettings") && ok;
  }
  ok = remove_key(L"Software\\Classes\\Drive\\shell\\OblivionWipeFree") && ok;
  ok = remove_key(L"Software\\Classes\\CLSID\\{645FF040-5081-101B-9F08-00AA002F954E}\\shell\\OblivionEmpty") && ok;
  ok = remove_legacy_commands() && ok;
  ok = remove_com_registration() && ok;
  ok = clean_deployments() && ok;
  SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nullptr, nullptr);
  return {ok, ok ? L"OBLIVION-Shellintegration entfernt."
                 : L"Shellintegration konnte nicht vollständig entfernt "
                   L"werden."};
}
} // namespace oblivion
