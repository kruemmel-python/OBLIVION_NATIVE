#include "oblivion/shell_integration.hpp"
#include "oblivion/resource_ids.h"

#include <Windows.h>
#include <shlobj.h>

#include <filesystem>
#include <limits>
#include <string>

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
  const auto bytes = (value.size() + 1) * sizeof(wchar_t);
  if (bytes > (std::numeric_limits<DWORD>::max)()) {
    RegCloseKey(handle);
    return false;
  }
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

bool file_identity(const std::filesystem::path &path, std::wstring &identity) {
  WIN32_FILE_ATTRIBUTE_DATA data{};
  if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data) ||
      (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
    return false;
  identity = std::to_wstring(data.ftLastWriteTime.dwHighDateTime) + L"-" +
             std::to_wstring(data.ftLastWriteTime.dwLowDateTime) + L"-" +
             std::to_wstring(data.nFileSizeHigh) + L"-" +
             std::to_wstring(data.nFileSizeLow);
  return true;
}

bool local_shell_root(std::filesystem::path &root) {
  PWSTR local = nullptr;
  const HRESULT result =
      SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_CREATE, nullptr, &local);
  if (FAILED(result) || !local)
    return false;
  root = std::filesystem::path{local} / L"Oblivion" / L"Shell";
  CoTaskMemFree(local);
  return true;
}

void clean_old_deployments(const std::filesystem::path &root,
                           const std::filesystem::path &keep) {
  std::error_code error;
  std::filesystem::directory_iterator it(root, error), end;
  if (error)
    return;
  while (it != end) {
    const bool is_directory = it->is_directory(error);
    if (error)
      return;
    if (is_directory) {
      if (std::filesystem::equivalent(it->path(), keep, error)) {
        if (error)
          return;
      } else {
        std::filesystem::remove_all(it->path(), error);
        if (error)
          return;
      }
    }
    it.increment(error);
    if (error)
      return;
  }
}

bool deploy_shell_exe(const std::filesystem::path &source_exe,
                      std::filesystem::path &installed_exe) {
  std::wstring identity;
  std::filesystem::path root;
  if (!file_identity(source_exe, identity) || !local_shell_root(root))
    return false;

  const auto directory = root / (L"build-" + identity);
  std::error_code error;
  std::filesystem::create_directories(directory, error);
  if (error)
    return false;

  installed_exe = directory / L"Oblivion.exe";
  if (!std::filesystem::exists(installed_exe, error)) {
    error.clear();
    if (!std::filesystem::copy_file(source_exe, installed_exe,
                                    std::filesystem::copy_options::none,
                                    error) ||
        error)
      return false;
  } else if (error) {
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
  const auto icon = executable + L",-" + std::to_wstring(IDI_OBLIVION_WARNING);
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
  const auto icon = executable + L",-" + std::to_wstring(IDI_OBLIVION_WARNING);
  return add_static_command(
      L"Software\\Classes\\Drive", L"OblivionWipeFree",
      L"Freien Speicherplatz mit Oblivion überschreiben", icon,
      quoted_exe + L" --wipe-free-space \"%1\"");
}

bool add_static_menu(const std::wstring &class_root,
                     const std::filesystem::path &exe) {
  const auto executable = exe.wstring();
  const auto base = L"Software\\Classes\\" + class_root;
  const auto icon = [&](const int id) {
    return executable + L",-" + std::to_wstring(id);
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

void clean_deployments() {
  std::filesystem::path root;
  if (!local_shell_root(root))
    return;
  std::error_code error;
  std::filesystem::remove_all(root, error);
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
  (void)uninstall_context_menu();

  std::filesystem::path installed_exe;
  bool ok = deploy_shell_exe(exe, installed_exe);
  ok = ok && remove_legacy_commands();
  ok = ok && remove_com_registration();
  for (const auto *class_root : {L"*", L"Directory"})
    ok = ok && add_static_menu(class_root, installed_exe);
  ok = ok && add_drive_menu(installed_exe);
  ok = ok && add_recycle_bin_menu(installed_exe);

  SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nullptr, nullptr);
  return {ok,
          ok ? L"OBLIVION-Kontextmenü installiert. Mehrfachauswahl wird "
               L"nativ in Oblivion.exe gebündelt; Explorer lädt keine "
               L"OBLIVION-COM-DLL."
             : L"Kontextmenü konnte nicht vollständig installiert werden."};
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
  clean_deployments();
  SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nullptr, nullptr);
  return {ok, ok ? L"OBLIVION-Shellintegration entfernt."
                 : L"Shellintegration konnte nicht vollständig entfernt "
                   L"werden."};
}
} // namespace oblivion
