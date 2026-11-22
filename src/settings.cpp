#include "oblivion/settings.hpp"

#include <Windows.h>

#include <algorithm>
#include <optional>

namespace oblivion {
namespace {
constexpr wchar_t key_name[] = L"Software\\Oblivion";
constexpr wchar_t policy_key_name[] = L"Software\\Policies\\Oblivion";

bool read_dword(HKEY key, const wchar_t *name, DWORD &value) noexcept {
  DWORD type = 0, size = sizeof(value);
  return RegQueryValueExW(key, name, nullptr, &type,
                          reinterpret_cast<BYTE *>(&value), &size) ==
             ERROR_SUCCESS &&
         type == REG_DWORD && size == sizeof(value);
}

bool write_dword(HKEY key, const wchar_t *name, const DWORD value) noexcept {
  return RegSetValueExW(key, name, 0, REG_DWORD,
                        reinterpret_cast<const BYTE *>(&value),
                        sizeof(value)) == ERROR_SUCCESS;
}

std::optional<DWORD> policy_dword(const wchar_t *name) noexcept {
  for (const HKEY root : {HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER}) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, policy_key_name, 0, KEY_QUERY_VALUE, &key) !=
        ERROR_SUCCESS)
      continue;
    DWORD value = 0;
    const bool found = read_dword(key, name, value);
    RegCloseKey(key);
    if (found)
      return value;
  }
  return std::nullopt;
}
} // namespace

void apply_security_policy(erase_options &options) noexcept {
  if (const auto mode = policy_dword(L"EraseMode");
      mode && *mode <= static_cast<DWORD>(erase_mode::gutmann))
    options.mode = static_cast<erase_mode>(*mode);
  if (const auto verify = policy_dword(L"EnforceVerification");
      verify && *verify != 0)
    options.verify = true;
  if (!shared_hardlink_overwrite_allowed() &&
      options.hardlinks == hardlink_policy::overwrite_shared_content)
    options.hardlinks = hardlink_policy::block;
}

bool shared_hardlink_overwrite_allowed() noexcept {
  const auto policy = policy_dword(L"DisallowSharedHardlinkOverwrite");
  return !policy || *policy == 0;
}

erase_options load_default_erase_options() {
  erase_options options;
  HKEY key = nullptr;
  if (RegOpenKeyExW(HKEY_CURRENT_USER, key_name, 0, KEY_QUERY_VALUE, &key) ==
      ERROR_SUCCESS) {
    DWORD value = 0;
    if (read_dword(key, L"EraseMode", value) &&
        value <= static_cast<DWORD>(erase_mode::gutmann))
      options.mode = static_cast<erase_mode>(value);
    if (read_dword(key, L"Verify", value))
      options.verify = value != 0;
    if (read_dword(key, L"EraseAlternateStreams", value))
      options.erase_alternate_streams = value != 0;
    if (read_dword(key, L"RenameBeforeDelete", value))
      options.rename_before_delete = value != 0;
    if (read_dword(key, L"RenameRounds", value))
      options.rename_rounds =
          static_cast<unsigned>((std::min)(value, DWORD{32}));
    if (read_dword(key, L"HardlinkPolicy", value) &&
        value == static_cast<DWORD>(hardlink_policy::delete_link_only))
      options.hardlinks = hardlink_policy::delete_link_only;
    RegCloseKey(key);
  }
  apply_security_policy(options);
  return options;
}

bool save_default_erase_options(const erase_options &options) {
  HKEY key = nullptr;
  if (RegCreateKeyExW(HKEY_CURRENT_USER, key_name, 0, nullptr, 0,
                      KEY_SET_VALUE, nullptr, &key, nullptr) != ERROR_SUCCESS)
    return false;
  const auto hardlinks =
      options.hardlinks == hardlink_policy::delete_link_only
          ? hardlink_policy::delete_link_only
          : hardlink_policy::block;
  const bool ok =
      write_dword(key, L"EraseMode", static_cast<DWORD>(options.mode)) &&
      write_dword(key, L"Verify", options.verify ? 1u : 0u) &&
      write_dword(key, L"EraseAlternateStreams",
                  options.erase_alternate_streams ? 1u : 0u) &&
      write_dword(key, L"RenameBeforeDelete",
                  options.rename_before_delete ? 1u : 0u) &&
      write_dword(key, L"RenameRounds",
                  static_cast<DWORD>((std::min)(options.rename_rounds, 32u))) &&
      write_dword(key, L"HardlinkPolicy", static_cast<DWORD>(hardlinks));
  RegCloseKey(key);
  return ok;
}

bool reset_default_erase_options() {
  const LONG result = RegDeleteTreeW(HKEY_CURRENT_USER, key_name);
  return result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND;
}
} // namespace oblivion
