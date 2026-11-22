#include "oblivion/elevation.hpp"
#include "oblivion/cotaskmem_string.hpp"
#include "oblivion/win_handle.hpp"

#include <Windows.h>
#include <ShlObj.h>
#include <shellapi.h>

#include <filesystem>
#include <limits>
#include <string>
#include <vector>

namespace oblivion {
namespace {

std::wstring quote(const std::wstring &value) {
  std::wstring result = L"\"";
  std::size_t slashes = 0;
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

bool same_path(const std::filesystem::path &left,
               const std::filesystem::path &right) noexcept try {
  const auto l = left.lexically_normal().wstring();
  const auto r = right.lexically_normal().wstring();
  if (l.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)()) ||
      r.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)()))
    return false;
  return CompareStringOrdinal(l.c_str(), static_cast<int>(l.size()), r.c_str(),
                              static_cast<int>(r.size()), TRUE) == CSTR_EQUAL;
} catch (...) {
  return false;
}

bool below(const std::filesystem::path &candidate,
           const std::filesystem::path &root) noexcept try {
  const auto normalized_candidate = candidate.lexically_normal();
  const auto normalized_root = root.lexically_normal();
  if (same_path(normalized_candidate, normalized_root))
    return true;
  auto candidate_text = normalized_candidate.wstring();
  auto root_text = normalized_root.wstring();
  if (root_text.empty())
    return false;
  if (root_text.back() != L'\\')
    root_text.push_back(L'\\');
  if (candidate_text.size() < root_text.size() ||
      root_text.size() >
          static_cast<std::size_t>((std::numeric_limits<int>::max)()))
    return false;
  return CompareStringOrdinal(candidate_text.c_str(),
                              static_cast<int>(root_text.size()),
                              root_text.c_str(),
                              static_cast<int>(root_text.size()), TRUE) ==
         CSTR_EQUAL;
} catch (...) {
  return false;
}

bool lock_trusted_elevation_executable(
    const std::filesystem::path &executable,
    std::vector<unique_win_handle> &directory_locks,
    unique_win_handle &executable_lock) noexcept try {
  unique_cotaskmem_string program_files_value;
  if (FAILED(SHGetKnownFolderPath(FOLDERID_ProgramFiles, KF_FLAG_DONT_VERIFY,
                                  nullptr, program_files_value.put())) ||
      !program_files_value)
    return false;

  std::error_code error;
  const auto absolute =
      std::filesystem::absolute(executable, error).lexically_normal();
  if (error || absolute.empty())
    return false;
  const auto program_files =
      std::filesystem::canonical(program_files_value.get(), error);
  if (error || program_files.empty() || !below(absolute, program_files))
    return false;
  const auto canonical = std::filesystem::canonical(absolute, error);
  if (error || !below(canonical, program_files) ||
      !same_path(canonical, absolute))
    return false;

  directory_locks.clear();
  auto current = program_files.root_path();
  for (const auto &component : program_files.relative_path()) {
    current /= component;
    unique_win_handle handle{CreateFileW(
        current.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    if (!handle ||
        !GetFileInformationByHandleEx(handle.get(), FileAttributeTagInfo,
                                      &attributes, sizeof(attributes)) ||
        (attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
        (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
      return false;
    directory_locks.push_back(std::move(handle));
  }
  const auto relative_parent =
      canonical.parent_path().lexically_relative(program_files);
  for (const auto &component : relative_parent) {
    if (component.empty() || component == L".")
      continue;
    if (component == L"..")
      return false;
    current /= component;
    unique_win_handle handle{CreateFileW(
        current.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    if (!handle ||
        !GetFileInformationByHandleEx(handle.get(), FileAttributeTagInfo,
                                      &attributes, sizeof(attributes)) ||
        (attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
        (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
      return false;
    directory_locks.push_back(std::move(handle));
  }

  executable_lock.reset(CreateFileW(
      canonical.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
  FILE_ATTRIBUTE_TAG_INFO executable_attributes{};
  return executable_lock &&
         GetFileInformationByHandleEx(executable_lock.get(),
                                      FileAttributeTagInfo,
                                      &executable_attributes,
                                      sizeof(executable_attributes)) != FALSE &&
         (executable_attributes.FileAttributes &
          (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0;
} catch (...) {
  return false;
}

} // namespace

bool is_process_elevated() {
  HANDLE raw = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw))
    return false;
  unique_win_handle token{raw};
  TOKEN_ELEVATION elevation{};
  DWORD returned = 0;
  return GetTokenInformation(token.get(), TokenElevation, &elevation,
                             sizeof(elevation), &returned) != FALSE &&
         elevation.TokenIsElevated != 0;
}

bool relaunch_elevated(const std::filesystem::path &executable,
                       const std::vector<std::wstring> &arguments) try {
  if (executable.empty())
    return false;
  std::vector<unique_win_handle> directory_locks;
  unique_win_handle executable_lock;
  if (!lock_trusted_elevation_executable(executable, directory_locks,
                                         executable_lock))
    return false;

  constexpr std::size_t max_command_chars = 32766u;
  std::wstring parameters;
  for (const auto &argument : arguments) {
    const auto quoted = quote(argument);
    const std::size_t separator = parameters.empty() ? 0u : 1u;
    if (quoted.size() > max_command_chars - parameters.size() ||
        separator > max_command_chars - parameters.size() - quoted.size())
      return false;
    if (separator)
      parameters.push_back(L' ');
    parameters += quoted;
  }

  SHELLEXECUTEINFOW info{};
  info.cbSize = sizeof(info);
  info.fMask = SEE_MASK_NOCLOSEPROCESS;
  info.lpVerb = L"runas";
  info.lpFile = executable.c_str();
  info.lpParameters = parameters.c_str();
  info.nShow = SW_SHOWNORMAL;
  const bool launched = ShellExecuteExW(&info) != FALSE;
  unique_win_handle process{info.hProcess};
  return launched;
} catch (...) {
  return false;
}

} // namespace oblivion
