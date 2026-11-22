#include "oblivion/path_validator.hpp"
#include "oblivion/cotaskmem_string.hpp"
#include <Windows.h>
#include <ShlObj.h>
#include <algorithm>
#include <climits>
#include <cwctype>
#include <system_error>
#include <vector>
namespace oblivion {
namespace {
std::wstring low(std::wstring v) {
  std::transform(v.begin(), v.end(), v.begin(), [](wchar_t c) {
    return static_cast<wchar_t>(std::towlower(c));
  });
  return v;
}
std::filesystem::path known_folder(const KNOWNFOLDERID &id) {
  unique_cotaskmem_string value;
  if (FAILED(SHGetKnownFolderPath(id, KF_FLAG_DONT_VERIFY, nullptr,
                                  value.put())) ||
      !value)
    return {};
  std::filesystem::path result{value.get()};
  return result.lexically_normal();
}
std::filesystem::path windows_directory() {
  std::wstring value(32768, L'\0');
  const UINT written =
      GetWindowsDirectoryW(value.data(), static_cast<UINT>(value.size()));
  if (written == 0 || static_cast<std::size_t>(written) >= value.size())
    return {};
  value.resize(written);
  return std::filesystem::path{value}.lexically_normal();
}
bool same(const std::filesystem::path &a, const std::filesystem::path &b) {
  if (a.empty() || b.empty())
    return false;
  const auto left = a.lexically_normal().wstring();
  const auto right = b.lexically_normal().wstring();
  if (left.size() > static_cast<std::size_t>(INT_MAX) ||
      right.size() > static_cast<std::size_t>(INT_MAX))
    return false;
  return CompareStringOrdinal(left.c_str(), static_cast<int>(left.size()),
                              right.c_str(), static_cast<int>(right.size()),
                              TRUE) == CSTR_EQUAL;
}
bool below(const std::filesystem::path &c, const std::filesystem::path &r) {
  if (r.empty())
    return false;
  const auto candidate_path = c.lexically_normal();
  const auto root_path = r.lexically_normal();
  if (same(candidate_path, root_path))
    return true;
  auto cs = candidate_path.wstring(), rs = root_path.wstring();
  if (!rs.empty() && rs.back() != L'\\')
    rs.push_back(L'\\');
  if (cs.size() < rs.size() || rs.size() > static_cast<std::size_t>(INT_MAX))
    return false;
  return CompareStringOrdinal(cs.c_str(), static_cast<int>(rs.size()),
                              rs.c_str(), static_cast<int>(rs.size()), TRUE) ==
         CSTR_EQUAL;
}
bool remote(const std::filesystem::path &p) {
  auto v = low(p.wstring());
  return v.starts_with(L"\\\\") || v.starts_with(L"\\\\?\\") ||
         v.starts_with(L"\\\\.\\");
}
bool ads(const std::filesystem::path &p) {
  auto v = p.wstring();
  auto c = v.find(L':');
  return c != std::wstring::npos &&
         (c != 1 || v.find(L':', c + 1) != std::wstring::npos);
}
bool reparse_ancestor(const std::filesystem::path &p,
                      std::filesystem::path &bad) {
  auto root = p.root_path();
  auto rel = p.lexically_relative(root);
  if (root.empty() || rel.empty())
    return false;
  std::vector<std::filesystem::path> c;
  for (const auto &x : rel)
    c.push_back(x);
  auto cur = root;
  for (std::size_t i = 0; i + 1 < c.size(); ++i) {
    cur /= c[i];
    DWORD a = GetFileAttributesW(cur.c_str());
    if (a == INVALID_FILE_ATTRIBUTES || (a & FILE_ATTRIBUTE_REPARSE_POINT)) {
      bad = cur;
      return true;
    }
  }
  return false;
}
validation_result block(const std::filesystem::path &p, std::wstring r,
                        path_criticality c) {
  return {false, std::move(r), p, c};
}
} // namespace
validation_result
path_validator::validate(const std::filesystem::path &path) const {
  if (path.empty())
    return block({}, L"Leerer Pfad.", path_criticality::critical);
  if (remote(path) && !allow_remote_)
    return block(path,
                 L"UNC-, Netzwerk- und Geräte-Namespace-Pfade sind gesperrt.",
                 path_criticality::system);
  if (ads(path))
    return block(path,
                 L"Direkte ADS-Ziele sind gesperrt; wähle die Basisdatei.",
                 path_criticality::system);
  std::error_code ec;
  if (!std::filesystem::exists(path, ec) || ec)
    return block(path, L"Ziel existiert nicht oder ist nicht zugreifbar.",
                 path_criticality::safe);
  auto abs = std::filesystem::absolute(path, ec);
  if (ec)
    return block(path, L"Pfad konnte nicht absolut aufgelöst werden.",
                 path_criticality::system);
  auto n = abs.lexically_normal();
  auto safety_path = std::filesystem::canonical(n, ec);
  if (ec)
    return block(n, L"Ziel konnte nicht kanonisch für die Schutzprüfung "
                    L"aufgelöst werden.",
                 path_criticality::system);
  safety_path = safety_path.lexically_normal();
  const auto root = safety_path.root_path().lexically_normal();
  std::filesystem::path bad;
  if (reparse_ancestor(n, bad))
    return block(
        n,
        L"Ziel liegt unter einem nicht verifizierbaren oder Reparse-/"
        L"Junction-/Symlink-Vorfahren: " +
            bad.wstring(),
        path_criticality::system);
  if (!root.empty() && same(safety_path, root))
    return block(n, L"Laufwerks-/Volume-Wurzeln sind hart gesperrt.",
                 path_criticality::critical);
  const auto win = windows_directory();
  const auto pf = known_folder(FOLDERID_ProgramFiles);
  const auto pfx = known_folder(FOLDERID_ProgramFilesX86);
  const auto pd = known_folder(FOLDERID_ProgramData);
  const auto up = known_folder(FOLDERID_Profile);
  const auto profiles = known_folder(FOLDERID_UserProfiles);
  const auto local_app_data = known_folder(FOLDERID_LocalAppData);
  if (win.empty() || pf.empty() || pd.empty() || up.empty() ||
      profiles.empty() || local_app_data.empty())
    return block(n, L"Windows-Schutzpfade konnten nicht verlässlich bestimmt "
                    L"werden.",
                 path_criticality::critical);
  if (below(safety_path, win))
    return block(n, L"Windows-Systempfade sind hart gesperrt.",
                 path_criticality::critical);
  if (below(safety_path, pf) || below(safety_path, pfx))
    return block(n, L"Program-Files-Pfade sind hart gesperrt.",
                 path_criticality::critical);
  if (below(safety_path, pd))
    return block(n, L"ProgramData ist gesperrt.", path_criticality::system);
  if (below(safety_path,
            (local_app_data / L"Oblivion").lexically_normal()))
    return block(n, L"OBLIVION-Audit- und Anwendungszustand ist gesperrt.",
                 path_criticality::critical);
  if (same(safety_path, up))
    return block(n, L"Benutzerprofil-Wurzel ist gesperrt.",
                 path_criticality::critical);
  if (same(safety_path, profiles) ||
      (below(safety_path, profiles) && !below(safety_path, up)))
    return block(n, L"Fremde Windows-Benutzerprofilbäume sind gesperrt.",
                 path_criticality::critical);
  std::vector<std::wstring> roots{L"system volume information", L"$recycle.bin",
                                  L"recovery", L"efi", L"boot"};
  if (!root.empty()) {
    auto rel = safety_path.lexically_relative(root);
    if (!rel.empty()) {
      auto it = rel.begin();
      auto first = low(it->wstring());
      if (first == L"$recycle.bin" && allow_recycle_bin_items_) {
        std::size_t depth = 0;
        for (const auto &part : rel) {
          if (!part.empty() && part != L".")
            ++depth;
        }
        const auto fname = low(safety_path.filename().wstring());
        if (depth < 3 || fname == L"desktop.ini")
          return block(n, L"Geschützter Papierkorb-Systemeintrag.",
                       path_criticality::critical);
      } else if (std::ranges::find(roots, first) != roots.end()) {
        return block(n, L"Geschützter Volume-/Boot-/Recovery-Bereich.",
                     path_criticality::critical);
      }
    }
  }
  std::vector<std::wstring> files{L"pagefile.sys", L"hiberfil.sys",
                                  L"swapfile.sys", L"bootmgr", L"bootnxt"};
  if (std::ranges::find(files, low(safety_path.filename().wstring())) !=
      files.end())
    return block(n, L"Windows-kritische Systemdatei ist gesperrt.",
                 path_criticality::critical);
  DWORD a = GetFileAttributesW(n.c_str());
  return {true,
          (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_REPARSE_POINT))
              ? L"Reparse Point erkannt; nur der Link selbst wird entfernt."
              : L"OK",
          n, path_criticality::safe};
}
} // namespace oblivion
