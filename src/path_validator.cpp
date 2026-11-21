#include "oblivion/path_validator.hpp"
#include <Windows.h>
#include <algorithm>
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
std::filesystem::path env(const wchar_t *n) {
  DWORD need = GetEnvironmentVariableW(n, nullptr, 0);
  if (!need)
    return {};
  std::wstring v(need, L'\0');
  DWORD w = GetEnvironmentVariableW(n, v.data(), need);
  if (!w || w >= need)
    return {};
  v.resize(w);
  return std::filesystem::path{v}.lexically_normal();
}
bool same(const std::filesystem::path &a, const std::filesystem::path &b) {
  return !a.empty() && !b.empty() &&
         low(a.lexically_normal().wstring()) ==
             low(b.lexically_normal().wstring());
}
bool below(const std::filesystem::path &c, const std::filesystem::path &r) {
  if (r.empty())
    return false;
  auto cs = low(c.lexically_normal().wstring()),
       rs = low(r.lexically_normal().wstring());
  if (!rs.empty() && rs.back() != L'\\')
    rs.push_back(L'\\');
  return cs == rs.substr(0, rs.size() - 1) || cs.starts_with(rs);
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
    if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_REPARSE_POINT)) {
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
  auto n = abs.lexically_normal(), root = n.root_path().lexically_normal();
  std::filesystem::path bad;
  if (reparse_ancestor(n, bad))
    return block(
        n,
        L"Ziel liegt unter einem Reparse-/Junction-/Symlink-Vorfahren: " +
            bad.wstring(),
        path_criticality::system);
  if (!root.empty() && same(n, root))
    return block(n, L"Laufwerks-/Volume-Wurzeln sind hart gesperrt.",
                 path_criticality::critical);
  auto win = env(L"SystemRoot"), pf = env(L"ProgramFiles"),
       pfx = env(L"ProgramFiles(x86)"), pd = env(L"ProgramData"),
       up = env(L"USERPROFILE"), sd = env(L"SystemDrive");
  if (below(n, win))
    return block(n, L"Windows-Systempfade sind hart gesperrt.",
                 path_criticality::critical);
  if (below(n, pf) || below(n, pfx))
    return block(n, L"Program-Files-Pfade sind hart gesperrt.",
                 path_criticality::critical);
  if (below(n, pd))
    return block(n, L"ProgramData ist gesperrt.", path_criticality::system);
  if (same(n, up))
    return block(n, L"Benutzerprofil-Wurzel ist gesperrt.",
                 path_criticality::critical);
  if (!sd.empty()) {
    std::filesystem::path users{sd.wstring() + L"\\Users"};
    if (same(n, users) || (below(n, users) && same(n.parent_path(), users)))
      return block(n, L"Windows-Benutzerprofil-Wurzeln sind gesperrt.",
                   path_criticality::critical);
  }
  std::vector<std::wstring> roots{L"system volume information", L"$recycle.bin",
                                  L"recovery", L"efi", L"boot"};
  if (!root.empty()) {
    auto rel = n.lexically_relative(root);
    if (!rel.empty()) {
      auto it = rel.begin();
      auto first = low(it->wstring());
      if (first == L"$recycle.bin" && allow_recycle_bin_items_) {
        std::size_t depth = 0;
        for (const auto &part : rel) {
          if (!part.empty() && part != L".")
            ++depth;
        }
        const auto fname = low(n.filename().wstring());
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
  if (std::ranges::find(files, low(n.filename().wstring())) != files.end())
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
