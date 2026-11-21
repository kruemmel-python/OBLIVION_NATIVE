#include "oblivion/app_logic.hpp"
#include "oblivion/analyzer.hpp"
#include "oblivion/audit.hpp"
#include "oblivion/erase_engine.hpp"
#include "oblivion/path_validator.hpp"
#include "oblivion/restart_manager.hpp"
#include "oblivion/storage_inspector.hpp"
#include <Windows.h>
#include <algorithm>
#include <chrono>
#include <cwctype>
#include <limits>
#include <set>
#include <sstream>
namespace oblivion {
namespace {
void merge(file_analysis &a, const file_analysis &b) {
  a.files += b.files;
  a.directories += b.directories;
  a.logical_bytes += b.logical_bytes;
  a.alternate_streams += b.alternate_streams;
  a.alternate_stream_bytes += b.alternate_stream_bytes;
  a.reparse_points += b.reparse_points;
  a.hardlinked_files += b.hardlinked_files;
  a.sparse_files += b.sparse_files;
  a.compressed_files += b.compressed_files;
  a.encrypted_files += b.encrypted_files;
  a.readonly_entries += b.readonly_entries;
  a.inaccessible_entries += b.inaccessible_entries;
  a.warnings.insert(a.warnings.end(), b.warnings.begin(), b.warnings.end());
}
std::wstring low(std::wstring v) {
  std::transform(v.begin(), v.end(), v.begin(), [](wchar_t c) {
    return static_cast<wchar_t>(std::towlower(c));
  });
  return v;
}
bool below(const std::filesystem::path &c, const std::filesystem::path &p) {
  auto a = low(c.lexically_normal().wstring()),
       b = low(p.lexically_normal().wstring());
  if (b.empty())
    return false;
  if (b.back() != L'\\')
    b.push_back(L'\\');
  return a.starts_with(b);
}
bool real_dir(const std::filesystem::path &p) {
  DWORD a = GetFileAttributesW(p.c_str());
  return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY) &&
         !(a & FILE_ATTRIBUTE_REPARSE_POINT);
}
std::uint64_t pc(erase_mode m) {
  switch (m) {
  case erase_mode::fast: return 1;
  case erase_mode::standard: return 2;
  case erase_mode::strong: return 3;
  case erase_mode::dod_5220_22_m: return 3;
  case erase_mode::nist_800_88: return 1;
  case erase_mode::bsi_gs: return 3;
  case erase_mode::gutmann: return 35;
  default: return 2;
  }
}
std::uint64_t sadd(std::uint64_t a, std::uint64_t b) {
  auto m = (std::numeric_limits<std::uint64_t>::max)();
  return b > m - a ? m : a + b;
}
std::uint64_t smul(std::uint64_t a, std::uint64_t b) {
  auto m = (std::numeric_limits<std::uint64_t>::max)();
  return a && b > m / a ? m : a * b;
}
std::wstring mode(erase_mode m) {
  switch (m) {
  case erase_mode::fast: return L"FAST";
  case erase_mode::strong: return L"STRONG";
  case erase_mode::dod_5220_22_m: return L"DoD 5220.22-M";
  case erase_mode::nist_800_88: return L"NIST SP 800-88";
  case erase_mode::bsi_gs: return L"BSI IT-Grundschutz";
  case erase_mode::gutmann: return L"Gutmann (35 Passes)";
  case erase_mode::standard:
  default: return L"STANDARD";
  }
}
std::wstring hp(hardlink_policy p) {
  return p == hardlink_policy::delete_link_only ? L"nur Linknamen entfernen"
         : p == hardlink_policy::overwrite_shared_content
             ? L"gemeinsamen Inhalt überschreiben"
             : L"blockieren";
}
std::wstring med(media_kind k) {
  return k == media_kind::solid_state  ? L"SSD/NVMe"
         : k == media_kind::rotational ? L"HDD"
                                       : L"unbekannt";
}
} // namespace
prepared_operation
prepare_operation(const std::vector<std::filesystem::path> &raw) {
  prepared_operation p;
  if (raw.empty()) {
    p.error = L"Keine Ziele angegeben.";
    return p;
  }
  path_validator v;
  analyzer a;
  storage_inspector si;
  std::set<std::wstring> seen;
  std::vector<std::filesystem::path> n;
  for (const auto &r : raw) {
    auto x = v.validate(r);
    if (!x.allowed) {
      p.error = L"Ziel blockiert:\n" + r.wstring() + L"\n\n" + x.reason;
      return p;
    }
    auto k = low(x.normalized.wstring());
    if (seen.insert(k).second) {
      n.push_back(x.normalized);
      if (x.reason != L"OK")
        p.warnings.push_back(x.reason + L" " + x.normalized.wstring());
    }
  }
  std::ranges::sort(n, [](const auto &a, const auto &b) {
    return a.wstring().size() < b.wstring().size();
  });
  for (const auto &c : n) {
    bool skip = false;
    for (const auto &parent : p.targets)
      if (real_dir(parent) && below(c, parent)) {
        p.warnings.push_back(L"Redundantes Kindziel übersprungen: " +
                             c.wstring());
        skip = true;
        break;
      }
    if (skip)
      continue;
    p.targets.push_back(c);
    auto ar = a.analyze(c);
    merge(p.analysis, ar);
    p.storage.push_back(si.inspect(c));
  }
  if (p.targets.empty()) {
    p.error = L"Keine eindeutigen Ziele übrig.";
    return p;
  }
  if (p.analysis.inaccessible_entries)
    p.warnings.push_back(L"Nicht alle Einträge waren vollständig zugreifbar.");
  if (p.analysis.hardlinked_files)
    p.warnings.push_back(
        L"Hardlinks erkannt; Standard ist Inhaltsüberschreibung blockieren.");
  if (p.analysis.reparse_points)
    p.warnings.push_back(
        L"Reparse Points erkannt; ihren Zielen wird niemals gefolgt.");
  p.valid = true;
  return p;
}
std::wstring format_prepared_analysis(const prepared_operation &p) {
  if (!p.valid)
    return p.error;

  struct storage_group {
    storage_info info;
    std::size_t target_count{0};
  };

  const auto same_volume = [](const storage_info &a, const storage_info &b) {
    if (!a.volume_guid.empty() && !b.volume_guid.empty())
      return low(a.volume_guid) == low(b.volume_guid);
    if (!a.volume_root.empty() && !b.volume_root.empty())
      return low(a.volume_root) == low(b.volume_root);
    return false;
  };

  std::vector<storage_group> groups;
  for (const auto &s : p.storage) {
    auto it = std::ranges::find_if(groups, [&](const storage_group &g) {
      return same_volume(g.info, s);
    });
    if (it == groups.end())
      groups.push_back({s, 1});
    else
      ++it->target_count;
  }

  std::wostringstream o;
  o << format_analysis_report(p.analysis, nullptr) << L"\nZiele:\n";
  for (std::size_t i = 0; i < p.targets.size(); ++i)
    o << L"\n[" << i + 1 << L"] " << p.targets[i].wstring();

  o << L"\n\nDatenträger: " << groups.size() << L"\n";
  for (std::size_t i = 0; i < groups.size(); ++i) {
    const auto &g = groups[i];
    const auto &s = g.info;
    o << L"\n[" << i + 1 << L"] "
      << (s.volume_root.empty() ? L"Volume unbekannt" : s.volume_root);
    if (g.target_count > 1)
      o << L" · " << g.target_count << L" Ziele";
    o << L"\n  Medium: " << med(s.kind)
      << L"\n  Dateisystem: " << s.filesystem << L"\n  Gerät: "
      << s.device_model << L"\n  Bus: " << s.bus_type << L"\n  TRIM: "
      << (s.trim_enabled ? L"aktiv" : L"nicht erkannt") << L"\n  USN: "
      << (s.usn_journal_active ? L"aktiv" : L"nicht erkannt") << L"\n";
    if (s.shadow_copy_query_succeeded)
      o << L"  Shadow Copies: " << s.shadow_copy_count << L"\n";
  }

  for (const auto &w : p.warnings)
    o << L"\nHinweis: " << w;
  return o.str();
}
bool requires_typed_confirmation(const file_analysis &a) {
  constexpr std::uint64_t gib = 1024ull * 1024ull * 1024ull;
  return a.files > 100 || a.logical_bytes >= gib || a.directories > 50;
}
std::wstring confirmation_text(const prepared_operation &p,
                               const erase_options &o) {
  std::wostringstream x;
  if (p.targets.size() > 1)
    x << L"Sollen wirklich alle " << p.targets.size()
      << L" ausgewählten Ziele gemeinsam und unwiderruflich gelöscht werden?";
  else
    x << L"Soll das ausgewählte Ziel wirklich unwiderruflich gelöscht werden?";
  x << L"\n\nZiele: " << p.targets.size() << L"\nDateien: "
    << p.analysis.files
    << L"\nVerzeichnisse: " << p.analysis.directories << L"\nBytes: "
    << p.analysis.logical_bytes << L"\nADS: " << p.analysis.alternate_streams
    << L"\nHardlinks: " << p.analysis.hardlinked_files << L"\nReparse Points: "
    << p.analysis.reparse_points << L"\n\nModus: " << mode(o.mode)
    << L"\nVerifikation: " << (o.verify ? L"aktiv" : L"deaktiviert")
    << L"\nHardlinks: " << hp(o.hardlinks) << L"\nRename-Runden: "
    << o.rename_rounds << L"\n";
  bool ssd = false, shadow = false, usn = false;
  for (const auto &s : p.storage) {
    ssd |= s.kind == media_kind::solid_state;
    shadow |= s.shadow_copy_query_succeeded && s.shadow_copy_count;
    usn |= s.usn_journal_active;
  }
  if (ssd)
    x << L"\nSSD/NVMe: physische Historienlöschung ist durch dateibasiertes "
         L"Überschreiben nicht garantiert.\n";
  if (shadow)
    x << L"\nShadow Copies vorhanden; sie werden nicht automatisch gelöscht.\n";
  if (usn)
    x << L"\nUSN-Journal aktiv; Metadatenhistorie kann bestehen bleiben.\n";
  x << L"\nDieser Vorgang kann nicht rückgängig gemacht werden.";
  return x.str();
}
gui_run_result execute_prepared_operation(const prepared_operation &p,
                                          const erase_options &o,
                                          const progress_callback &cb,
                                          const std::function<bool()> &cancel) {
  gui_run_result out;
  if (!p.valid) {
    out.exit_code = 2;
    out.summary = p.error;
    return out;
  }
  erase_engine e;
  analyzer a;
  std::uint64_t fd = 0, dd = 0, bw = 0, ads = 0, rp = 0, hb = 0;
  std::size_t wc = 0;
  bool all = true, denied = false;
  std::vector<std::wstring> locks;
  auto logical = sadd(
           p.analysis.logical_bytes,
           o.erase_alternate_streams ? p.analysis.alternate_stream_bytes : 0),
       expected = smul(logical, pc(o.mode));
  for (std::size_t i = 0; i < p.targets.size(); ++i) {
    if (cancel && cancel()) {
      out.cancelled = true;
      out.exit_code = 130;
      out.summary = L"Abgebrochen.";
      return out;
    }
    auto per = a.analyze(p.targets[i]);
    auto start = std::chrono::steady_clock::now();
    auto before = bw;
    progress_callback wrap = [&](const progress_info &info) {
      if (cancel && cancel())
        return false;
      if (!cb)
        return true;
      auto q = info;
      q.overall_completed = sadd(before, info.bytes_written_total);
      q.overall_total = expected;
      return cb(q);
    };
    auto r = e.erase(p.targets[i], o, wrap);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now() - start)
                  .count();
    operation_audit ar;
    ar.operation_id = create_operation_id();
    ar.target = p.targets[i];
    if (i < p.storage.size())
      ar.storage = p.storage[i];
    ar.options = o;
    ar.analysis = per;
    ar.result = r;
    ar.duration_ms = ms > 0 ? static_cast<std::uint64_t>(ms) : 0;
    const bool audit_ok = !write_audit_record(ar).empty();
    fd += r.files_deleted;
    dd += r.directories_deleted;
    bw += r.bytes_written;
    ads += r.alternate_streams_overwritten;
    rp += r.reparse_points_removed;
    hb += r.hardlinks_blocked;
    wc += r.warnings.size() + (audit_ok ? 0u : 1u);
    all &= r.success && audit_ok;
    denied |= r.win32_error == ERROR_ACCESS_DENIED;
    if (!r.lock_owners.empty())
      locks.push_back(p.targets[i].wstring() + L"\n" +
                      format_lock_owners(r.lock_owners));
    if (r.cancelled) {
      out.cancelled = true;
      out.exit_code = 130;
      all = false;
      break;
    }
  }
  std::wostringstream s;
  s << (out.cancelled ? L"OBLIVION wurde abgebrochen.\n\n"
        : all         ? L"OBLIVION hat den Vorgang abgeschlossen.\n\n"
              : L"OBLIVION konnte nicht alle Ziele vollständig löschen.\n\n")
    << L"Dateien gelöscht: " << fd << L"\nVerzeichnisse gelöscht: " << dd
    << L"\nGeschriebene Bytes: " << bw << L"\nADS überschrieben: " << ads
    << L"\nReparse Points entfernt: " << rp << L"\nHardlinks blockiert: " << hb
    << L"\nWarnungen: " << wc << L"\nAudit: " << audit_directory().wstring();
  for (const auto &l : locks)
    s << L"\n\n" << l;
  out.completed = !out.cancelled;
  out.exit_code = out.cancelled ? 130 : (all ? 0 : (denied ? 5 : 3));
  out.summary = s.str();
  return out;
}
} // namespace oblivion
