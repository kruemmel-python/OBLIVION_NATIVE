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
std::uint64_t sadd(std::uint64_t a, std::uint64_t b) {
  const auto maximum = (std::numeric_limits<std::uint64_t>::max)();
  return b > maximum - a ? maximum : a + b;
}
bool cancellation_requested(const std::function<bool()> &cancel) noexcept {
  try {
    return cancel && cancel();
  } catch (...) {
    return true;
  }
}
void merge(file_analysis &a, const file_analysis &b) {
  a.files = sadd(a.files, b.files);
  a.directories = sadd(a.directories, b.directories);
  a.logical_bytes = sadd(a.logical_bytes, b.logical_bytes);
  a.alternate_streams = sadd(a.alternate_streams, b.alternate_streams);
  a.alternate_stream_bytes =
      sadd(a.alternate_stream_bytes, b.alternate_stream_bytes);
  a.reparse_points = sadd(a.reparse_points, b.reparse_points);
  a.hardlinked_files = sadd(a.hardlinked_files, b.hardlinked_files);
  a.sparse_files = sadd(a.sparse_files, b.sparse_files);
  a.compressed_files = sadd(a.compressed_files, b.compressed_files);
  a.encrypted_files = sadd(a.encrypted_files, b.encrypted_files);
  a.readonly_entries = sadd(a.readonly_entries, b.readonly_entries);
  a.inaccessible_entries = sadd(a.inaccessible_entries, b.inaccessible_entries);
  constexpr std::size_t max_warnings = 256;
  for (const auto &warning : b.warnings) {
    if (a.warnings.size() >= max_warnings)
      break;
    a.warnings.push_back(warning);
  }
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
  if (raw.size() > max_operation_targets) {
    p.error = L"Zu viele Ziele; maximal " +
              std::to_wstring(max_operation_targets) +
              L" Ziele pro Vorgang sind zulässig.";
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
  return a.files > 100 || a.logical_bytes >= gib || a.directories > 50 ||
         a.inaccessible_entries != 0;
}
bool requires_hardlink_confirmation(const erase_options &options) {
  return options.hardlinks == hardlink_policy::overwrite_shared_content;
}
std::vector<std::wstring> build_elevation_arguments(
    const erase_options &options,
    const std::vector<std::filesystem::path> &targets) {
  std::vector<std::wstring> result{L"--elevated-retry"};
  switch (options.mode) {
  case erase_mode::fast: result.push_back(L"--fast"); break;
  case erase_mode::strong: result.push_back(L"--strong"); break;
  case erase_mode::dod_5220_22_m: result.push_back(L"--dod"); break;
  case erase_mode::nist_800_88: result.push_back(L"--nist"); break;
  case erase_mode::bsi_gs: result.push_back(L"--bsi"); break;
  case erase_mode::gutmann: result.push_back(L"--gutmann"); break;
  case erase_mode::standard:
  default: result.push_back(L"--standard"); break;
  }
  if (!options.verify)
    result.push_back(L"--no-verify");
  if (!options.erase_alternate_streams)
    result.push_back(L"--no-ads");
  if (!options.rename_before_delete)
    result.push_back(L"--no-rename");
  result.push_back(L"--rename-rounds");
  result.push_back(std::to_wstring((std::min)(options.rename_rounds, 32u)));
  if (options.hardlinks == hardlink_policy::delete_link_only)
    result.push_back(L"--hardlink-delete-name");
  else if (options.hardlinks == hardlink_policy::overwrite_shared_content)
    result.push_back(L"--hardlink-overwrite-shared");
  for (const auto &target : targets)
    result.push_back(target.wstring());
  return result;
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
  if (p.analysis.inaccessible_entries)
    x << L"\nWARNUNG: Die Voranalyse war unvollständig. Deshalb ist die "
         L"stärkere Texteingabe-Bestätigung erforderlich; die Löschengine "
         L"arbeitet bei Zugriffs- oder Aufzählungsfehlern weiterhin "
         L"fail-closed.\n";
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
  bool all = true, denied = false, audit_failed = false,
       analysis_failed = false;
  std::vector<std::wstring> locks;
  auto logical = sadd(
           p.analysis.logical_bytes,
           o.erase_alternate_streams ? p.analysis.alternate_stream_bytes : 0),
       expected = smul(logical, pc(o.mode));
  for (std::size_t i = 0; i < p.targets.size(); ++i) {
    if (cancellation_requested(cancel)) {
      out.cancelled = true;
      out.exit_code = 130;
      out.summary = L"Abgebrochen.";
      return out;
    }
    file_analysis per;
    try {
      per = a.analyze(p.targets[i]);
    } catch (...) {
      all = false;
      analysis_failed = true;
      wc = wc == (std::numeric_limits<std::size_t>::max)() ? wc : wc + 1u;
      break;
    }
    auto start = std::chrono::steady_clock::now();
    auto before = bw;
    progress_callback wrap = [&](const progress_info &info) {
      if (cancellation_requested(cancel))
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
    bool audit_ok = false;
    try {
      operation_audit ar;
      ar.operation_id = create_operation_id();
      ar.target = p.targets[i];
      if (i < p.storage.size())
        ar.storage = p.storage[i];
      ar.options = o;
      ar.analysis = per;
      ar.result = r;
      ar.duration_ms = ms > 0 ? static_cast<std::uint64_t>(ms) : 0;
      audit_ok = !write_audit_record(ar).empty();
    } catch (...) {
      audit_ok = false;
    }
    fd = sadd(fd, r.files_deleted);
    dd = sadd(dd, r.directories_deleted);
    bw = sadd(bw, r.bytes_written);
    ads = sadd(ads, r.alternate_streams_overwritten);
    rp = sadd(rp, r.reparse_points_removed);
    hb = sadd(hb, r.hardlinks_blocked);
    auto warning_increment = r.warnings.size();
    if (!audit_ok &&
        warning_increment != (std::numeric_limits<std::size_t>::max)())
      ++warning_increment;
    wc = warning_increment > (std::numeric_limits<std::size_t>::max)() - wc
             ? (std::numeric_limits<std::size_t>::max)()
             : wc + warning_increment;
    all &= r.success && audit_ok;
    denied |= r.win32_error == ERROR_ACCESS_DENIED;
    try {
      if (!r.success && r.win32_error == ERROR_ACCESS_DENIED)
        out.elevation_retry_targets.push_back(p.targets[i]);
      if (!r.lock_owners.empty())
        locks.push_back(p.targets[i].wstring() + L"\n" +
                        format_lock_owners(r.lock_owners));
    } catch (...) {
      all = false;
      wc = wc == (std::numeric_limits<std::size_t>::max)() ? wc : wc + 1u;
    }
    if (r.cancelled) {
      out.cancelled = true;
      out.exit_code = 130;
      all = false;
      break;
    }
    if (!audit_ok) {
      audit_failed = true;
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
    << L"\nWarnungen: " << wc << L"\nAudit: " << audit_directory().wstring()
    << L"\nAuditstatus: "
    << (audit_failed   ? L"FEHLER – weitere Ziele gestoppt"
        : analysis_failed ? L"UNVOLLSTÄNDIG – Ziel nicht bearbeitet"
                          : L"OK");
  if (analysis_failed)
    s << L"\nVoranalyse: FEHLER – aktuelles und weitere Ziele nicht bearbeitet";
  for (const auto &l : locks)
    s << L"\n\n" << l;
  out.completed = !out.cancelled;
  out.exit_code = out.cancelled ? 130 : (all ? 0 : (denied ? 5 : 3));
  out.summary = s.str();
  return out;
}
} // namespace oblivion
