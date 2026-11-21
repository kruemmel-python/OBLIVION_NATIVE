#include "oblivion/certificate.hpp"
#include "oblivion/audit_integrity.hpp"

#include <Windows.h>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <map>
#include <string_view>
#include <system_error>
#include <vector>

namespace oblivion {
namespace {

constexpr std::uintmax_t max_audit_record_bytes = 16u * 1024u * 1024u;

std::string to_utf8(const std::wstring &w) {
  if (w.empty())
    return {};
  int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()),
                              nullptr, 0, nullptr, nullptr);
  if (n <= 0)
    return {};
  std::string r(static_cast<std::size_t>(n), '\0');
  WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()),
                      r.data(), n, nullptr, nullptr);
  return r;
}

std::wstring get_env_info(bool user) {
  wchar_t buf[256]{};
  DWORD size = 256;
  if (user) {
    if (GetUserNameW(buf, &size))
      return buf;
  } else {
    if (GetComputerNameW(buf, &size))
      return buf;
  }
  return L"SYSTEM";
}

std::wstring current_timestamp() {
  SYSTEMTIME st{};
  GetLocalTime(&st);
  wchar_t buf[64]{};
  swprintf_s(buf, L"%04u-%02u-%02u %02u:%02u:%02u", st.wYear, st.wMonth,
             st.wDay, st.wHour, st.wMinute, st.wSecond);
  return buf;
}

std::string read_sha256_sidecar(const std::filesystem::path &audit_file) {
  auto sidecar = audit_file;
  sidecar += L".sha256";
  std::ifstream f(sidecar);
  if (!f.is_open())
    return "Kein Sidecar";
  std::string hash;
  f >> hash;
  return hash.empty() ? "Unbekannt" : hash;
}

std::string html_escape(const std::string_view value) {
  std::string escaped;
  escaped.reserve(value.size());
  for (const char character : value) {
    switch (character) {
    case '&': escaped += "&amp;"; break;
    case '<': escaped += "&lt;"; break;
    case '>': escaped += "&gt;"; break;
    case '"': escaped += "&quot;"; break;
    case '\'': escaped += "&#39;"; break;
    default: escaped.push_back(character); break;
    }
  }
  return escaped;
}

} // namespace

bool generate_certificate_from_audit(
    const std::filesystem::path &audit_file,
    const std::filesystem::path &output_html_file) {
  std::error_code size_error;
  const auto size = std::filesystem::file_size(audit_file, size_error);
  if (size_error || size == 0 || size > max_audit_record_bytes)
    return false;
  std::ifstream file(audit_file);
  if (!file.is_open())
    return false;

  const bool hmac_valid = verify_audit_file(audit_file);
  const bool chain_valid =
      hmac_valid && verify_audit_chain(audit_file.parent_path());
  const std::string sha256_hash = read_sha256_sidecar(audit_file);

  std::map<std::string, std::string> fields;
  std::string line;
  while (std::getline(file, line)) {
    if (line.empty() || line[0] == '[' || line.rfind("OBLIVION", 0) == 0)
      continue;
    const auto colon = line.find(':');
    if (colon != std::string::npos) {
      std::string key = line.substr(0, colon);
      std::string val = line.substr(colon + 1);
      while (!val.empty() && (val.front() == ' ' || val.front() == '\t'))
        val.erase(0, 1);
      while (!val.empty() && (val.back() == '\r' || val.back() == ' '))
        val.pop_back();
      fields[key] = val;
    }
  }

  std::ofstream out(output_html_file);
  if (!out.is_open())
    return false;

  const std::string op_id = fields.count("OperationID") ? fields["OperationID"] : "N/A";
  const std::string target_ref = fields.count("TargetRef") ? fields["TargetRef"] : "Pseudonymisiert (DPAPI)";
  const std::string mode = fields.count("Mode") ? fields["Mode"] : "STANDARD";
  const std::string verify = fields.count("Verify") ? fields["Verify"] : "true";
  const std::string media = fields.count("Media") ? fields["Media"] : "N/A";
  const std::string fs = fields.count("Filesystem") ? fields["Filesystem"] : "NTFS";
  const std::string files = fields.count("DeletedFiles") ? fields["DeletedFiles"] : (fields.count("Files") ? fields["Files"] : "0");
  const std::string dirs = fields.count("DeletedDirectories") ? fields["DeletedDirectories"] : (fields.count("Directories") ? fields["Directories"] : "0");
  const std::string bytes = fields.count("WrittenBytes") ? fields["WrittenBytes"] : (fields.count("LogicalBytes") ? fields["LogicalBytes"] : "0");
  const std::string duration = fields.count("DurationMs") ? fields["DurationMs"] + " ms" : "N/A";

  // Konvertiere breite Strings für Ausgabe
  const std::string user = to_utf8(get_env_info(true));
  const std::string comp = to_utf8(get_env_info(false));
  const std::string timestamp = to_utf8(current_timestamp());

  out << "<!DOCTYPE html>\n"
      << "<html lang=\"de\">\n"
      << "<head>\n"
      << "  <meta charset=\"UTF-8\">\n"
      << "  <title>OBLIVION – Datenvernichtungs-Zertifikat</title>\n"
      << "  <style>\n"
      << "    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f1115; color: #e6e6e6; margin: 0; padding: 40px; }\n"
      << "    .certificate { max-width: 800px; margin: 0 auto; background: #1a1d24; border: 2px solid #2d3340; border-radius: 8px; padding: 40px; box-shadow: 0 8px 32px rgba(0,0,0,0.5); }\n"
      << "    .header { text-align: center; border-bottom: 2px solid #3b4455; padding-bottom: 24px; margin-bottom: 28px; }\n"
      << "    .logo { font-size: 32px; font-weight: bold; letter-spacing: 4px; color: #ff4757; text-transform: uppercase; margin-bottom: 8px; }\n"
      << "    .subtitle { font-size: 14px; text-transform: uppercase; letter-spacing: 2px; color: #a4b0be; }\n"
      << "    .badge { display: inline-block; padding: 6px 16px; border-radius: 20px; font-size: 13px; font-weight: 600; text-transform: uppercase; margin-top: 14px; "
      << (hmac_valid ? "background: #1e392a; color: #2ed573; border: 1px solid #2ed573;" : "background: #3a1e22; color: #ff4757; border: 1px solid #ff4757;") << " }\n"
      << "    .section { margin-bottom: 24px; }\n"
      << "    .section-title { font-size: 14px; text-transform: uppercase; letter-spacing: 1px; color: #70a1ff; margin-bottom: 12px; border-bottom: 1px solid #2d3340; padding-bottom: 4px; }\n"
      << "    table { width: 100%; border-collapse: collapse; margin-bottom: 8px; font-size: 14px; }\n"
      << "    td { padding: 8px 12px; border-bottom: 1px solid #242933; }\n"
      << "    td.label { color: #a4b0be; width: 38%; font-weight: 500; }\n"
      << "    td.value { color: #ffffff; font-family: 'Consolas', monospace; word-break: break-all; }\n"
      << "    .footer { text-align: center; margin-top: 36px; padding-top: 20px; border-top: 1px solid #2d3340; font-size: 12px; color: #747d8c; }\n"
      << "    @media print {\n"
      << "      body { background: #ffffff; color: #000000; padding: 0; }\n"
      << "      .certificate { border: 1px solid #333333; box-shadow: none; background: #ffffff; color: #000000; padding: 24px; max-width: 100%; }\n"
      << "      .logo { color: #000000; }\n"
      << "      .badge { border: 1px solid #000; background: #eee; color: #000; }\n"
      << "      td { border-bottom: 1px solid #ddd; }\n"
      << "      td.label { color: #444; }\n"
      << "      td.value { color: #000; }\n"
      << "    }\n"
      << "  </style>\n"
      << "</head>\n"
      << "<body>\n"
      << "  <div class=\"certificate\">\n"
      << "    <div class=\"header\">\n"
      << "      <div class=\"logo\">OBLIVION NATIVE</div>\n"
      << "      <div class=\"subtitle\">Technischer Datenvernichtungs- und Auditbericht</div>\n"
      << "      <div class=\"badge\">"
      << (chain_valid
              ? "&#10003; Einzeldatensatz-HMAC &amp; vollständige Audit-Kette verifiziert"
              : (hmac_valid
                     ? "&#9888; Einzeldatensatz-HMAC gültig (Audit-Kette bis chain.head unvollständig)"
                     : "&#9888; Manipulationswarnung / HMAC ungültig"))
      << "</div>\n"
      << "    </div>\n"
      << "    <div class=\"section\">\n"
      << "      <div class=\"section-title\">1. Identifikation &amp; Vorgang</div>\n"
      << "      <table>\n"
      << "        <tr><td class=\"label\">Operation ID</td><td class=\"value\">" << html_escape(op_id) << "</td></tr>\n"
      << "        <tr><td class=\"label\">Erstellungszeitpunkt</td><td class=\"value\">" << html_escape(timestamp) << "</td></tr>\n"
      << "        <tr><td class=\"label\">Operator (Windows-Benutzer)</td><td class=\"value\">" << html_escape(user) << "</td></tr>\n"
      << "        <tr><td class=\"label\">Arbeitsstation</td><td class=\"value\">" << html_escape(comp) << "</td></tr>\n"
      << "        <tr><td class=\"label\">Dauer</td><td class=\"value\">" << html_escape(duration) << "</td></tr>\n"
      << "      </table>\n"
      << "    </div>\n"
      << "    <div class=\"section\">\n"
      << "      <div class=\"section-title\">2. Vernichtungs- &amp; Speicherparameter</div>\n"
      << "      <table>\n"
      << "        <tr><td class=\"label\">Löschprofil / Standard</td><td class=\"value\">" << html_escape(mode) << "</td></tr>\n"
      << "        <tr><td class=\"label\">Readback-Verifikation</td><td class=\"value\">" << html_escape(verify) << "</td></tr>\n"
      << "        <tr><td class=\"label\">Datenträgertyp</td><td class=\"value\">" << html_escape(media) << "</td></tr>\n"
      << "        <tr><td class=\"label\">Dateisystem</td><td class=\"value\">" << html_escape(fs) << "</td></tr>\n"
      << "        <tr><td class=\"label\">Zielreferenz (HMAC)</td><td class=\"value\">" << html_escape(target_ref) << "</td></tr>\n"
      << "      </table>\n"
      << "    </div>\n"
      << "    <div class=\"section\">\n"
      << "      <div class=\"section-title\">3. Vernichtungsnachweis &amp; Statistik</div>\n"
      << "      <table>\n"
      << "        <tr><td class=\"label\">Gelöschte Dateien</td><td class=\"value\">" << html_escape(files) << "</td></tr>\n"
      << "        <tr><td class=\"label\">Gelöschte Verzeichnisse</td><td class=\"value\">" << html_escape(dirs) << "</td></tr>\n"
      << "        <tr><td class=\"label\">Überschriebene Bytes</td><td class=\"value\">" << html_escape(bytes) << " Bytes</td></tr>\n"
      << "        <tr><td class=\"label\">Audit-Log SHA-256</td><td class=\"value\">" << html_escape(sha256_hash) << "</td></tr>\n"
      << "      </table>\n"
      << "    </div>\n"
      << "    <div class=\"footer\">\n"
      << "      Erstellt mit OBLIVION Native 2.1.1 &bull; Lokale C++20/Win32-Sicherheitsarchitektur ohne externe Serverabhängigkeit &bull; Lokaler technischer Audit-Nachweis (kein amtliches Gutachten)\n"
      << "    </div>\n"
      << "  </div>\n"
      << "</body>\n"
      << "</html>\n";

  return true;
}

} // namespace oblivion
