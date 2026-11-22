#include "oblivion/certificate.hpp"
#include "oblivion/audit_integrity.hpp"
#include "oblivion/bcrypt_handle.hpp"
#include "oblivion/win_handle.hpp"

#include <Windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cwctype>
#include <fstream>
#include <limits>
#include <sstream>
#include <map>
#include <string_view>
#include <system_error>
#include <vector>

namespace oblivion {
namespace {

constexpr std::uintmax_t max_audit_record_bytes = 16u * 1024u * 1024u;

bool lock_output_parent(const std::filesystem::path &output,
                        std::vector<unique_win_handle> &locks) noexcept try {
  locks.clear();
  const auto parent = output.parent_path();
  auto current = parent.root_path();
  if (current.empty())
    return false;
  for (const auto &component : parent.relative_path()) {
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

bool same_file_or_path(const std::filesystem::path &left,
                       const std::filesystem::path &right) {
  std::error_code equivalent_error;
  if (std::filesystem::equivalent(left, right, equivalent_error))
    return true;
  std::error_code left_error, right_error;
  auto normalized_left =
      std::filesystem::absolute(left, left_error).lexically_normal().wstring();
  auto normalized_right =
      std::filesystem::absolute(right, right_error).lexically_normal().wstring();
  if (left_error || right_error)
    return false;
  const auto lower = [](std::wstring &value) {
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t c) {
      return static_cast<wchar_t>(std::towlower(c));
    });
  };
  lower(normalized_left);
  lower(normalized_right);
  return normalized_left == normalized_right;
}

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

std::string sha256_file(const std::filesystem::path &audit_file) {
  unique_bcrypt_algorithm algorithm;
  DWORD object_size = 0, digest_size = 0, copied = 0;
  if (BCryptOpenAlgorithmProvider(algorithm.put(), BCRYPT_SHA256_ALGORITHM, nullptr,
                                  0) < 0)
    return {};
  if (BCryptGetProperty(algorithm.get(), BCRYPT_OBJECT_LENGTH,
                        reinterpret_cast<PUCHAR>(&object_size),
                        sizeof(object_size), &copied, 0) < 0 ||
      BCryptGetProperty(algorithm.get(), BCRYPT_HASH_LENGTH,
                        reinterpret_cast<PUCHAR>(&digest_size),
                        sizeof(digest_size), &copied, 0) < 0) {
    return {};
  }
  std::vector<std::byte> object(object_size), digest(digest_size);
  // BCrypt owns references into the caller-supplied object buffer until its
  // hash handle is destroyed, so keep the handle later in declaration order.
  unique_bcrypt_hash hash;
  if (BCryptCreateHash(algorithm.get(), hash.put(),
                       reinterpret_cast<PUCHAR>(object.data()), object_size,
                       nullptr, 0, 0) < 0) {
    return {};
  }
  std::ifstream input(audit_file, std::ios::binary);
  std::vector<char> buffer(65536, '\0');
  bool ok = input.is_open();
  while (ok && input) {
    input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
    const auto count = input.gcount();
    if (count > 0 &&
        BCryptHashData(hash.get(), reinterpret_cast<PUCHAR>(buffer.data()),
                       static_cast<ULONG>(count), 0) < 0)
      ok = false;
  }
  if (!input.eof())
    ok = false;
  if (!ok || BCryptFinishHash(hash.get(), reinterpret_cast<PUCHAR>(digest.data()),
                              digest_size, 0) < 0)
    digest.clear();
  constexpr char digits[] = "0123456789abcdef";
  std::string result;
  result.reserve(digest.size() * 2u);
  for (const auto byte : digest) {
    const auto value = std::to_integer<unsigned>(byte);
    result.push_back(digits[value >> 4u]);
    result.push_back(digits[value & 15u]);
  }
  return result;
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

bool certificate_field(const std::string_view key) {
  constexpr std::array<std::string_view, 17> allowed{
      "OperationID",       "TargetRef",          "Mode",
      "Verify",            "Media",              "Filesystem",
      "FilesDeleted",      "Files",              "DirectoriesDeleted",
      "Directories",       "BytesWritten",       "LogicalBytes",
      "DurationMs",        "Success",            "Cancelled",
      "Win32Error",        "HardlinkPolicy"};
  return std::ranges::find(allowed, key) != allowed.end();
}

} // namespace

bool generate_certificate_from_audit(
    const std::filesystem::path &audit_file,
    const std::filesystem::path &output_html_file) noexcept try {
  std::error_code input_error, output_error;
  const auto input_path =
      std::filesystem::absolute(audit_file, input_error).lexically_normal();
  const auto output_path =
      std::filesystem::absolute(output_html_file, output_error).lexically_normal();
  if (audit_file.empty() || output_html_file.empty() || input_error ||
      output_error || input_path.empty() || output_path.empty() ||
      same_file_or_path(input_path, output_path))
    return false;
  std::vector<unique_win_handle> input_parent_locks;
  if (!lock_output_parent(input_path, input_parent_locks))
    return false;
  unique_win_handle audit_lock{CreateFileW(
      input_path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
  if (!audit_lock)
    return false;
  FILE_ATTRIBUTE_TAG_INFO audit_attributes{};
  LARGE_INTEGER audit_size{};
  if (!GetFileInformationByHandleEx(audit_lock.get(), FileAttributeTagInfo,
                                    &audit_attributes,
                                    sizeof(audit_attributes)) ||
      (audit_attributes.FileAttributes &
       (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
      !GetFileSizeEx(audit_lock.get(), &audit_size) ||
      audit_size.QuadPart <= 0 ||
      static_cast<std::uint64_t>(audit_size.QuadPart) > max_audit_record_bytes)
    return false;
  std::ifstream file(input_path);
  if (!file.is_open())
    return false;

  const bool hmac_valid = verify_audit_file(input_path);
  const bool chain_valid =
      hmac_valid && verify_audit_chain(input_path.parent_path());
  const std::string sha256_hash = sha256_file(input_path);
  if (sha256_hash.size() != 64)
    return false;

  std::map<std::string, std::string> fields;
  std::string line;
  std::size_t line_count = 0;
  while (std::getline(file, line)) {
    if (++line_count > 100000u || line.size() > 65536u)
      return false;
    if (line.empty() || line[0] == '[' || line.rfind("OBLIVION", 0) == 0)
      continue;
    const auto colon = line.find(':');
    if (colon != std::string::npos) {
      std::string key = line.substr(0, colon);
      if (!certificate_field(key))
        continue;
      std::string val = line.substr(colon + 1);
      while (!val.empty() && (val.front() == ' ' || val.front() == '\t'))
        val.erase(0, 1);
      while (!val.empty() && (val.back() == '\r' || val.back() == ' '))
        val.pop_back();
      if (val.size() > 4096u || !fields.emplace(std::move(key), std::move(val)).second)
        return false;
    }
  }

  std::ostringstream out;

  const std::string op_id = fields.count("OperationID") ? fields["OperationID"] : "N/A";
  const std::string target_ref = fields.count("TargetRef") ? fields["TargetRef"] : "Pseudonymisiert (DPAPI)";
  const std::string mode = fields.count("Mode") ? fields["Mode"] : "STANDARD";
  const std::string verify = fields.count("Verify") ? fields["Verify"] : "true";
  const std::string media = fields.count("Media") ? fields["Media"] : "N/A";
  const std::string fs = fields.count("Filesystem") ? fields["Filesystem"] : "NTFS";
  const std::string files = fields.count("FilesDeleted") ? fields["FilesDeleted"] : (fields.count("Files") ? fields["Files"] : "0");
  const std::string dirs = fields.count("DirectoriesDeleted") ? fields["DirectoriesDeleted"] : (fields.count("Directories") ? fields["Directories"] : "0");
  const std::string bytes = fields.count("BytesWritten") ? fields["BytesWritten"] : (fields.count("LogicalBytes") ? fields["LogicalBytes"] : "0");
  const std::string duration = fields.count("DurationMs") ? fields["DurationMs"] + " ms" : "N/A";
  const std::string success = fields.count("Success") ? fields["Success"] : "unknown";
  const std::string cancelled = fields.count("Cancelled") ? fields["Cancelled"] : "unknown";
  const std::string win32_error = fields.count("Win32Error") ? fields["Win32Error"] : "unknown";
  const bool operation_success = hmac_valid && success == "true" &&
                                 cancelled == "false";

  // Konvertiere breite Strings für Ausgabe
  const std::string user = to_utf8(get_env_info(true));
  const std::string comp = to_utf8(get_env_info(false));
  const std::string timestamp = to_utf8(current_timestamp());

  out << "<!DOCTYPE html>\n"
      << "<html lang=\"de\">\n"
      << "<head>\n"
      << "  <meta charset=\"UTF-8\">\n"
      << "  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src "
         "'none'; style-src 'unsafe-inline'\">\n"
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
      << "      <div class=\"badge\" style=\""
      << (operation_success
              ? "background: #1e392a; color: #2ed573; border: 1px solid #2ed573;"
              : "background: #3a1e22; color: #ff4757; border: 1px solid #ff4757;")
      << "\">"
      << (operation_success
              ? "&#10003; Löschvorgang laut Auditdatensatz erfolgreich"
              : "&#9888; Löschvorgang nicht als erfolgreich ausgewiesen")
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
      << "        <tr><td class=\"label\">Vorgang erfolgreich</td><td class=\"value\">" << html_escape(success) << "</td></tr>\n"
      << "        <tr><td class=\"label\">Abgebrochen</td><td class=\"value\">" << html_escape(cancelled) << "</td></tr>\n"
      << "        <tr><td class=\"label\">Win32-Fehlercode</td><td class=\"value\">" << html_escape(win32_error) << "</td></tr>\n"
      << "        <tr><td class=\"label\">Audit-Log SHA-256</td><td class=\"value\">" << html_escape(sha256_hash) << "</td></tr>\n"
      << "      </table>\n"
      << "    </div>\n"
      << "    <div class=\"footer\">\n"
      << "      Erstellt mit OBLIVION Native 2.1.2 &bull; Lokale C++20/Win32-Sicherheitsarchitektur ohne externe Serverabhängigkeit &bull; Lokaler technischer Audit-Nachweis (kein amtliches Gutachten)\n"
      << "    </div>\n"
      << "  </div>\n"
      << "</body>\n"
      << "</html>\n";

  if (!out.good())
    return false;
  const auto html = out.str();
  if (html.empty() ||
      html.size() >
          static_cast<std::size_t>((std::numeric_limits<DWORD>::max)()))
    return false;
  std::vector<unique_win_handle> output_parent_locks;
  if (!lock_output_parent(output_path, output_parent_locks))
    return false;
  unique_win_handle output{CreateFileW(
      output_path.c_str(), GENERIC_WRITE | DELETE, 0, nullptr, CREATE_NEW,
      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
  if (!output)
    return false;
  const auto discard = [&output]() noexcept {
    FILE_DISPOSITION_INFO disposition{TRUE};
    (void)SetFileInformationByHandle(output.get(), FileDispositionInfo,
                                     &disposition, sizeof(disposition));
    output.reset();
  };
  DWORD written = 0;
  const auto output_bytes = static_cast<DWORD>(html.size());
  if (!WriteFile(output.get(), html.data(), output_bytes, &written, nullptr) ||
      written != output_bytes || FlushFileBuffers(output.get()) == FALSE) {
    discard();
    return false;
  }
  return true;
} catch (...) {
  return false;
}

} // namespace oblivion
