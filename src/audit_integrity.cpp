#include "oblivion/audit_integrity.hpp"

#include "oblivion/audit.hpp"
#include "oblivion/random.hpp"
#include "oblivion/secure_memory.hpp"
#include "oblivion/win_handle.hpp"

#include <Windows.h>
#include <bcrypt.h>
#include <wincrypt.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace oblivion {
namespace {
constexpr std::size_t key_size = 32;
constexpr std::size_t max_audit_record_bytes = 16u * 1024u * 1024u;
constexpr std::size_t max_audit_proof_bytes = 512u;

class audit_lock final {
public:
  audit_lock() noexcept
      : mutex_(CreateMutexW(nullptr, FALSE, L"Local\\OblivionAuditIntegrity")) {
    if (!mutex_)
      return;
    const DWORD result = WaitForSingleObject(mutex_.get(), 30000);
    acquired_ = result == WAIT_OBJECT_0 || result == WAIT_ABANDONED;
  }
  ~audit_lock() {
    if (acquired_)
      (void)ReleaseMutex(mutex_.get());
  }
  [[nodiscard]] explicit operator bool() const noexcept { return acquired_; }

private:
  unique_win_handle mutex_;
  bool acquired_{false};
};

std::vector<std::byte> read_binary(const std::filesystem::path &file) {
  std::ifstream input(file, std::ios::binary | std::ios::ate);
  if (!input)
    return {};
  const auto end = input.tellg();
  if (end <= 0)
    return {};
  const auto size = static_cast<std::uintmax_t>(end);
  if (size >
          static_cast<std::uintmax_t>((std::numeric_limits<std::size_t>::max)()) ||
      size > max_audit_record_bytes)
    return {};
  std::vector<std::byte> bytes(static_cast<std::size_t>(size));
  input.seekg(0, std::ios::beg);
  input.read(reinterpret_cast<char *>(bytes.data()),
             static_cast<std::streamsize>(bytes.size()));
  if (!input)
    return {};
  return bytes;
}

bool write_binary(const std::filesystem::path &file,
                  const std::span<const std::byte> bytes) {
  std::ofstream output(file, std::ios::binary | std::ios::trunc);
  if (!output)
    return false;
  output.write(reinterpret_cast<const char *>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
  return output.good();
}

bool load_key(secure_buffer &key) {
  if (!key.valid() || key.size() != key_size)
    return false;
  const auto file = audit_directory() / L"audit.key.dpapi";
  auto encrypted = read_binary(file);
  if (!encrypted.empty() &&
      encrypted.size() <=
          static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())) {
    DATA_BLOB input{static_cast<DWORD>(encrypted.size()),
                    reinterpret_cast<BYTE *>(encrypted.data())};
    DATA_BLOB output{};
    if (CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr,
                           CRYPTPROTECT_UI_FORBIDDEN, &output) != FALSE) {
      const bool valid = output.cbData == key.size();
      if (valid)
        std::copy_n(reinterpret_cast<const std::byte *>(output.pbData),
                    key.size(), key.data());
      SecureZeroMemory(output.pbData, output.cbData);
      LocalFree(output.pbData);
      return valid;
    }
    return false;
  }

  if (!try_fill_secure_random(key.bytes()))
    return false;
  DATA_BLOB input{static_cast<DWORD>(key.size()),
                  reinterpret_cast<BYTE *>(key.data())};
  DATA_BLOB output{};
  if (CryptProtectData(&input, L"OBLIVION Audit HMAC Key", nullptr, nullptr,
                       nullptr, CRYPTPROTECT_UI_FORBIDDEN, &output) == FALSE)
    return false;
  const bool written =
      write_binary(file, {reinterpret_cast<const std::byte *>(output.pbData),
                          output.cbData});
  LocalFree(output.pbData);
  return written;
}

std::vector<std::byte> hmac(const std::span<const std::byte> key,
                            const std::string_view data) {
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  BCRYPT_HASH_HANDLE hash = nullptr;
  DWORD object_size = 0, digest_size = 0, copied = 0;
  if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr,
                                  BCRYPT_ALG_HANDLE_HMAC_FLAG) < 0)
    return {};
  if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                        reinterpret_cast<PUCHAR>(&object_size),
                        sizeof(object_size), &copied, 0) < 0 ||
      BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH,
                        reinterpret_cast<PUCHAR>(&digest_size),
                        sizeof(digest_size), &copied, 0) < 0) {
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return {};
  }
  secure_buffer object(object_size);
  std::vector<std::byte> digest(digest_size);
  if (!object.valid() ||
      BCryptCreateHash(
          algorithm, &hash, reinterpret_cast<PUCHAR>(object.data()),
          object_size,
          reinterpret_cast<PUCHAR>(const_cast<std::byte *>(key.data())),
          static_cast<ULONG>(key.size()), 0) < 0) {
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return {};
  }
  std::size_t offset = 0;
  while (offset < data.size()) {
    const auto count = static_cast<ULONG>((std::min)(
        data.size() - offset,
        static_cast<std::size_t>((std::numeric_limits<ULONG>::max)())));
    if (BCryptHashData(
            hash,
            reinterpret_cast<PUCHAR>(const_cast<char *>(data.data() + offset)),
            count, 0) < 0) {
      digest.clear();
      break;
    }
    offset += count;
  }
  if (!digest.empty() &&
      BCryptFinishHash(hash, reinterpret_cast<PUCHAR>(digest.data()),
                       digest_size, 0) < 0)
    digest.clear();
  BCryptDestroyHash(hash);
  BCryptCloseAlgorithmProvider(algorithm, 0);
  return digest;
}

std::string hex(const std::span<const std::byte> bytes) {
  constexpr char digits[] = "0123456789abcdef";
  std::string result;
  result.reserve(bytes.size() * 2);
  for (const auto byte : bytes) {
    const auto value = std::to_integer<unsigned>(byte);
    result.push_back(digits[value >> 4]);
    result.push_back(digits[value & 15]);
  }
  return result;
}

std::string utf8(const std::wstring_view value) {
  if (value.empty() || value.size() > static_cast<std::size_t>(
                                          (std::numeric_limits<int>::max)()))
    return {};
  const int size = WideCharToMultiByte(
      CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
      static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
  if (size <= 0)
    return {};
  std::string result(static_cast<std::size_t>(size), '\0');
  if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                          static_cast<int>(value.size()), result.data(), size,
                          nullptr, nullptr) != size)
    return {};
  return result;
}

std::string read_text(const std::filesystem::path &file) {
  const auto bytes = read_binary(file);
  return {reinterpret_cast<const char *>(bytes.data()), bytes.size()};
}

bool valid_hex_digest(const std::string_view value) {
  return value.size() == 64 && std::ranges::all_of(value, [](const char c) {
           return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
         });
}
} // namespace

std::wstring audit_reference(const std::wstring_view value) {
  audit_lock lock;
  if (!lock)
    return L"unavailable";
  secure_buffer key(key_size);
  if (!load_key(key))
    return L"unavailable";
  const auto encoded = utf8(value);
  const auto digest = hmac(key.bytes(), encoded);
  const auto text = hex(digest);
  return text.empty() ? L"unavailable" : std::wstring(text.begin(), text.end());
}

bool seal_audit_file(const std::filesystem::path &file) {
  audit_lock lock;
  if (!lock)
    return false;
  secure_buffer key(key_size);
  if (!load_key(key))
    return false;
  const auto record = read_text(file);
  if (record.empty())
    return false;
  const auto head_file = file.parent_path() / L"chain.head";
  auto previous = read_text(head_file);
  while (!previous.empty() &&
         (previous.back() == '\r' || previous.back() == '\n'))
    previous.pop_back();
  if (!valid_hex_digest(previous))
    previous = std::string(64, '0');
  const auto digest = hmac(key.bytes(), previous + "\n" + record);
  const auto current = hex(digest);
  if (!valid_hex_digest(current))
    return false;
  auto sidecar = file;
  sidecar += L".hmac";
  std::ofstream proof(sidecar, std::ios::binary | std::ios::trunc);
  if (!proof)
    return false;
  proof << "Previous=" << previous << "\nHMAC-SHA256=" << current << '\n';
  proof.close();
  if (!proof)
    return false;
  const auto temporary = head_file.wstring() + L".tmp";
  std::ofstream head(temporary, std::ios::binary | std::ios::trunc);
  if (!head)
    return false;
  head << current << '\n';
  head.close();
  return MoveFileExW(temporary.c_str(), head_file.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) !=
         FALSE;
}

namespace {

bool parse_and_verify_sidecar(const std::filesystem::path &file,
                              secure_buffer &key,
                              std::string &previous_out,
                              std::string &expected_out) {
  auto sidecar = file;
  sidecar += L".hmac";
  std::error_code size_error;
  const auto sidecar_size = std::filesystem::file_size(sidecar, size_error);
  if (size_error || sidecar_size == 0 ||
      sidecar_size > max_audit_proof_bytes)
    return false;
  std::ifstream proof(sidecar, std::ios::binary);
  std::string previous_line, current_line;
  if (!std::getline(proof, previous_line) ||
      !std::getline(proof, current_line))
    return false;
  constexpr std::string_view previous_prefix = "Previous=";
  constexpr std::string_view current_prefix = "HMAC-SHA256=";
  if (!previous_line.starts_with(previous_prefix) ||
      !current_line.starts_with(current_prefix))
    return false;
  previous_out = previous_line.substr(previous_prefix.size());
  expected_out = current_line.substr(current_prefix.size());
  if (!valid_hex_digest(previous_out) || !valid_hex_digest(expected_out))
    return false;
  const auto record = read_text(file);
  return hex(hmac(key.bytes(), previous_out + "\n" + record)) == expected_out;
}

} // namespace

bool verify_audit_file(const std::filesystem::path &file) {
  audit_lock lock;
  if (!lock)
    return false;
  secure_buffer key(key_size);
  if (!load_key(key))
    return false;
  std::string previous, expected;
  return parse_and_verify_sidecar(file, key, previous, expected);
}

bool verify_audit_chain(const std::filesystem::path &audit_dir) {
  audit_lock lock;
  if (!lock)
    return false;
  secure_buffer key(key_size);
  if (!load_key(key))
    return false;

  const auto head_file = audit_dir / L"chain.head";
  std::error_code head_size_error;
  const auto head_size = std::filesystem::file_size(head_file, head_size_error);
  if (head_size_error || head_size == 0 || head_size > 128)
    return false;
  std::ifstream head_in(head_file, std::ios::binary);
  std::string head;
  if (!std::getline(head_in, head) || !valid_hex_digest(head))
    return false;

  std::unordered_map<std::string, std::string> links;
  std::error_code ec;
  std::filesystem::directory_iterator it(audit_dir, ec), end;
  if (ec)
    return false;
  while (it != end) {
    const bool is_regular = it->is_regular_file(ec);
    if (ec)
      return false;
    if (is_regular && it->path().extension() == L".hmac") {
      auto record_file = it->path();
      record_file.replace_extension();
      std::string previous, expected;
      if (!parse_and_verify_sidecar(record_file, key, previous, expected))
        return false;
      if (!links.emplace(expected, previous).second)
        return false;
    }
    it.increment(ec);
    if (ec)
      return false;
  }
  if (links.empty())
    return false;

  const std::string zero(64, '0');
  std::string cursor = head;
  std::unordered_set<std::string> visited;
  while (cursor != zero) {
    if (!visited.insert(cursor).second)
      return false;
    const auto link_it = links.find(cursor);
    if (link_it == links.end())
      return false;
    cursor = link_it->second;
  }
  return visited.size() == links.size();
}

} // namespace oblivion
