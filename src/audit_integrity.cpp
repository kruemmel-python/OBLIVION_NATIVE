#include "oblivion/audit_integrity.hpp"

#include "oblivion/audit.hpp"
#include "oblivion/bcrypt_handle.hpp"
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
#include <utility>
#include <vector>

namespace oblivion {
namespace {
constexpr std::size_t key_size = 32;
constexpr std::size_t max_audit_record_bytes = 16u * 1024u * 1024u;
constexpr std::size_t max_audit_proof_bytes = 512u;
constexpr std::size_t max_audit_directory_entries = 100000u;
constexpr std::size_t max_audit_chain_records = 10000u;
constexpr std::uint64_t max_audit_chain_bytes = 256ull * 1024ull * 1024ull;

class audit_lock final {
public:
  audit_lock() noexcept {
    try {
      std::filesystem::path directory;
      if (!prepare_audit_directory(directory))
        return;
      auto current = directory.root_path();
      if (current.empty())
        return;
      for (const auto &component : directory.relative_path()) {
        if (component.empty() || component == L".")
          continue;
        if (component == L"..")
          return;
        current /= component;
        unique_win_handle directory_handle{CreateFileW(
            current.c_str(), FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            nullptr)};
        FILE_ATTRIBUTE_TAG_INFO directory_attributes{};
        if (!directory_handle ||
            !GetFileInformationByHandleEx(
                directory_handle.get(), FileAttributeTagInfo,
                &directory_attributes, sizeof(directory_attributes)) ||
            (directory_attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) ==
                0 ||
            (directory_attributes.FileAttributes &
             FILE_ATTRIBUTE_REPARSE_POINT) != 0)
          return;
        directories_.push_back(std::move(directory_handle));
      }
      const auto file = directory / L"audit.lock";
      const auto deadline = GetTickCount64() + 30000u;
      for (;;) {
        file_.reset(CreateFileW(
            file.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_ALWAYS,
            FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED |
                FILE_FLAG_OPEN_REPARSE_POINT,
            nullptr));
        if (file_)
          break;
        const DWORD error = GetLastError();
        if ((error != ERROR_SHARING_VIOLATION &&
             error != ERROR_LOCK_VIOLATION) ||
            GetTickCount64() >= deadline)
          return;
        Sleep(25);
      }
      FILE_ATTRIBUTE_TAG_INFO attributes{};
      if (!GetFileInformationByHandleEx(file_.get(), FileAttributeTagInfo,
                                        &attributes, sizeof(attributes)) ||
          (attributes.FileAttributes &
           (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
        file_.reset();
        return;
      }
      acquired_ = true;
    } catch (...) {
      file_.reset();
      acquired_ = false;
    }
  }
  [[nodiscard]] explicit operator bool() const noexcept { return acquired_; }

private:
  std::vector<unique_win_handle> directories_;
  unique_win_handle file_;
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
                  const std::span<const std::byte> bytes,
                  unique_win_handle *retained = nullptr) {
  unique_win_handle output{CreateFileW(
      file.c_str(), GENERIC_WRITE | DELETE, 0, nullptr, CREATE_NEW,
      FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, nullptr)};
  if (!output)
    return false;
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const auto count = static_cast<DWORD>((std::min)(
        bytes.size() - offset,
        static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
    DWORD written = 0;
    if (!WriteFile(output.get(), bytes.data() + offset, count, &written,
                   nullptr) ||
        written != count) {
      FILE_DISPOSITION_INFO disposition{TRUE};
      (void)SetFileInformationByHandle(output.get(), FileDispositionInfo,
                                       &disposition, sizeof(disposition));
      output.reset();
      return false;
    }
    offset += written;
  }
  if (FlushFileBuffers(output.get()) == FALSE) {
    FILE_DISPOSITION_INFO disposition{TRUE};
    (void)SetFileInformationByHandle(output.get(), FileDispositionInfo,
                                     &disposition, sizeof(disposition));
    output.reset();
    return false;
  }
  if (retained)
    *retained = std::move(output);
  return true;
}

void discard_binary(unique_win_handle &file) noexcept {
  FILE_DISPOSITION_INFO disposition{TRUE};
  (void)SetFileInformationByHandle(file.get(), FileDispositionInfo,
                                   &disposition, sizeof(disposition));
  file.reset();
}
class binary_discard_guard final {
public:
  explicit binary_discard_guard(unique_win_handle &file) noexcept
      : file_(file) {}
  ~binary_discard_guard() {
    if (armed_ && file_)
      discard_binary(file_);
  }
  binary_discard_guard(const binary_discard_guard &) = delete;
  binary_discard_guard &operator=(const binary_discard_guard &) = delete;
  void commit() noexcept { armed_ = false; }

private:
  unique_win_handle &file_;
  bool armed_{true};
};

bool replace_by_handle(HANDLE source,
                       const std::filesystem::path &destination) noexcept try {
  const auto leaf = destination.filename().wstring();
  if (leaf.empty() || leaf == L"." || leaf == L"..")
    return false;
  unique_win_handle directory{CreateFileW(
      destination.parent_path().c_str(), FILE_LIST_DIRECTORY,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
      OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
  FILE_ATTRIBUTE_TAG_INFO directory_attributes{};
  if (!directory ||
      !GetFileInformationByHandleEx(directory.get(), FileAttributeTagInfo,
                                    &directory_attributes,
                                    sizeof(directory_attributes)) ||
      (directory_attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
      (directory_attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
    return false;
  auto name = std::filesystem::absolute(destination).lexically_normal().wstring();
  if (name.starts_with(L"\\\\?\\")) {
    // Already an extended-length absolute path.
  } else if (name.starts_with(L"\\\\"))
    name = L"\\\\?\\UNC\\" + name.substr(2);
  else
    name = L"\\\\?\\" + name;
  constexpr auto prefix = offsetof(FILE_RENAME_INFO, FileName);
  if (name.size() > (std::numeric_limits<DWORD>::max)() / sizeof(wchar_t) ||
      name.size() >
          ((std::numeric_limits<std::size_t>::max)() - prefix -
           sizeof(wchar_t)) /
              sizeof(wchar_t))
    return false;
  const auto name_bytes = name.size() * sizeof(wchar_t);
  std::vector<std::byte> storage(prefix + name_bytes + sizeof(wchar_t));
  auto *information = reinterpret_cast<FILE_RENAME_INFO *>(storage.data());
  information->ReplaceIfExists = TRUE;
  information->RootDirectory = nullptr;
  information->FileNameLength = static_cast<DWORD>(name_bytes);
  std::copy(name.begin(), name.end(), information->FileName);
  return SetFileInformationByHandle(
             source, FileRenameInfo, information,
             static_cast<DWORD>(storage.size())) != FALSE;
} catch (...) {
  return false;
}

bool load_key(secure_buffer &key) {
  if (!key.valid() || key.size() != key_size)
    return false;
  std::filesystem::path directory;
  if (!prepare_audit_directory(directory))
    return false;
  const auto file = directory / L"audit.key.dpapi";
  std::error_code existence_error;
  const bool key_exists = std::filesystem::exists(file, existence_error);
  if (existence_error)
    return false;
  if (key_exists) {
    auto encrypted = read_binary(file);
    if (encrypted.empty() ||
        encrypted.size() >
            static_cast<std::size_t>((std::numeric_limits<DWORD>::max)()))
      return false;
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
  unique_bcrypt_algorithm algorithm;
  DWORD object_size = 0, digest_size = 0, copied = 0;
  if (BCryptOpenAlgorithmProvider(algorithm.put(), BCRYPT_SHA256_ALGORITHM, nullptr,
                                  BCRYPT_ALG_HANDLE_HMAC_FLAG) < 0)
    return {};
  if (BCryptGetProperty(algorithm.get(), BCRYPT_OBJECT_LENGTH,
                        reinterpret_cast<PUCHAR>(&object_size),
                        sizeof(object_size), &copied, 0) < 0 ||
      BCryptGetProperty(algorithm.get(), BCRYPT_HASH_LENGTH,
                        reinterpret_cast<PUCHAR>(&digest_size),
                        sizeof(digest_size), &copied, 0) < 0) {
    return {};
  }
  secure_buffer object(object_size);
  std::vector<std::byte> digest(digest_size);
  // The BCrypt hash handle borrows the hash-object storage. It must therefore
  // be destroyed before that secure storage is wiped and released.
  unique_bcrypt_hash hash;
  if (!object.valid() ||
      BCryptCreateHash(
          algorithm.get(), hash.put(), reinterpret_cast<PUCHAR>(object.data()),
          object_size,
          reinterpret_cast<PUCHAR>(const_cast<std::byte *>(key.data())),
          static_cast<ULONG>(key.size()), 0) < 0) {
    return {};
  }
  std::size_t offset = 0;
  while (offset < data.size()) {
    const auto count = static_cast<ULONG>((std::min)(
        data.size() - offset,
        static_cast<std::size_t>((std::numeric_limits<ULONG>::max)())));
    if (BCryptHashData(
            hash.get(),
            reinterpret_cast<PUCHAR>(const_cast<char *>(data.data() + offset)),
            count, 0) < 0) {
      digest.clear();
      break;
    }
    offset += count;
  }
  if (!digest.empty() &&
      BCryptFinishHash(hash.get(), reinterpret_cast<PUCHAR>(digest.data()),
                       digest_size, 0) < 0)
    digest.clear();
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
  if (bytes.empty())
    return {};
  return {reinterpret_cast<const char *>(bytes.data()), bytes.size()};
}

bool valid_hex_digest(const std::string_view value) {
  return value.size() == 64 && std::ranges::all_of(value, [](const char c) {
           return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
         });
}

bool normalize_digest_line(std::string &value) {
  if (value.ends_with("\r\n"))
    value.resize(value.size() - 2u);
  else if (value.ends_with('\n'))
    value.pop_back();
  return valid_hex_digest(value);
}
} // namespace

std::wstring audit_reference(const std::wstring_view value) noexcept try {
  audit_lock lock;
  if (!lock)
    return L"unavailable";
  secure_buffer key(key_size);
  if (!load_key(key))
    return L"unavailable";
  const auto encoded = utf8(value);
  if (!value.empty() && encoded.empty())
    return L"unavailable";
  const auto digest = hmac(key.bytes(), encoded);
  const auto text = hex(digest);
  return text.empty() ? L"unavailable" : std::wstring(text.begin(), text.end());
} catch (...) {
  return L"unavailable";
}

namespace {
bool seal_audit_record(const std::filesystem::path &file, secure_buffer &key,
                       const std::string_view record) {
  std::filesystem::path directory;
  std::error_code equivalent_error;
  if (!prepare_audit_directory(directory) ||
      !std::filesystem::equivalent(file.parent_path(), directory,
                                   equivalent_error) ||
      equivalent_error)
    return false;
  if (record.empty())
    return false;
  const auto head_file = file.parent_path() / L"chain.head";
  std::error_code existence_error;
  const bool head_exists = std::filesystem::exists(head_file, existence_error);
  if (existence_error)
    return false;
  std::string previous;
  if (head_exists) {
    std::error_code head_size_error;
    const auto head_size =
        std::filesystem::file_size(head_file, head_size_error);
    if (head_size_error || head_size == 0 || head_size > 66)
      return false;
    previous = read_text(head_file);
    if (!normalize_digest_line(previous))
      return false;
  } else {
    std::error_code scan_error;
    std::filesystem::directory_iterator it(file.parent_path(), scan_error), end;
    if (scan_error)
      return false;
    std::size_t entry_count = 0;
    while (it != end) {
      if (++entry_count > max_audit_directory_entries)
        return false;
      if (it->path().extension() == L".hmac")
        return false;
      it.increment(scan_error);
      if (scan_error)
        return false;
    }
    previous.assign(64, '0');
  }
  std::string authenticated = previous + '\n';
  authenticated.append(record.data(), record.size());
  const auto digest = hmac(key.bytes(), authenticated);
  const auto current = hex(digest);
  if (!valid_hex_digest(current))
    return false;
  auto sidecar = file;
  sidecar += L".hmac";
  const std::string proof =
      "Previous=" + previous + "\nHMAC-SHA256=" + current + '\n';
  unique_win_handle sidecar_handle;
  if (!write_binary(
          sidecar,
          {reinterpret_cast<const std::byte *>(proof.data()), proof.size()},
          &sidecar_handle)) {
    return false;
  }
  binary_discard_guard sidecar_guard{sidecar_handle};
  std::array<std::byte, 16> temporary_random{};
  if (!try_fill_secure_random(temporary_random))
    return false;
  const auto temporary_suffix = hex(temporary_random);
  const auto temporary =
      head_file.wstring() + L"." +
      std::wstring(temporary_suffix.begin(), temporary_suffix.end()) + L".tmp";
  const std::string head = current + '\n';
  unique_win_handle temporary_handle;
  if (!write_binary(
          temporary,
          {reinterpret_cast<const std::byte *>(head.data()), head.size()},
          &temporary_handle)) {
    return false;
  }
  binary_discard_guard temporary_guard{temporary_handle};
  if (!replace_by_handle(temporary_handle.get(), head_file))
    return false;
  temporary_guard.commit();
  sidecar_guard.commit();
  return true;
}
} // namespace

bool seal_audit_file(const std::filesystem::path &file) noexcept try {
  audit_lock lock;
  if (!lock)
    return false;
  secure_buffer key(key_size);
  if (!load_key(key))
    return false;
  const auto record = read_text(file);
  return !record.empty() && seal_audit_record(file, key, record);
} catch (...) {
  return false;
}

bool seal_audit_file_contents(const std::filesystem::path &file,
                              const std::string_view contents) noexcept try {
  audit_lock lock;
  if (!lock || contents.empty())
    return false;
  secure_buffer key(key_size);
  return load_key(key) && seal_audit_record(file, key, contents);
} catch (...) {
  return false;
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
  if (proof.peek() != std::char_traits<char>::eof())
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

bool verify_audit_file(const std::filesystem::path &file) noexcept try {
  audit_lock lock;
  if (!lock)
    return false;
  secure_buffer key(key_size);
  if (!load_key(key))
    return false;
  std::string previous, expected;
  return parse_and_verify_sidecar(file, key, previous, expected);
} catch (...) {
  return false;
}

bool verify_audit_chain(const std::filesystem::path &audit_dir) noexcept try {
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
  std::string head = read_text(head_file);
  if (!normalize_digest_line(head))
    return false;

  std::unordered_map<std::string, std::string> links;
  std::error_code ec;
  std::filesystem::directory_iterator it(audit_dir, ec), end;
  if (ec)
    return false;
  std::size_t directory_entries = 0;
  std::uint64_t chain_bytes = 0;
  while (it != end) {
    if (++directory_entries > max_audit_directory_entries)
      return false;
    const bool is_regular = it->is_regular_file(ec);
    if (ec)
      return false;
    if (is_regular && it->path().extension() == L".hmac") {
      if (links.size() >= max_audit_chain_records)
        return false;
      auto record_file = it->path();
      record_file.replace_extension();
      std::error_code record_size_error;
      const auto record_size =
          std::filesystem::file_size(record_file, record_size_error);
      if (record_size_error || record_size == 0 ||
          record_size > max_audit_record_bytes ||
          record_size > max_audit_chain_bytes - chain_bytes)
        return false;
      chain_bytes += static_cast<std::uint64_t>(record_size);
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
} catch (...) {
  return false;
}

} // namespace oblivion
