#include "oblivion/shell_batch.hpp"
#include "oblivion/win_handle.hpp"

#include <Windows.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>
#include <string>
#include <thread>

namespace oblivion {
namespace {

constexpr std::uint32_t max_path_chars = 32767u;
constexpr std::size_t max_batch_targets = 4096u;
constexpr DWORD pipe_buffer_bytes = 65536u;
enum class accept_result { received, quiet_timeout, rejected, fatal_error };

bool same_executable_process(const DWORD process_id) {
  DWORD current_session = 0, peer_session = 0;
  if (!ProcessIdToSessionId(GetCurrentProcessId(), &current_session) ||
      !ProcessIdToSessionId(process_id, &peer_session) ||
      current_session != peer_session)
    return false;

  std::wstring current(32768, L'\0');
  const DWORD current_length = GetModuleFileNameW(
      nullptr, current.data(), static_cast<DWORD>(current.size()));
  if (current_length == 0 ||
      static_cast<std::size_t>(current_length) >= current.size())
    return false;
  current.resize(current_length);

  unique_win_handle process{
      OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process_id)};
  if (!process)
    return false;

  unique_win_handle current_token, peer_token;
  HANDLE raw_current_token = nullptr, raw_peer_token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_current_token) ||
      !OpenProcessToken(process.get(), TOKEN_QUERY, &raw_peer_token)) {
    if (raw_current_token)
      CloseHandle(raw_current_token);
    if (raw_peer_token)
      CloseHandle(raw_peer_token);
    return false;
  }
  current_token.reset(raw_current_token);
  peer_token.reset(raw_peer_token);
  DWORD current_bytes = 0, peer_bytes = 0;
  (void)GetTokenInformation(current_token.get(), TokenUser, nullptr, 0,
                            &current_bytes);
  (void)GetTokenInformation(peer_token.get(), TokenUser, nullptr, 0,
                            &peer_bytes);
  if (current_bytes == 0 || peer_bytes == 0)
    return false;
  std::vector<std::byte> current_user(current_bytes), peer_user(peer_bytes);
  if (!GetTokenInformation(current_token.get(), TokenUser,
                           current_user.data(), current_bytes,
                           &current_bytes) ||
      !GetTokenInformation(peer_token.get(), TokenUser, peer_user.data(),
                           peer_bytes, &peer_bytes))
    return false;
  const auto *current_token_user =
      reinterpret_cast<const TOKEN_USER *>(current_user.data());
  const auto *peer_token_user =
      reinterpret_cast<const TOKEN_USER *>(peer_user.data());
  if (!EqualSid(current_token_user->User.Sid, peer_token_user->User.Sid))
    return false;

  std::wstring peer(32768, L'\0');
  DWORD peer_length = static_cast<DWORD>(peer.size());
  if (!QueryFullProcessImageNameW(process.get(), 0, peer.data(),
                                  &peer_length) ||
      peer_length == 0 || static_cast<std::size_t>(peer_length) >= peer.size())
    return false;
  peer.resize(peer_length);
  return CompareStringOrdinal(current.c_str(), static_cast<int>(current.size()),
                              peer.c_str(), static_cast<int>(peer.size()),
                              TRUE) == CSTR_EQUAL;
}

std::wstring pipe_name(const shell_batch_action action) {
  DWORD session_id = 0;
  if (!ProcessIdToSessionId(GetCurrentProcessId(), &session_id))
    session_id = 0;
  return L"\\\\.\\pipe\\Oblivion.ShellBatch." +
         std::to_wstring(session_id) +
         (action == shell_batch_action::analyze ? L".Analyze" : L".Erase");
}

DWORD wait_until(const std::chrono::steady_clock::time_point deadline) {
  const auto now = std::chrono::steady_clock::now();
  if (now >= deadline)
    return 0;
  const auto remaining =
      std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now)
          .count();
  return static_cast<DWORD>((std::min)(
      static_cast<std::uint64_t>(remaining),
      static_cast<std::uint64_t>((std::numeric_limits<DWORD>::max)())));
}

bool write_all_overlapped(
    const HANDLE handle, const void *data, const DWORD size,
    const std::chrono::steady_clock::time_point deadline) {
  const auto *cursor = static_cast<const std::byte *>(data);
  DWORD remaining = size;
  while (remaining != 0) {
    unique_win_handle event{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    if (!event)
      return false;
    OVERLAPPED overlapped{};
    overlapped.hEvent = event.get();
    DWORD written = 0;
    if (!WriteFile(handle, cursor, remaining, nullptr, &overlapped)) {
      const DWORD error = GetLastError();
      if (error != ERROR_IO_PENDING)
        return false;
      const DWORD timeout = wait_until(deadline);
      if (timeout == 0 ||
          WaitForSingleObject(event.get(), timeout) != WAIT_OBJECT_0) {
        (void)CancelIoEx(handle, &overlapped);
        DWORD cancelled = 0;
        (void)GetOverlappedResult(handle, &overlapped, &cancelled, TRUE);
        return false;
      }
    }
    if (!GetOverlappedResult(handle, &overlapped, &written, FALSE) ||
        written == 0)
      return false;
    cursor += written;
    remaining -= written;
  }
  return true;
}

bool read_all_overlapped(
    const HANDLE handle, void *data, const DWORD size,
    const std::chrono::steady_clock::time_point deadline) {
  auto *cursor = static_cast<std::byte *>(data);
  DWORD remaining = size;
  while (remaining != 0) {
    unique_win_handle event{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    if (!event)
      return false;

    OVERLAPPED overlapped{};
    overlapped.hEvent = event.get();
    DWORD read = 0;
    if (!ReadFile(handle, cursor, remaining, nullptr, &overlapped)) {
      const DWORD error = GetLastError();
      if (error != ERROR_IO_PENDING)
        return false;
      const DWORD timeout = wait_until(deadline);
      if (timeout == 0) {
        (void)CancelIoEx(handle, &overlapped);
        DWORD cancelled = 0;
        (void)GetOverlappedResult(handle, &overlapped, &cancelled, TRUE);
        return false;
      }
      const DWORD wait = WaitForSingleObject(event.get(), timeout);
      if (wait != WAIT_OBJECT_0) {
        (void)CancelIoEx(handle, &overlapped);
        DWORD cancelled = 0;
        (void)GetOverlappedResult(handle, &overlapped, &cancelled, TRUE);
        return false;
      }
    }
    if (!GetOverlappedResult(handle, &overlapped, &read, FALSE) || read == 0)
      return false;
    cursor += read;
    remaining -= read;
  }
  return true;
}

bool send_to_owner(const std::wstring &name,
                   const std::filesystem::path &target,
                   const std::uint32_t timeout_ms) {
  const std::wstring value = target.wstring();
  if (value.empty() || value.size() > max_path_chars)
    return false;

  const auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::milliseconds(timeout_ms);
  while (std::chrono::steady_clock::now() < deadline) {
    unique_win_handle pipe{CreateFileW(name.c_str(), GENERIC_WRITE, 0, nullptr,
                                       OPEN_EXISTING, FILE_FLAG_OVERLAPPED,
                                       nullptr)};
    if (pipe) {
      ULONG server_process_id = 0;
      if (!GetNamedPipeServerProcessId(pipe.get(), &server_process_id) ||
          !same_executable_process(server_process_id))
        return false;
      const auto count = static_cast<std::uint32_t>(value.size());
      const auto bytes64 = static_cast<std::uint64_t>(count) * sizeof(wchar_t);
      if (bytes64 > (std::numeric_limits<DWORD>::max)())
        return false;
      const auto bytes = static_cast<DWORD>(bytes64);
      return write_all_overlapped(pipe.get(), &count, sizeof(count), deadline) &&
             write_all_overlapped(pipe.get(), value.data(), bytes, deadline);
    }

    const DWORD error = GetLastError();
    if (error != ERROR_PIPE_BUSY && error != ERROR_FILE_NOT_FOUND &&
        error != ERROR_ACCESS_DENIED)
      return false;
    (void)WaitNamedPipeW(name.c_str(), 100);
    std::this_thread::sleep_for(std::chrono::milliseconds(15));
  }
  return false;
}

accept_result accept_one(const HANDLE pipe,
                         const std::uint32_t quiet_timeout_ms,
                         std::filesystem::path &target) {
  unique_win_handle event{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
  if (!event)
    return accept_result::fatal_error;

  OVERLAPPED overlapped{};
  overlapped.hEvent = event.get();
  bool connected = ConnectNamedPipe(pipe, &overlapped) != FALSE;
  if (!connected) {
    const DWORD error = GetLastError();
    if (error == ERROR_PIPE_CONNECTED) {
      connected = true;
    } else if (error == ERROR_IO_PENDING) {
      const DWORD wait = WaitForSingleObject(event.get(), quiet_timeout_ms);
      if (wait == WAIT_TIMEOUT) {
        (void)CancelIoEx(pipe, &overlapped);
        DWORD cancelled = 0;
        (void)GetOverlappedResult(pipe, &overlapped, &cancelled, TRUE);
        return accept_result::quiet_timeout;
      }
      if (wait != WAIT_OBJECT_0)
        return accept_result::fatal_error;
      DWORD transferred = 0;
      if (!GetOverlappedResult(pipe, &overlapped, &transferred, FALSE))
        return accept_result::fatal_error;
      connected = true;
    } else {
      return accept_result::fatal_error;
    }
  }

  if (!connected)
    return accept_result::fatal_error;

  ULONG client_process_id = 0;
  if (!GetNamedPipeClientProcessId(pipe, &client_process_id) ||
      !same_executable_process(client_process_id)) {
    (void)DisconnectNamedPipe(pipe);
    return accept_result::rejected;
  }

  std::uint32_t count = 0;
  const auto message_deadline = std::chrono::steady_clock::now() +
                                std::chrono::milliseconds(1500);
  if (!read_all_overlapped(pipe, &count, sizeof(count), message_deadline) ||
      count == 0 ||
      count > max_path_chars) {
    (void)DisconnectNamedPipe(pipe);
    return accept_result::rejected;
  }

  std::wstring value(count, L'\0');
  const auto bytes64 = static_cast<std::uint64_t>(count) * sizeof(wchar_t);
  if (bytes64 > (std::numeric_limits<DWORD>::max)()) {
    (void)DisconnectNamedPipe(pipe);
    return accept_result::rejected;
  }
  const auto bytes = static_cast<DWORD>(bytes64);
  const bool read_ok =
      read_all_overlapped(pipe, value.data(), bytes, message_deadline);
  (void)DisconnectNamedPipe(pipe);
  if (!read_ok || value.find(L'\0') != std::wstring::npos)
    return accept_result::rejected;

  target = std::filesystem::path{value};
  return target.empty() ? accept_result::rejected : accept_result::received;
}

unique_win_handle create_owner_pipe(const std::wstring &name) {
  return unique_win_handle{CreateNamedPipeW(
      name.c_str(), PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED |
                        FILE_FLAG_FIRST_PIPE_INSTANCE,
      PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT |
          PIPE_REJECT_REMOTE_CLIENTS,
      1, 0, pipe_buffer_bytes, 0, nullptr)};
}

} // namespace

shell_batch_result collect_shell_batch(const shell_batch_action action,
                                       const std::filesystem::path &target,
                                       const std::uint32_t quiet_timeout_ms,
                                       const std::uint32_t client_timeout_ms) {
  shell_batch_result result;
  if (target.empty()) {
    result.error = L"Leeres Shell-Ziel.";
    return result;
  }

  const std::wstring name = pipe_name(action);
  for (int attempt = 0; attempt < 3; ++attempt) {
    unique_win_handle server = create_owner_pipe(name);
    if (server) {
      result.owner = true;
      result.success = true;
      result.targets.push_back(target);

      const auto batch_deadline = std::chrono::steady_clock::now() +
                                  std::chrono::seconds(5);
      for (;;) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= batch_deadline)
          break;
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                                   batch_deadline - now)
                                   .count();
        const auto wait_ms = static_cast<std::uint32_t>((std::min)(
            static_cast<std::uint64_t>(quiet_timeout_ms),
            static_cast<std::uint64_t>(remaining)));
        std::filesystem::path received;
        const auto accepted = accept_one(server.get(), wait_ms, received);
        if (accepted == accept_result::quiet_timeout ||
            accepted == accept_result::fatal_error)
          break;
        if (accepted == accept_result::received) {
          if (result.targets.size() >= max_batch_targets) {
            result.success = false;
            result.error = L"Shell-Mehrfachauswahl überschreitet das sichere "
                           L"Limit von 4096 Zielen.";
            break;
          }
          result.targets.push_back(std::move(received));
        }
      }
      return result;
    }

    const DWORD error = GetLastError();
    if (error != ERROR_ACCESS_DENIED && error != ERROR_PIPE_BUSY) {
      result.error = L"Shell-Batch-Kanal konnte nicht erstellt werden. Win32=" +
                     std::to_wstring(error);
      return result;
    }

    if (send_to_owner(name, target, client_timeout_ms)) {
      result.owner = false;
      result.success = true;
      return result;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(25));
  }

  result.error = L"Shell-Mehrfachauswahl konnte nicht an die führende "
                 L"OBLIVION-Instanz übergeben werden.";
  return result;
}

} // namespace oblivion
