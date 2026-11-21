#include "oblivion/shell_batch.hpp"
#include "oblivion/win_handle.hpp"

#include <Windows.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <thread>

namespace oblivion {
namespace {

constexpr std::uint32_t max_path_chars = 32767u;
constexpr DWORD pipe_buffer_bytes = 65536u;

std::wstring pipe_name(const shell_batch_action action) {
  DWORD session_id = 0;
  if (!ProcessIdToSessionId(GetCurrentProcessId(), &session_id))
    session_id = 0;
  return L"\\\\.\\pipe\\Oblivion.ShellBatch." +
         std::to_wstring(session_id) +
         (action == shell_batch_action::analyze ? L".Analyze" : L".Erase");
}

bool write_all(const HANDLE handle, const void *data, const DWORD size) {
  const auto *cursor = static_cast<const std::byte *>(data);
  DWORD remaining = size;
  while (remaining != 0) {
    DWORD written = 0;
    if (!WriteFile(handle, cursor, remaining, &written, nullptr) || written == 0)
      return false;
    cursor += written;
    remaining -= written;
  }
  return true;
}

bool read_all_overlapped(const HANDLE handle, void *data, const DWORD size,
                         const DWORD timeout_ms) {
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
      const DWORD wait = WaitForSingleObject(event.get(), timeout_ms);
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
                                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                                       nullptr)};
    if (pipe) {
      const auto count = static_cast<std::uint32_t>(value.size());
      const auto bytes64 = static_cast<std::uint64_t>(count) * sizeof(wchar_t);
      if (bytes64 > (std::numeric_limits<DWORD>::max)())
        return false;
      const auto bytes = static_cast<DWORD>(bytes64);
      return write_all(pipe.get(), &count, sizeof(count)) &&
             write_all(pipe.get(), value.data(), bytes);
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

bool accept_one(const HANDLE pipe, const std::uint32_t quiet_timeout_ms,
                std::filesystem::path &target) {
  unique_win_handle event{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
  if (!event)
    return false;

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
        return false;
      }
      if (wait != WAIT_OBJECT_0)
        return false;
      DWORD transferred = 0;
      if (!GetOverlappedResult(pipe, &overlapped, &transferred, FALSE))
        return false;
      connected = true;
    } else {
      return false;
    }
  }

  if (!connected)
    return false;

  std::uint32_t count = 0;
  if (!read_all_overlapped(pipe, &count, sizeof(count), 1500) || count == 0 ||
      count > max_path_chars) {
    (void)DisconnectNamedPipe(pipe);
    return false;
  }

  std::wstring value(count, L'\0');
  const auto bytes64 = static_cast<std::uint64_t>(count) * sizeof(wchar_t);
  if (bytes64 > (std::numeric_limits<DWORD>::max)()) {
    (void)DisconnectNamedPipe(pipe);
    return false;
  }
  const auto bytes = static_cast<DWORD>(bytes64);
  const bool read_ok = read_all_overlapped(pipe, value.data(), bytes, 1500);
  (void)DisconnectNamedPipe(pipe);
  if (!read_ok)
    return false;

  target = std::filesystem::path{value};
  return !target.empty();
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
        if (!accept_one(server.get(), wait_ms, received))
          break;
        result.targets.push_back(std::move(received));
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
