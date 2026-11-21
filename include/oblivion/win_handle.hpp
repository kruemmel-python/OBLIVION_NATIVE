#pragma once

#include <Windows.h>

#include <utility>

namespace oblivion {

class unique_win_handle final {
public:
  unique_win_handle() noexcept = default;
  explicit unique_win_handle(HANDLE handle) noexcept : handle_(handle) {}
  ~unique_win_handle() { reset(); }

  unique_win_handle(const unique_win_handle &) = delete;
  unique_win_handle &operator=(const unique_win_handle &) = delete;

  unique_win_handle(unique_win_handle &&other) noexcept
      : handle_(other.release()) {}
  unique_win_handle &operator=(unique_win_handle &&other) noexcept {
    if (this != &other) {
      reset(other.release());
    }
    return *this;
  }

  [[nodiscard]] HANDLE get() const noexcept { return handle_; }
  [[nodiscard]] explicit operator bool() const noexcept {
    return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
  }
  [[nodiscard]] HANDLE release() noexcept {
    return std::exchange(handle_, INVALID_HANDLE_VALUE);
  }
  void reset(HANDLE replacement = INVALID_HANDLE_VALUE) noexcept {
    if (*this) {
      (void)CloseHandle(handle_);
    }
    handle_ = replacement;
  }

private:
  HANDLE handle_{INVALID_HANDLE_VALUE};
};

} // namespace oblivion
