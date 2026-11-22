#pragma once

#include <Windows.h>
#include <objbase.h>

#include <utility>

namespace oblivion {

class unique_cotaskmem_string final {
public:
  unique_cotaskmem_string() noexcept = default;
  explicit unique_cotaskmem_string(PWSTR value) noexcept : value_(value) {}
  ~unique_cotaskmem_string() { reset(); }
  unique_cotaskmem_string(const unique_cotaskmem_string &) = delete;
  unique_cotaskmem_string &operator=(const unique_cotaskmem_string &) = delete;
  unique_cotaskmem_string(unique_cotaskmem_string &&other) noexcept
      : value_(other.release()) {}
  unique_cotaskmem_string &
  operator=(unique_cotaskmem_string &&other) noexcept {
    if (this != &other)
      reset(other.release());
    return *this;
  }
  PWSTR get() const noexcept { return value_; }
  PWSTR *put() noexcept {
    reset();
    return &value_;
  }
  explicit operator bool() const noexcept { return value_ != nullptr; }
  PWSTR release() noexcept { return std::exchange(value_, nullptr); }
  void reset(PWSTR replacement = nullptr) noexcept {
    CoTaskMemFree(value_);
    value_ = replacement;
  }

private:
  PWSTR value_{};
};

} // namespace oblivion
