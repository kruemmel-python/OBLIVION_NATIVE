#pragma once

#include <Windows.h>
#include <bcrypt.h>

#include <utility>

namespace oblivion {

class unique_bcrypt_algorithm final {
public:
  unique_bcrypt_algorithm() noexcept = default;
  ~unique_bcrypt_algorithm() { reset(); }
  unique_bcrypt_algorithm(const unique_bcrypt_algorithm &) = delete;
  unique_bcrypt_algorithm &operator=(const unique_bcrypt_algorithm &) = delete;
  unique_bcrypt_algorithm(unique_bcrypt_algorithm &&other) noexcept
      : value_(other.release()) {}
  unique_bcrypt_algorithm &
  operator=(unique_bcrypt_algorithm &&other) noexcept {
    if (this != &other)
      reset(other.release());
    return *this;
  }
  BCRYPT_ALG_HANDLE get() const noexcept { return value_; }
  BCRYPT_ALG_HANDLE *put() noexcept {
    reset();
    return &value_;
  }
  explicit operator bool() const noexcept { return value_ != nullptr; }
  BCRYPT_ALG_HANDLE release() noexcept {
    return std::exchange(value_, nullptr);
  }
  void reset(BCRYPT_ALG_HANDLE replacement = nullptr) noexcept {
    if (value_)
      (void)BCryptCloseAlgorithmProvider(value_, 0);
    value_ = replacement;
  }

private:
  BCRYPT_ALG_HANDLE value_{};
};

class unique_bcrypt_hash final {
public:
  unique_bcrypt_hash() noexcept = default;
  ~unique_bcrypt_hash() { reset(); }
  unique_bcrypt_hash(const unique_bcrypt_hash &) = delete;
  unique_bcrypt_hash &operator=(const unique_bcrypt_hash &) = delete;
  unique_bcrypt_hash(unique_bcrypt_hash &&other) noexcept
      : value_(other.release()) {}
  unique_bcrypt_hash &operator=(unique_bcrypt_hash &&other) noexcept {
    if (this != &other)
      reset(other.release());
    return *this;
  }
  BCRYPT_HASH_HANDLE get() const noexcept { return value_; }
  BCRYPT_HASH_HANDLE *put() noexcept {
    reset();
    return &value_;
  }
  explicit operator bool() const noexcept { return value_ != nullptr; }
  BCRYPT_HASH_HANDLE release() noexcept {
    return std::exchange(value_, nullptr);
  }
  void reset(BCRYPT_HASH_HANDLE replacement = nullptr) noexcept {
    if (value_)
      (void)BCryptDestroyHash(value_);
    value_ = replacement;
  }

private:
  BCRYPT_HASH_HANDLE value_{};
};

} // namespace oblivion
