#pragma once

#include <cstddef>
#include <span>

namespace oblivion {

void secure_wipe(std::span<std::byte> memory) noexcept;

class secure_buffer final {
public:
  explicit secure_buffer(std::size_t size) noexcept;
  ~secure_buffer();

  secure_buffer(const secure_buffer &) = delete;
  secure_buffer &operator=(const secure_buffer &) = delete;
  secure_buffer(secure_buffer &&) = delete;
  secure_buffer &operator=(secure_buffer &&) = delete;

  [[nodiscard]] std::byte *data() noexcept { return data_; }
  [[nodiscard]] const std::byte *data() const noexcept { return data_; }
  [[nodiscard]] std::size_t size() const noexcept { return size_; }
  [[nodiscard]] bool locked() const noexcept { return locked_; }
  [[nodiscard]] bool valid() const noexcept {
    return size_ == 0 || data_ != nullptr;
  }
  [[nodiscard]] std::span<std::byte> bytes() noexcept {
    return {data_, size_};
  }
  void clear() noexcept;

private:
  std::byte *data_{nullptr};
  std::size_t size_{0};
  bool locked_{false};
};

} // namespace oblivion
