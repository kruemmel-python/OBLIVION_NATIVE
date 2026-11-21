#include "oblivion/secure_memory.hpp"

#include <Windows.h>

namespace oblivion {

void secure_wipe(const std::span<std::byte> memory) noexcept {
  if (!memory.empty()) {
    SecureZeroMemory(memory.data(), memory.size());
  }
}

secure_buffer::secure_buffer(const std::size_t size) noexcept : size_(size) {
  if (size_ == 0) {
    return;
  }
  data_ = static_cast<std::byte *>(
      VirtualAlloc(nullptr, size_, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
  if (data_ == nullptr) {
    return;
  }
  locked_ = VirtualLock(data_, size_) != FALSE;
}

secure_buffer::~secure_buffer() {
  clear();
  if (locked_) {
    (void)VirtualUnlock(data_, size_);
  }
  if (data_ != nullptr) {
    (void)VirtualFree(data_, 0, MEM_RELEASE);
  }
}

void secure_buffer::clear() noexcept {
  if (data_ != nullptr) {
    secure_wipe(bytes());
  }
}

} // namespace oblivion
