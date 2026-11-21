#include "oblivion/shell_batch.hpp"

#include <Windows.h>

#include <algorithm>
#include <chrono>
#include <cwctype>
#include <filesystem>
#include <future>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace {
int fail(const std::string &message, const int code) {
  std::cerr << message << '\n';
  return code;
}

std::wstring lower(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(), [](wchar_t c) {
    return static_cast<wchar_t>(towlower(c));
  });
  return value;
}
} // namespace

int wmain() {
  using namespace oblivion;

  const auto root = std::filesystem::temp_directory_path() /
                    (L"oblivion-shell-batch-test-" +
                     std::to_wstring(GetCurrentProcessId()) + L"-" +
                     std::to_wstring(GetTickCount64()));
  const std::vector<std::filesystem::path> expected = {
      root / L"erste Datei.txt", root / L"zweite Datei.bin",
      root / L"dritte-äöü.dat"};

  auto owner_future = std::async(std::launch::async, [&] {
    return collect_shell_batch(shell_batch_action::erase, expected[0], 350,
                               1500);
  });

  std::this_thread::sleep_for(std::chrono::milliseconds(120));
  const auto second =
      collect_shell_batch(shell_batch_action::erase, expected[1], 350, 1500);
  const auto third =
      collect_shell_batch(shell_batch_action::erase, expected[2], 350, 1500);
  const auto owner = owner_future.get();

  if (!owner.success || !owner.owner)
    return fail("Fuehrende Shell-Batch-Instanz fehlgeschlagen.", 2);
  if (!second.success || second.owner || !third.success || third.owner)
    return fail("Folgeinstanz wurde nicht an den Batch uebergeben.", 3);
  if (owner.targets.size() != expected.size())
    return fail("Shell-Batch enthaelt nicht alle drei Ziele.", 4);

  std::vector<std::wstring> actual;
  std::vector<std::wstring> wanted;
  for (const auto &path : owner.targets)
    actual.push_back(lower(path.wstring()));
  for (const auto &path : expected)
    wanted.push_back(lower(path.wstring()));
  std::ranges::sort(actual);
  std::ranges::sort(wanted);
  if (actual != wanted)
    return fail("Shell-Batch hat ein falsches Ziel uebergeben.", 5);

  std::cout << "Statische Windows-Shell-Aufrufe werden zu einer nativen "
               "OBLIVION-Mehrfachoperation gebuendelt.\n";
  return 0;
}
