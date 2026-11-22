#include "oblivion/shell_batch.hpp"
#include "oblivion/win_handle.hpp"

#include <Windows.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cwctype>
#include <filesystem>
#include <future>
#include <iostream>
#include <string>
#include <string_view>
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

  DWORD session = 0;
  if (!ProcessIdToSessionId(GetCurrentProcessId(), &session))
    return fail("Sitzung fuer Timeout-Test nicht bestimmbar.", 6);
  const std::wstring stalled_name =
      L"\\\\.\\pipe\\Oblivion.ShellBatch." + std::to_wstring(session) +
      L".Analyze";
  auto stalled_owner = std::async(std::launch::async, [&] {
    return collect_shell_batch(shell_batch_action::analyze,
                               root / L"owner-target.bin", 100, 1500);
  });
  std::this_thread::sleep_for(std::chrono::milliseconds(25));
  unique_win_handle stalled_client;
  for (unsigned attempt = 0; attempt < 20 && !stalled_client; ++attempt) {
    stalled_client.reset(CreateFileW(stalled_name.c_str(), GENERIC_WRITE, 0,
                                     nullptr, OPEN_EXISTING, 0, nullptr));
    if (!stalled_client)
      std::this_thread::sleep_for(std::chrono::milliseconds(25));
  }
  if (!stalled_client)
    return fail("Timeout-Test-Client konnte nicht verbinden.", 7);
  const std::uint32_t slow_count = 4;
  DWORD written = 0;
  if (!WriteFile(stalled_client.get(), &slow_count, sizeof(slow_count),
                 &written, nullptr) ||
      written != sizeof(slow_count))
    return fail("Timeout-Test-Header konnte nicht gesendet werden.", 8);
  const auto timeout_start = std::chrono::steady_clock::now();
  for (const wchar_t character : std::wstring_view{L"ABCD"}) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    written = 0;
    if (!WriteFile(stalled_client.get(), &character, sizeof(character),
                   &written, nullptr) ||
        written != sizeof(character))
      break;
  }
  stalled_client.reset();
  const auto stalled = stalled_owner.get();
  const auto timeout_elapsed = std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::steady_clock::now() - timeout_start);
  if (!stalled.success || !stalled.owner || stalled.targets.size() != 1u ||
      timeout_elapsed >= std::chrono::seconds(3))
    return fail("Partieller Pipe-Transfer respektiert keine Gesamtfrist.", 9);

  std::cout << "Statische Windows-Shell-Aufrufe werden zu einer nativen "
               "OBLIVION-Mehrfachoperation gebuendelt.\n";
  return 0;
}
