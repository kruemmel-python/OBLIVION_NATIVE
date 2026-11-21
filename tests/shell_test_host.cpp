#include <Windows.h>
#include <shellapi.h>

#include <filesystem>
#include <fstream>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

namespace {
std::string utf8(const std::wstring_view value) {
    if (value.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)())) return {};
    const auto length = static_cast<int>(value.size());
    const int required = WideCharToMultiByte(CP_UTF8, 0, value.data(), length, nullptr, 0, nullptr, nullptr);
    if (required <= 0) return {};
    std::string result(static_cast<std::size_t>(required), '\0');
    if (WideCharToMultiByte(CP_UTF8, 0, value.data(), length, result.data(), required, nullptr, nullptr) != required) return {};
    return result;
}
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    constexpr wchar_t variable[] = L"OBLIVION_SHELL_TEST_LOG";
    const DWORD required = GetEnvironmentVariableW(variable, nullptr, 0);
    if (required < 2) return 2;
    std::vector<wchar_t> log_path(required);
    if (GetEnvironmentVariableW(variable, log_path.data(), required) != required - 1) return 3;

    int argc = 0;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) return 4;

    std::ofstream output(std::filesystem::path{log_path.data()}, std::ios::binary | std::ios::trunc);
    if (!output) {
        LocalFree(argv);
        return 5;
    }
    output << argc << '\n';
    for (int index = 0; index < argc; ++index) output << utf8(argv[index]) << '\n';
    LocalFree(argv);
    return output ? 0 : 6;
}
