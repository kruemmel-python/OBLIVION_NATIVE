#include <Windows.h>
#include <shobjidl.h>

#include <array>
#include <filesystem>
#include <iostream>
#include <string>

namespace {
constexpr CLSID root_clsid{0xb7bc56b2,
                           0x689f,
                           0x4e78,
                           {0x9a, 0x59, 0x63, 0xf1, 0x80, 0x11, 0xe6, 0xb0}};

template <typename T> class com_ptr {
  T *value_{};

public:
  ~com_ptr() {
    if (value_)
      value_->Release();
  }
  T **put() noexcept { return &value_; }
  T *operator->() const noexcept { return value_; }
  explicit operator bool() const noexcept { return value_ != nullptr; }
};

bool title_is(IExplorerCommand *command, const wchar_t *expected) {
  PWSTR title{};
  const HRESULT result = command->GetTitle(nullptr, &title);
  const bool matches = SUCCEEDED(result) && title != nullptr &&
                       std::wstring_view{title} == expected;
  CoTaskMemFree(title);
  return matches;
}
} // namespace

int wmain(int argc, wchar_t **argv) {
  const HRESULT com_result = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
  if (FAILED(com_result))
    return 10;

  if (argc == 2 && std::wstring_view{argv[1]} == L"--registered") {
    com_ptr<IExplorerCommand> registered;
    const HRESULT activation = CoCreateInstance(
        root_clsid, nullptr, CLSCTX_LOCAL_SERVER, IID_PPV_ARGS(registered.put()));
    if (FAILED(activation) || !registered ||
        !title_is(registered.operator->(), L"Oblivion")) {
      std::wcerr << L"Registrierte COM-Aktivierung fehlgeschlagen: 0x"
                 << std::hex << static_cast<unsigned long>(activation) << L'\n';
      CoUninitialize();
      return 11;
    }
    std::wcout << L"Registrierte COM-Aktivierung erfolgreich.\n";
    CoUninitialize();
    return 0;
  }

  std::wstring executable(32768, L'\0');
  const DWORD length = GetModuleFileNameW(
      nullptr, executable.data(), static_cast<DWORD>(executable.size()));
  if (length == 0 || static_cast<std::size_t>(length) >= executable.size())
    return 1;
  executable.resize(length);
  const auto dll =
      std::filesystem::path{executable}.parent_path() / L"OblivionShell.dll";
  const HMODULE module = LoadLibraryExW(
      dll.c_str(), nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR |
                                LOAD_LIBRARY_SEARCH_SYSTEM32);
  if (!module)
    return 2;
  using get_class_object_fn = HRESULT(STDAPICALLTYPE *)(REFCLSID, REFIID,
                                                        void **);
  const auto get_class_object = reinterpret_cast<get_class_object_fn>(
      GetProcAddress(module, "DllGetClassObject"));
  if (!get_class_object) {
    FreeLibrary(module);
    return 3;
  }

  com_ptr<IClassFactory> factory;
  HRESULT result = get_class_object(root_clsid, IID_PPV_ARGS(factory.put()));
  if (FAILED(result) || !factory)
    return 4;
  com_ptr<IExplorerCommand> root;
  result = factory->CreateInstance(nullptr, IID_PPV_ARGS(root.put()));
  if (FAILED(result) || !root || !title_is(root.operator->(), L"Oblivion"))
    return 5;
  EXPCMDFLAGS flags{};
  if (FAILED(root->GetFlags(&flags)) || (flags & ECF_HASSUBCOMMANDS) == 0)
    return 6;
  com_ptr<IEnumExplorerCommand> children;
  if (FAILED(root->EnumSubCommands(children.put())) || !children)
    return 7;
  constexpr std::array<const wchar_t *, 3> expected{
      L"Sicher löschen", L"Analysieren (Dry Run)", L"Optionen"};
  for (const auto *title : expected) {
    IExplorerCommand *child{};
    ULONG fetched{};
    result = children->Next(1, &child, &fetched);
    if (result != S_OK || fetched != 1 || !child || !title_is(child, title)) {
      if (child)
        child->Release();
      return 8;
    }
    child->Release();
  }
  IExplorerCommand *extra{};
  ULONG fetched{};
  result = children->Next(1, &extra, &fetched);
  if (extra)
    extra->Release();
  if (result != S_FALSE || fetched != 0)
    return 9;
  std::wcout << L"IExplorerCommand-Untermenü vollständig verifiziert.\n";
  CoUninitialize();
  return 0;
}
