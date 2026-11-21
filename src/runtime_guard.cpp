#include "oblivion/runtime_guard.hpp"

#include <Windows.h>

#include <sstream>

namespace oblivion {
namespace {

template <typename Policy>
bool apply_and_query(const PROCESS_MITIGATION_POLICY kind, Policy requested,
                     Policy &active) noexcept {
  (void)SetProcessMitigationPolicy(kind, &requested, sizeof(requested));
  return GetProcessMitigationPolicy(GetCurrentProcess(), kind, &active,
                                    sizeof(active)) != FALSE;
}

const wchar_t *state(const bool enabled) noexcept {
  return enabled ? L"aktiv" : L"FEHLER";
}

} // namespace

runtime_hardening_status harden_current_process() noexcept {
  runtime_hardening_status status;
  status.safe_dll_search =
      SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) != FALSE;
  status.heap_corruption_termination =
      HeapSetInformation(nullptr, HeapEnableTerminationOnCorruption, nullptr,
                         0) != FALSE;

  PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynamic_requested{};
  dynamic_requested.ProhibitDynamicCode = 1;
  PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynamic_active{};
  status.dynamic_code_prohibited =
      apply_and_query(ProcessDynamicCodePolicy, dynamic_requested,
                      dynamic_active) &&
      dynamic_active.ProhibitDynamicCode != 0;

  PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY handle_requested{};
  handle_requested.RaiseExceptionOnInvalidHandleReference = 1;
  handle_requested.HandleExceptionsPermanentlyEnabled = 1;
  PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY handle_active{};
  status.strict_handle_checks =
      apply_and_query(ProcessStrictHandleCheckPolicy, handle_requested,
                      handle_active) &&
      handle_active.RaiseExceptionOnInvalidHandleReference != 0 &&
      handle_active.HandleExceptionsPermanentlyEnabled != 0;

  PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY extension_requested{};
  extension_requested.DisableExtensionPoints = 1;
  PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY extension_active{};
  status.legacy_extension_points_disabled =
      apply_and_query(ProcessExtensionPointDisablePolicy, extension_requested,
                      extension_active) &&
      extension_active.DisableExtensionPoints != 0;

  PROCESS_MITIGATION_IMAGE_LOAD_POLICY image_requested{};
  image_requested.NoRemoteImages = 1;
  image_requested.NoLowMandatoryLabelImages = 1;
  image_requested.PreferSystem32Images = 1;
  PROCESS_MITIGATION_IMAGE_LOAD_POLICY image_active{};
  status.unsafe_images_blocked =
      apply_and_query(ProcessImageLoadPolicy, image_requested, image_active) &&
      image_active.NoRemoteImages != 0 &&
      image_active.NoLowMandatoryLabelImages != 0 &&
      image_active.PreferSystem32Images != 0;

  // Suppress OS "Bad Image" (0xc0000428) modal popups when third-party shell
  // extensions (e.g. Nilesoft Shell) are blocked by MicrosoftSignedOnly inside
  // file dialogs.
  SetErrorMode(GetErrorMode() | SEM_FAILCRITICALERRORS |
               SEM_NOOPENFILEERRORBOX);

  PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY signature_requested{};
  signature_requested.MicrosoftSignedOnly = 1;
  PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY signature_active{};
  status.microsoft_signed_binaries_only =
      apply_and_query(ProcessSignaturePolicy, signature_requested,
                      signature_active) &&
      signature_active.MicrosoftSignedOnly != 0;
  return status;
}

std::wstring format_runtime_hardening(const runtime_hardening_status &status) {
  std::wostringstream output;
  output << L"OBLIVION Laufzeithärtung\n\n"
         << L"Sichere DLL-Suche: " << state(status.safe_dll_search) << L'\n'
         << L"Heap-Korruptionsabbruch: "
         << state(status.heap_corruption_termination) << L'\n'
         << L"Dynamischer Code gesperrt: "
         << state(status.dynamic_code_prohibited) << L'\n'
         << L"Strikte Handle-Prüfung: " << state(status.strict_handle_checks)
         << L'\n' << L"Legacy Extension Points gesperrt: "
         << state(status.legacy_extension_points_disabled) << L'\n'
         << L"Unsichere Images gesperrt: "
         << state(status.unsafe_images_blocked) << L'\n'
         << L"Nur Microsoft-signierte DLLs: "
         << state(status.microsoft_signed_binaries_only)
         << L"\n\nGesamtstatus: " << (status.complete() ? L"OK" : L"FEHLER");
  return output.str();
}

} // namespace oblivion
