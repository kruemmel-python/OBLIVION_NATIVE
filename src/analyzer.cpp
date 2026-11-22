#include "oblivion/analyzer.hpp"
#include "oblivion/win_handle.hpp"
#include <Windows.h>
#include <array>
#include <filesystem>
#include <limits>
#include <sstream>
#include <system_error>
#include <vector>
#ifdef OBLIVION_TESTING
#include "oblivion/test_hooks.hpp"
#endif
namespace oblivion { namespace {
constexpr std::size_t max_analysis_entries = 1000000u;
constexpr std::size_t max_analysis_streams_per_file = 100000u;
std::size_t analysis_entry_limit() noexcept {
#ifdef OBLIVION_TESTING
  if (testing::hooks().analysis_max_entries != 0)
    return testing::hooks().analysis_max_entries;
#endif
  return max_analysis_entries;
}
class unique_find_handle {
  HANDLE value_{INVALID_HANDLE_VALUE};
public:
  explicit unique_find_handle(HANDLE value) noexcept : value_(value) {}
  ~unique_find_handle(){if(value_!=INVALID_HANDLE_VALUE)FindClose(value_);}
  unique_find_handle(const unique_find_handle&)=delete;
  unique_find_handle& operator=(const unique_find_handle&)=delete;
  HANDLE get()const noexcept{return value_;}
  explicit operator bool()const noexcept{return value_!=INVALID_HANDLE_VALUE;}
};
std::uint64_t sat(std::uint64_t a,std::uint64_t b){const auto m=(std::numeric_limits<std::uint64_t>::max)();return b>m-a?m:a+b;}
void warn(file_analysis&r,std::wstring s){if(r.warnings.size()<64)r.warnings.push_back(std::move(s));}
void merge(file_analysis&a,const file_analysis&b){a.files=sat(a.files,b.files);a.directories=sat(a.directories,b.directories);a.logical_bytes=sat(a.logical_bytes,b.logical_bytes);a.alternate_streams=sat(a.alternate_streams,b.alternate_streams);a.alternate_stream_bytes=sat(a.alternate_stream_bytes,b.alternate_stream_bytes);a.reparse_points=sat(a.reparse_points,b.reparse_points);a.hardlinked_files=sat(a.hardlinked_files,b.hardlinked_files);a.sparse_files=sat(a.sparse_files,b.sparse_files);a.compressed_files=sat(a.compressed_files,b.compressed_files);a.encrypted_files=sat(a.encrypted_files,b.encrypted_files);a.readonly_entries=sat(a.readonly_entries,b.readonly_entries);a.inaccessible_entries=sat(a.inaccessible_entries,b.inaccessible_entries);for(const auto&w:b.warnings)warn(a,w);}
void streams(const std::filesystem::path &p, file_analysis &r) {
  std::vector<wchar_t> volume_root(32768, L'\0');
  DWORD filesystem_flags = 0;
  if (!GetVolumePathNameW(p.c_str(), volume_root.data(),
                          static_cast<DWORD>(volume_root.size())) ||
      !GetVolumeInformationW(volume_root.data(), nullptr, 0, nullptr, nullptr,
                             &filesystem_flags, nullptr, 0)) {
    ++r.inaccessible_entries;
    warn(r, L"Datenstrom-Unterstützung nicht bestimmbar: " + p.wstring());
    return;
  }
  if ((filesystem_flags & FILE_NAMED_STREAMS) == 0)
    return;
  WIN32_FIND_STREAM_DATA data{};
  unique_find_handle stream{
      FindFirstStreamW(p.c_str(), FindStreamInfoStandard, &data, 0)};
  if (!stream) {
    if (GetLastError() != ERROR_HANDLE_EOF) {
      ++r.inaccessible_entries;
      warn(r, L"Datenströme nicht vollständig aufzählbar: " + p.wstring());
    }
    return;
  }
  std::size_t stream_count = 0;
  for (;;) {
    if (++stream_count > max_analysis_streams_per_file) {
      ++r.inaccessible_entries;
      warn(r, L"Datenstrom-Limit überschritten: " + p.wstring());
      break;
    }
    std::wstring name = data.cStreamName;
    if (!name.empty() && name != L"::$DATA") {
      ++r.alternate_streams;
      if (data.StreamSize.QuadPart > 0)
        r.alternate_stream_bytes =
            sat(r.alternate_stream_bytes,
                static_cast<std::uint64_t>(data.StreamSize.QuadPart));
    }
    if (!FindNextStreamW(stream.get(), &data)) {
      const DWORD error = GetLastError();
      if (error != ERROR_HANDLE_EOF) {
        ++r.inaccessible_entries;
        warn(r, L"Datenstrom-Aufzählung abgebrochen: " + p.wstring());
      }
      break;
    }
  }
}
bool scan(const std::filesystem::path &p, file_analysis &r,
          const std::size_t depth, std::size_t &entry_count) {
  constexpr std::size_t max_directory_depth = 256;
  if (entry_count >= analysis_entry_limit()) {
    ++r.inaccessible_entries;
    warn(r, L"Maximales Analyse-Limit von 1000000 Einträgen überschritten.");
    return false;
  }
  ++entry_count;
  if (depth > max_directory_depth) {
    ++r.inaccessible_entries;
    warn(r, L"Maximale sichere Verzeichnistiefe überschritten: " + p.wstring());
    return true;
  }
  DWORD attributes = GetFileAttributesW(p.c_str());
  if (attributes == INVALID_FILE_ATTRIBUTES) {
    ++r.inaccessible_entries;
    warn(r, L"Nicht zugreifbar: " + p.wstring());
    return true;
  }
  if (attributes & FILE_ATTRIBUTE_READONLY)
    ++r.readonly_entries;
  if (attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
    ++r.reparse_points;
    if (attributes & FILE_ATTRIBUTE_DIRECTORY)
      ++r.directories;
    else
      ++r.files;
    return true;
  }
  if (!(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
    ++r.files;
    WIN32_FILE_ATTRIBUTE_DATA data{};
    if (GetFileAttributesExW(p.c_str(), GetFileExInfoStandard, &data)) {
      ULARGE_INTEGER size{};
      size.HighPart = data.nFileSizeHigh;
      size.LowPart = data.nFileSizeLow;
      r.logical_bytes = sat(r.logical_bytes, size.QuadPart);
    } else {
      ++r.inaccessible_entries;
    }
    if (attributes & FILE_ATTRIBUTE_SPARSE_FILE)
      ++r.sparse_files;
    if (attributes & FILE_ATTRIBUTE_COMPRESSED)
      ++r.compressed_files;
    if (attributes & FILE_ATTRIBUTE_ENCRYPTED)
      ++r.encrypted_files;
    unique_win_handle handle{CreateFileW(
        p.c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
    if (handle) {
      BY_HANDLE_FILE_INFORMATION information{};
      if (GetFileInformationByHandle(handle.get(), &information) &&
          information.nNumberOfLinks > 1)
        ++r.hardlinked_files;
    } else {
      ++r.inaccessible_entries;
    }
    streams(p, r);
    return true;
  }
  ++r.directories;
  std::error_code error;
  std::filesystem::directory_iterator iterator(p, error), end;
  if (error) {
    ++r.inaccessible_entries;
    warn(r, L"Verzeichnis nicht lesbar: " + p.wstring());
    return true;
  }
  while (iterator != end) {
    if (!scan(iterator->path(), r, depth + 1u, entry_count))
      return false;
    iterator.increment(error);
    if (error) {
      ++r.inaccessible_entries;
      warn(r, L"Verzeichnis unvollständig aufgezählt: " + p.wstring());
      break;
    }
  }
  return true;
}
std::wstring bytes(std::uint64_t v){wchar_t b[64]{};const double x=static_cast<double>(v);if(x>=1099511627776.0)swprintf_s(b,L"%.2f TiB",x/1099511627776.0);else if(x>=1073741824.0)swprintf_s(b,L"%.2f GiB",x/1073741824.0);else if(x>=1048576.0)swprintf_s(b,L"%.2f MiB",x/1048576.0);else if(x>=1024.0)swprintf_s(b,L"%.2f KiB",x/1024.0);else swprintf_s(b,L"%llu B",static_cast<unsigned long long>(v));return b;}
}
file_analysis analyzer::analyze(const std::filesystem::path&p)const{file_analysis r;std::size_t entry_count=0;(void)scan(p,r,0,entry_count);return r;} file_analysis analyzer::analyze(const std::vector<std::filesystem::path>&ps)const{file_analysis r;for(const auto&p:ps)merge(r,analyze(p));return r;}
std::wstring format_analysis_report(const file_analysis&r,const storage_info*s){std::wostringstream o;o<<L"OBLIVION ANALYSE\n\nDateien: "<<r.files<<L"\nVerzeichnisse: "<<r.directories<<L"\nLogische Datenmenge: "<<bytes(r.logical_bytes)<<L"\nAlternate Data Streams: "<<r.alternate_streams<<L" ("<<bytes(r.alternate_stream_bytes)<<L")\nReparse Points: "<<r.reparse_points<<L"\nHardlink-Dateien: "<<r.hardlinked_files<<L"\nSparse: "<<r.sparse_files<<L"\nKomprimiert: "<<r.compressed_files<<L"\nEFS: "<<r.encrypted_files<<L"\nRead-only: "<<r.readonly_entries<<L"\nNicht vollständig zugreifbar: "<<r.inaccessible_entries<<L"\n";if(s)o<<L"\nVolume: "<<s->volume_root<<L"\nDateisystem: "<<s->filesystem<<L"\nGerät: "<<s->device_model<<L"\nBus: "<<s->bus_type<<L"\nTRIM: "<<(s->trim_enabled?L"aktiv":L"nicht erkannt")<<L"\nUSN: "<<(s->usn_journal_active?L"aktiv":L"nicht erkannt")<<L"\n";for(const auto&w:r.warnings)o<<L"- "<<w<<L"\n";return o.str();}
}
