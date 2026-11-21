#pragma once
#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>
namespace oblivion {
enum class erase_mode { fast, standard, strong, dod_5220_22_m, nist_800_88, bsi_gs, gutmann };
enum class hardlink_policy { block, delete_link_only, overwrite_shared_content };
enum class media_kind { unknown, rotational, solid_state };
enum class path_criticality { safe, sensitive, system, critical };
struct erase_options {
    erase_mode mode{erase_mode::standard};
    bool verify{true};
    bool rename_before_delete{true};
    unsigned rename_rounds{3};
    bool erase_alternate_streams{true};
    hardlink_policy hardlinks{hardlink_policy::block};
    std::size_t buffer_size{4u * 1024u * 1024u};
};
struct validation_result { bool allowed{false}; std::wstring reason; std::filesystem::path normalized; path_criticality criticality{path_criticality::safe}; };
struct storage_info {
    media_kind kind{media_kind::unknown}; bool trim_enabled{false}; bool usn_journal_active{false};
    bool shadow_copy_query_succeeded{false}; std::uint32_t shadow_copy_count{0};
    std::uint32_t physical_drive_number{0xFFFFFFFFu};
    std::wstring volume_root, volume_guid, filesystem, device_model, device_serial, bus_type, description;
};
struct file_analysis {
    std::uint64_t files{0}, directories{0}, logical_bytes{0}, alternate_streams{0}, alternate_stream_bytes{0};
    std::uint64_t reparse_points{0}, hardlinked_files{0}, sparse_files{0}, compressed_files{0}, encrypted_files{0};
    std::uint64_t readonly_entries{0}, inaccessible_entries{0};
    std::vector<std::wstring> warnings;
};
struct lock_owner { std::uint32_t process_id{0}; std::wstring application_name, service_name; };
struct progress_info {
    std::filesystem::path current; std::wstring phase, pass_name;
    std::uint32_t pass_index{0}, pass_count{0};
    std::uint64_t completed{0}, total{0}, bytes_written_total{0}, overall_completed{0}, overall_total{0};
};
struct erase_result {
    bool success{false}, cancelled{false}; std::uint32_t win32_error{0};
    std::uint64_t bytes_written{0}, files_deleted{0}, directories_deleted{0}, alternate_streams_overwritten{0}, reparse_points_removed{0}, hardlinks_blocked{0};
    std::wstring message; std::vector<std::wstring> warnings; std::vector<lock_owner> lock_owners;
};
using progress_callback = std::function<bool(const progress_info&)>;
struct operation_audit {
    std::wstring operation_id; std::filesystem::path target; storage_info storage; erase_options options; file_analysis analysis; erase_result result; std::uint64_t duration_ms{0};
};
}
