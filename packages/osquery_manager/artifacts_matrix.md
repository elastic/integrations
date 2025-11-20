## Osquery Saved Queries - Forensic Artifact Coverage

This document tracks the coverage of forensic artifacts in Osquery.

**Last Updated**: 2025-11-20
**Total Core Artifacts**: 2 available + 38 in progress + 6 not available = 46 total variants
**Total Queries**: 31 (4 core forensic variants + 27 additional)
**Completion Rate**: 4.3% (2/46 core artifacts fully supported)

---

## Coverage Summary

| Status | Count | Percentage |
|--------|-------|------------|
| ✅ Available (Fully Supported) | 2     | 4.3%       |
| ⚠️ In Progress (Needs Validation) | 38    | 82.6%      |
| ❌ Not Available (Requires Extensions) | 6     | 13.0%      |

---

## Core Forensic Artifacts Coverage

| # | Artifact | ✓ | OS | Query | File | Implementation Notes                                                                                                             |
|---|----------|--|----|-------|------|----------------------------------------------------------------------------------------------------------------------------------|
| 1 | AppCompatCache          | ⚠️ | Win | -     | -    | shimcache table                                                                                                                  |
| 2 | AmCache                 | ❌ | Win | -     | -    | Not natively supported — PR #7261 was closed due to lack of a SQL constraint, leading to indeterminate runtime                   |
| 3 | BITS Jobs Database      | ⚠️ | Win | -     | -    | Not a native table, but can be queried via windows_eventlog                                                                      |
| 4 | Browser URL History     | ⚠️ | Win | -     | -    | No native table. Can be supported via ATC custom tables                                                                          |
| 4a | Browser URL History     | ⚠️ | Linux | -     | -    | No native table. Can be supported via ATC custom tables                                                                          |
| 4b | Browser URL History     | ⚠️ | Mac | -     | -    | No native table. Can be supported via ATC custom tables                                                                          |
| 5 | File Listing            | ⚠️ | Win | -     | -    | file and hash tables                                                                                                             |
| 5a | File Listing            | ⚠️ | Linux | -     | -    | file and hash tables                                                                                                             |
| 5b | File Listing            | ⚠️ | Mac | -     | -    | file and hash tables                                                                                                             |
| 6 | Installed Services      | ⚠️ | Win | -     | -    | services table                                                                                                                   |
| 6a | Installed Services      | ⚠️ | Linux | -     | -    | systemd table                                                                                                                    |
| 6b | Installed Services      | ⚠️ | Mac | -     | -    | launchd table                                                                                                                    |
| 7 | Jumplists               | ❌ | Win | -     | -    | Not natively supported — PR #7260 closed due to OLE format complexity                                                            |
| 8 | LNK files               | ⚠️ | Win | -     | -    | shortcut_files table (deprecated), file table and recent_files table is an alternative (osquery upgrade needed for recent files) |
| 9 | ARP Cache               | ⚠️ | Win | -     | -    | arp_cache table                                                                                                                  |
| 9a | ARP Cache               | ⚠️ | Linux | -     | -    | arp_cache table                                                                                                                  |
| 9b | ARP Cache               | ⚠️ | Mac | -     | -    | arp_cache table                                                                                                                  |
| 10 | Disks & Volumes         | ⚠️ | Win | -     | -    | disk_info table                                                                                                                  |
| 10a | Disks & Volumes         | ⚠️ | Linux | -     | -    | disk_info table                                                                                                                  |
| 10b | Disks & Volumes         | ⚠️ | Mac | -     | -    | disk_info table                                                                                                                  |
| 11 | Network Interfaces & IP Configuration | ⚠️ | Win | -     | -    | interface_details, interface_addresses, interface_ipv6                                                                           |
| 11a | Network Interfaces & IP Configuration | ⚠️ | Linux | -     | -    | interface_details, interface_addresses, interface_ipv6                                                                           |
| 11b | Network Interfaces & IP Configuration | ⚠️ | Mac | -     | -    | interface_details, interface_addresses, interface_ipv6                                                                           |
| 12 | NTFS USN Journal        | ⚠️ | Win | -     | -    | ntfs_journal_events table                                                                                                        |
| 13 | Open Handles            | ❌ | Win | -     | -    | PR #7835 open; external extension available: EclecticIQ ext                                                                      |
| 13a | Open Handles            | ❌ | Linux | -     | -    | PR #7835 open; external extension available: EclecticIQ ext                                                                      |
| 13b | Open Handles            | ❌ | Mac | -     | -    | PR #7835 open; external extension available: EclecticIQ ext                                                                      |
| 14 | Persistence             | ⚠️ | Win | -     | -    | Supported across multiple tables (services, startup_items, scheduled_tasks)                                                      |
| 14a | Persistence             | ⚠️ | Linux | -     | -    | Supported across multiple tables (services, startup_items, scheduled_tasks)                                                      |
| 14b | Persistence             | ⚠️ | Mac | -     | -    | Supported across multiple tables (services, startup_items, scheduled_tasks)                                                      |
| 15 | PowerShell History      | ⚠️ | Win | -     | -    | powershell_events table                                                                                                          |
| 16 | Prefetch Files          | ✅ | Win | prefetch_windows_elastic | [c9f4](kibana/osquery_saved_query/osquery_manager-c9f4e1a0-a7e4-11ef-9b3d-94b24cd614c6.json) | Native prefetch table (CORRECTED: parses .pf files to extract executable names, run counts, last run times, and accessed resources - equivalent to VQL Windows.Forensics.Prefetch) |
| 17 | Process Listing         | ⚠️ | Win | -     | -    | processes table                                                                                                                  |
| 17a | Process Listing         | ⚠️ | Linux | -     | -    | processes table                                                                                                                  |
| 17b | Process Listing         | ⚠️ | Mac | -     | -    | processes table                                                                                                                  |
| 18 | Registry                | ⚠️ | Win | -     | -    | registry table                                                                                                                   |
| 19 | Shell History           | ⚠️ | Linux | -     | -    | shell_history table                                                                                                              |
| 19a | Shell History           | ⚠️ | Mac | -     | -    | shell_history table                                                                                                              |
| 20 | Shellbags               | ⚠️ | Win | -     | -    | shellbags table                                                                                                                  |
| 21 | Tasks                   | ⚠️ | Win | -     | -    | scheduled_tasks table                                                                                                            |
| 21a | Tasks                   | ⚠️ | Linux | -     | -    | scheduled_tasks table                                                                                                            |
| 21b | Tasks                   | ⚠️ | Mac | -     | -    | scheduled_tasks table                                                                                                            |
| 22 | User Assist             | ⚠️ | Win | -     | -    | userassist table                                                                                                                 |
| 23 | WMI Config & Used Apps  | ⚠️ | Win | -     | -    | wmi_cli_event_consumers, wmi_script_event_consumers                                                                              |
| 24 | WMI Providers & Filters | ⚠️ | Win | -     | -    | wmi_event_filters, wmi_filter_consumer_binding                                                                                   |
| 25 | MFT                     | ❌ | Win | -     | -    | Not natively supported. Available via Trail of Bits extension                                                                    |

---

## Additional Queries (Original Repository)

These queries existed in the original repository and provide additional coverage beyond the core forensic artifacts listed above.

| # | Query | ✓ | OS | File | Description |
|:-:|-------|:-:|:--:|:----:|-------------|
| 1 | listening_ports | ✅ | All | [0796](kibana/osquery_saved_query/osquery_manager-0796f890-b4a9-11ec-8f39-bf9c07530bbb.json) | Network listening ports enumeration |
| 2 | processes | ✅ | All | [363d](kibana/osquery_saved_query/osquery_manager-363d6a30-b4a9-11ec-8f39-bf9c07530bbb.json) | General process listing (all processes) |
| 3 | logged_in_users | ✅ | All | [ccd3](kibana/osquery_saved_query/osquery_manager-ccd3f850-b4a5-11ec-8f39-bf9c07530bbb.json) | Currently logged in users |
| 4 | users | ✅ | All | [cebd](kibana/osquery_saved_query/osquery_manager-cebd7b00-b4b4-11ec-8f39-bf9c07530bbb.json) | System user accounts enumeration |
| 5 | file_info | ✅ | All | [128b](kibana/osquery_saved_query/osquery_manager-128b90b0-b4a6-11ec-8f39-bf9c07530bbb.json) | File metadata queries by path |
| 6 | file_info_by_type | ✅ | All | [fc4e](kibana/osquery_saved_query/osquery_manager-fc4e34b0-b4a5-11ec-8f39-bf9c07530bbb.json) | File information by extension type |
| 7 | system_os | ✅ | All | [23af](kibana/osquery_saved_query/osquery_manager-23af51c0-d75f-11ec-879b-83915b27217e.json) | Operating system information |
| 8 | system_info | ✅ | All | [47d9](kibana/osquery_saved_query/osquery_manager-47d96fe0-d75f-11ec-879b-83915b27217e.json) | System hardware information |
| 9 | system_memory_linux | ✅ |Linux | [315b](kibana/osquery_saved_query/osquery_manager-315bfda0-d75f-11ec-879b-83915b27217e.json) | Memory information (Linux specific) |
| 10 | applications_mac | ✅ | Mac | [5c14](kibana/osquery_saved_query/osquery_manager-5c144ac0-b4a5-11ec-8f39-bf9c07530bbb.json) | Installed applications enumeration |
| 10a | applications_windows | ✅ | Win | [a887](kibana/osquery_saved_query/osquery_manager-a8870ff0-b4a5-11ec-8f39-bf9c07530bbb.json) | Installed applications enumeration |
| 11 | usb_devices_mac_or_linux | ✅ | Mac+Linux | [7ee7](kibana/osquery_saved_query/osquery_manager-7ee71870-b4b4-11ec-8f39-bf9c07530bbb.json) | USB device enumeration (non-Windows) |
| 12 | registry_windows | ✅ | Win | [6fc0](kibana/osquery_saved_query/osquery_manager-6fc00190-b4b4-11ec-8f39-bf9c07530bbb.json) | General registry queries |
| 13 | persisted_apps | ✅ | Win | [2de2](kibana/osquery_saved_query/osquery_manager-2de24900-b4a9-11ec-8f39-bf9c07530bbb.json) | Persistence applications (non-executables) |
| 14 | persisted_apps_executables_windows | ✅ | Win | [239d](kibana/osquery_saved_query/osquery_manager-239dce60-b4a9-11ec-8f39-bf9c07530bbb.json) | Persistence applications (executables) |
| 15 | posh_logging_windows | ✅ | Win | [5595](kibana/osquery_saved_query/osquery_manager-55955db0-0c07-11ed-a49c-6b13b058b135.json) | PowerShell logging configuration status |
| 16 | defender_exclusions_windows | ✅ | Win | [157d](kibana/osquery_saved_query/osquery_manager-157d5550-fd27-11ec-8645-83a23bc513b5.json) | Windows Defender exclusion paths |
| 17 | firewall_rules_windows | ✅ | Win | [e640](kibana/osquery_saved_query/osquery_manager-e640e200-b4a8-11ec-8f39-bf9c07530bbb.json) | Windows Firewall rules enumeration |
| 18 | loaded_drivers_windows | ✅ | Win | [f864](kibana/osquery_saved_query/osquery_manager-f8649710-b4a8-11ec-8f39-bf9c07530bbb.json) | Loaded kernel drivers |
| 19 | services_running_on_user_accounts | ✅ | Win | [ee58](kibana/osquery_saved_query/osquery_manager-ee586dc0-1801-11ed-89c6-331eb0db6d01.json) | Services running under user accounts (not SYSTEM) |
| 20 | wdigest_uselogoncredential | ✅ | Win | [a08d](kibana/osquery_saved_query/osquery_manager-a08d7320-1823-11ed-89c6-331eb0db6d01.json) | WDigest credential caching configuration |
| 21 | winbaseobj_mutex_search | ✅ | Win | [0f61](kibana/osquery_saved_query/osquery_manager-0f61edf0-17e1-11ed-89c6-331eb0db6d01.json) | Mutex objects for malware IOC detection |
| 22 | unsigned_processes_vt | ✅ | Win | [3e71](kibana/osquery_saved_query/osquery_manager-3e7155d0-0db5-11ed-a49c-6b13b058b135.json) | Unsigned running processes with VirusTotal integration |
| 23 | unsigned_services_vt | ✅ | Win | [8386](kibana/osquery_saved_query/osquery_manager-83869f40-0dab-11ed-a49c-6b13b058b135.json) | Unsigned services with VirusTotal integration |
| 24 | unsigned_startup_items_vt | ✅ | Win | [b068](kibana/osquery_saved_query/osquery_manager-b0683c20-0dbb-11ed-a49c-6b13b058b135.json) | Unsigned startup items with VirusTotal integration |
| 25 | unsigned_dlls_on_system_folders_vt | ✅ | Win | [63c1](kibana/osquery_saved_query/osquery_manager-63c1fe20-176f-11ed-89c6-331eb0db6d01.json) | Unsigned DLLs in system folders with VirusTotal integration |
| 26 | executables_in_temp_folder_vt | ✅ | Win | [3e55](kibana/osquery_saved_query/osquery_manager-3e553650-17fd-11ed-89c6-331eb0db6d01.json) | Executables/drivers in temp folders with VirusTotal integration |

**Note**: Queries with VirusTotal integration require the VirusTotal extension configured in osquery.

---

## Not Available Artifacts

The following artifacts cannot be queried with standard osquery and require extensions or are not yet supported:

| # | Artifact | Status | Reason | Alternative Approach |
|:-:|----------|:------:|--------|----------------------|
| 1 | AmCache (Windows) | ❌ | PR #7261 closed due to SQL constraint problems, leading to indeterminate runtime | Use combination of Prefetch analysis (prefetch table), AppCompatCache (shimcache table), file system queries for recent executables, and registry uninstall keys |
| 2 | Jumplists (Windows) | ❌ | PR #7260 closed due to OLE format complexity | File enumeration (list .automaticDestinations-ms files), manual offline analysis, or use Recent files from Shellbags (shellbags table) / LNK Files (shortcut_files, recent_files tables) |
| 3 | Open Handles (All Platforms) | ❌ | PR #7835 still open, not merged | Network connections via process_open_sockets, file table for static analysis, or EclecticIQ extension (eclecticiq-osq-ext-bin) |
| 4 | MFT (Windows) | ❌ | Complex NTFS structure requires specialized parsing | Trail of Bits osquery extension (if deployed), NTFS USN Journal (ntfs_journal_events table) for recent activity, or targeted file system queries |

### Partially Available Artifacts

| # | Artifact | Status | Notes |
|:-:|----------|:------:|-------|
| 1 | Browser URL History (All Platforms) | ⚠️ | No native table, databases locked while browser running. Can be supported via ATC custom tables. Alternative: Downloads folder analysis, file system queries for browser cache |
| 2 | BITS Jobs Database (Windows) | ⚠️ | Not a native table, but can be queried via windows_eventlog table |
| 3 | Prefetch Files (Windows) | ✅ | CORRECTED: Native prefetch table available since Osquery v5.x - fully parses .pf files to extract executable names, run counts, last run times, and accessed resources. Equivalent to VQL Windows.Forensics.Prefetch artifact. |

### Alternative Coverage

While some artifacts are not directly available, the existing queries provide strong coverage through related artifacts:

**Execution Tracking**: Use Prefetch (native prefetch table) + AppCompatCache (shimcache) + File Listing + Process Listing instead of AmCache
**User Activity**: Use Shellbags + LNK Files + Recent Files instead of Jumplists/Browser History
**File System Monitoring**: Use NTFS USN Journal + File Listing with Hashes instead of MFT
**Resource Access**: Use Network Connections (process_open_sockets) + Process Listing instead of Open Handles

---

## Legend

### Status Definitions

- ✅ Available in standard osquery with production-ready queries
- ⚠️ In Progress - Query exists but needs validation or refinement
- ❌ Not Available - Requires osquery extensions or not yet supported

---

## Artifacts by Category

### Execution Artifacts
- ⚠️ AppCompatCache (Windows: shimcache table)
- ⚠️ PowerShell History (Windows: powershell_events table)
- ✅ Prefetch Files (Windows: native prefetch table - CORRECTED to use proper parsing, not file enumeration)
- ❌ AmCache (Not Available - Use AppCompatCache + Prefetch as alternatives)

### Persistence Mechanisms
- ⚠️ Installed Services (All platforms: services table)
- ⚠️ Persistence (All platforms: multiple tables)
- ⚠️ Registry (Windows: registry table)
- ⚠️ Tasks (All platforms: scheduled_tasks table)
- ⚠️ WMI Config & Used Apps (Windows: wmi_cli_event_consumers, wmi_script_event_consumers)
- ⚠️ WMI Providers & Filters (Windows: wmi_event_filters, wmi_filter_consumer_binding)
- ⚠️ BITS Jobs Database (Windows: via windows_eventlog)

### User Activity
- ⚠️ LNK files (Windows: shortcut_files, file, recent_files tables)
- ⚠️ Shell History (Linux/Mac: shell_history table)
- ⚠️ Shellbags (Windows: shellbags table)
- ⚠️ User Assist (Windows: userassist table)
- ⚠️ Browser URL History (All platforms: via ATC custom tables)
- ❌ Jumplists (Not Available - Use Shellbags + LNK Files as alternatives)

### File System/Forensics
- ⚠️ File Listing (All platforms: file and hash tables)
- ⚠️ NTFS USN Journal (Windows: ntfs_journal_events table)
- ❌ MFT (Not Available - Use NTFS USN Journal as alternative or Trail of Bits extension)

### Network/C2 Indicators
- ⚠️ ARP Cache (All platforms: arp_cache table)
- ⚠️ Network Interfaces & IP Configuration (All platforms: interface_details, interface_addresses, interface_ipv6)

### System Information
- ⚠️ Disks & Volumes (All platforms: disk_info table)
- ⚠️ Process Listing (All platforms: processes table)
- ❌ Open Handles (Not Available - PR #7835 open, EclecticIQ extension available)

---
