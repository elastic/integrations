## Osquery Saved Queries - Forensic Artifact Coverage

This document tracks the coverage of forensic artifacts in Osquery.

**Last Updated**: 2026-01-19
**Total Core Artifacts**: 16 available + 22 in progress + 6 not available = 44 total variants
**Total Queries**: 41
**Completion Rate**: 36.4% (16/44 core artifacts fully supported)

---

## Coverage Summary

| Status | Count | Percentage |
|--------|-------|------------|
| ✅ Available (Fully Supported) | 16     | 36.4%      |
| ⚠️ In Progress (Needs Validation) | 22    | 50.0%      |
| ❌ Not Available (Requires Extensions) | 6     | 13.6%      |

---

## Core Forensic Artifacts Coverage

| # | Artifact | ✓ | OS | Query | File | Implementation Notes                                                                                                             |
|---|----------|--|----|-------|------|----------------------------------------------------------------------------------------------------------------------------------|
| 1 | AppCompatCache          | ✅ | Win | appcompatcache_shimcache_windows_elastic     | [4a7c](kibana/osquery_saved_query/osquery_manager-4a7c3e8f-9d5b-4c2a-b1e4-7f8a6d3c9e2b.json)    | shimcache table with signature-aware filtering (unsigned/untrusted binaries, suspicious paths), hash enrichment, excludes valid Microsoft-signed binaries                                                                                                                  |
| 2 | AmCache                 | ❌ | Win | -     | -    | Not natively supported — PR #7261 was closed due to lack of a SQL constraint, leading to indeterminate runtime                   |
| 3 | BITS Jobs Database      | ✅ | Win | bits_monitoring_windows_elastic | [4b2e](kibana/osquery_saved_query/osquery_manager-4b2e8f3a-9d5c-4e2a-b8f1-7c6d3e9a2b1f.json) | Not a native table, but can be queried via windows_eventlog (EventID 59)                                                        |
| 4 | Browser URL History     | ⚠️ | Win | -     | -    | No native table. Can be supported via ATC custom tables                                                                          |
| 4a | Browser URL History     | ⚠️ | Linux | -     | -    | No native table. Can be supported via ATC custom tables                                                                          |
| 4b | Browser URL History     | ⚠️ | Mac   | -     | -    | No native table. Can be supported via ATC custom tables                                                                          |
| 5 | File Listing            | ⚠️ | Win   | -     | -    | file and hash tables                                                                                                             |
| 5a | File Listing            | ⚠️ | Linux | -     | -    | file and hash tables                                                                                                             |
| 5b | File Listing            | ⚠️ | Mac   | -     | -    | file and hash tables                                                                                                             |
| 6 | Installed Services      | ⚠️ | Win   | -     | -    | services table                                                                                                                   |
| 6a | Installed Services      | ⚠️ | Linux | -     | -    | systemd table                                                                                                                    |
| 6b | Installed Services      | ⚠️ | Mac   | -     | -    | launchd table                                                                                                                    |
| 7 | Jumplists               | ❌ | Win   | -     | -    | Not natively supported — PR #7260 closed due to OLE format complexity                                                            |
| 8 | LNK files               | ✅ | Win   | lnk_forensics_windows_elastic | [a1b2](kibana/osquery_saved_query/osquery_manager-a1b2c3d4-lnk1-11ef-8f39-bf9c07530bbb.json) | file table with native shortcut parsing; can enrich with hash + authenticode; enumerate common locations via users table |
| 9 | ARP Cache (Enriched)    | ✅ | All   | arp_cache_elastic | [b2c3](kibana/osquery_saved_query/osquery_manager-b2c3d4e5-f6a7-11ef-89c6-331eb0db6d02.json) | Enriched ARP cache with local interface details (local IP, local MAC). Combines arp_cache with interface_details and interface_addresses tables. Includes ECS mappings for destination.ip/mac, source.ip/mac, interface.name, network.type, and MITRE ATT&CK threat enrichment (T1016, T1018) |
| 10 | Disks & Volumes         | ✅ | Win | disk_info_windows_elastic | [d8a1](kibana/osquery_saved_query/osquery_manager-d8a1b2c3-d4e5-11ef-a6b7-12c3d4e5f678.json) | disk_info table                                                                                                                  |
| 10a | Disks & Volumes         | ✅ | Linux | disk_info_linux_macos_elastic | [e9f2](kibana/osquery_saved_query/osquery_manager-e9f2c3d4-e5f6-11ef-b8c9-23d4e5f6a789.json) | block_devices + mounts tables                                                                                                    |
| 10b | Disks & Volumes         | ✅ | Mac | disk_info_linux_macos_elastic | [e9f2](kibana/osquery_saved_query/osquery_manager-e9f2c3d4-e5f6-11ef-b8c9-23d4e5f6a789.json) | block_devices + mounts tables                                                                                                    |
| 11 | Network Interfaces & IP Configuration | ✅ | Win | network_interfaces_windows_elastic | [9307](kibana/osquery_saved_query/osquery_manager-9307c448-d8e2-49a3-aeca-469881183087.json) | interface_details + interface_addresses with DHCP/DNS configuration |
| 11a | Network Interfaces & IP Configuration | ✅ | Linux | network_interfaces_linux_macos_elastic | [c251](kibana/osquery_saved_query/osquery_manager-c251aeb1-698f-44a4-9526-cdd349b9ccbe.json) | interface_details + interface_addresses + interface_ipv6 (hop_limit, forwarding, redirect_accept) |
| 11b | Network Interfaces & IP Configuration | ✅ | Mac | network_interfaces_linux_macos_elastic | [c251](kibana/osquery_saved_query/osquery_manager-c251aeb1-698f-44a4-9526-cdd349b9ccbe.json) | interface_details + interface_addresses + interface_ipv6 (hop_limit, forwarding, redirect_accept) |
| 12 | NTFS USN Journal        | ⚠️ | Win   | -     | -    | ntfs_journal_events table                                                                                                        |
| 13 | Open Handles            | ❌ | Win   | -     | -    | PR #7835 open; external extension available: EclecticIQ ext                                                                      |
| 13a | Open Handles            | ❌ | Linux | -     | -    | PR #7835 open; external extension available: EclecticIQ ext                                                                      |
| 13b | Open Handles            | ❌ | Mac | -     | -    | PR #7835 open; external extension available: EclecticIQ ext                                                                      |
| 14 | Startup Items | ✅ | Win | startup_items_windows_elastic | [d4e5](kibana/osquery_saved_query/osquery_manager-d4e5f6a7-b8c9-12de-f345-678901234567.json) | Dual-detection approach: (1) Non-whitelisted binaries, (2) LotL indicators (PowerShell -e, certutil, wscript abuse). Filters known-good tasks while flagging suspicious patterns. MITRE ATT&CK T1547.001, T1059.001, T1105 |
| 14a | Startup Items | ✅ | Linux | startup_items_linux_elastic | [e5f6](kibana/osquery_saved_query/osquery_manager-e5f6a7b8-c9d0-23ef-4567-890123456789.json) | Dual-detection approach: (1) User-created systemd/cron/XDG autostart, (2) LotL patterns (bash -c, curl pipe bash, base64 -d). Location-based filtering for cross-distro compatibility. MITRE ATT&CK T1543.002, T1053.003, T1547.013, T1059.004, T1105 |
| 14b | Startup Items | ✅ | Mac | startup_items_darwin_elastic | [f6a7](kibana/osquery_saved_query/osquery_manager-f6a7b8c9-d0e1-34f0-5678-901234567890.json) | Dual-detection approach: (1) Non-Apple signed LaunchAgents/Daemons, (2) LotL patterns (bash -c, curl pipe bash, osascript -e). Signature-based filtering with comprehensive LotL coverage. MITRE ATT&CK T1543.001, T1547.015, T1059.004, T1105 |
| 15 | PowerShell History      | ✅ | Win | [a1b2](kibana/osquery_saved_query/osquery_manager-a1b2c3d4-e5f6-11ed-8f39-bf9c07530bbb.json) | powershell_events | Comprehensive PowerShell forensic monitoring (Event IDs 4103, 4104, 4688) for fileless malware detection |
| 16 | Prefetch Files          | ✅ | Win | prefetch_windows_elastic | [c9f4](kibana/osquery_saved_query/osquery_manager-c9f4e1a0-a7e4-11ef-9b3d-94b24cd614c6.json) | Native prefetch table (CORRECTED: parses .pf files to extract executable names, run counts, last run times, and accessed resources - equivalent to VQL Windows.Forensics.Prefetch) |
| 17 | Process Listing         | ⚠️ | Win | -     | -    | processes table                                                                                                                  |
| 17a | Process Listing         | ⚠️ | Linux | -     | -    | processes table                                                                                                                  |
| 17b | Process Listing         | ⚠️ | Mac   | -     | -    | processes table                                                                                                                  |
| 18 | Registry                | ⚠️ | Win   | -     | -    | registry table                                                                                                                   |
| 19 | Shell History           | ✅ | Linux | shell_history_linux_macos_elastic | [8476](kibana/osquery_saved_query/osquery_manager-8476c6fe-9c0b-447b-a334-c5ecc0779d9d.json) | shell_history table with LEFT JOIN for anti-forensics detection (users with no history). MITRE: T1059.004, T1552.003, T1070.003, T1105, T1562.001 |
| 19a | Shell History           | ✅ | Mac | shell_history_linux_macos_elastic | [8476](kibana/osquery_saved_query/osquery_manager-8476c6fe-9c0b-447b-a334-c5ecc0779d9d.json) | shell_history table with LEFT JOIN for anti-forensics detection (users with no history). MITRE: T1059.004, T1552.003, T1070.003, T1105, T1562.001 |
| 20 | Shellbags               | ✅ | Win | shellbags_windows_elastic | [a4b2](kibana/osquery_saved_query/osquery_manager-a4b2c8d0-8876-11f0-b4d1-4f9e8c3a1b2e.json) | shellbags table - tracks directory access via Windows Explorer |
| 21 | Tasks                   | ⚠️ | Win | -     | -    | scheduled_tasks table                                                                                                            |
| 21a | Tasks                   | ⚠️ | Linux | -     | -    | scheduled_tasks table                                                                                                            |
| 21b | Tasks                   | ⚠️ | Mac   | -     | -    | scheduled_tasks table                                                                                                            |
| 22 | User Assist             | ⚠️ | Win   | -     | -    | userassist table                                                                                                                 |
| 23 | WMI Config & Used Apps  | ⚠️ | Win   | -     | -    | wmi_cli_event_consumers, wmi_script_event_consumers                                                                              |
| 24 | WMI Providers & Filters | ⚠️ | Win   | -     | -    | wmi_event_filters, wmi_filter_consumer_binding                                                                                   |
| 25 | MFT                     | ❌ | Win   | -     | -    | Not natively supported. Available via Trail of Bits extension                                                                    |

---

## Additional Queries (Original Repository)

These queries existed in the original repository and provide additional coverage beyond the core forensic artifacts listed above.

| # | Query | ✓ | OS | File | Description |
|:-:|-------|:-:|:--:|:----:|-------------|
| 1 | listening_ports_elastic | ✅ | All | [0796](kibana/osquery_saved_query/osquery_manager-0796f890-b4a9-11ec-8f39-bf9c07530bbb.json) | Network listening ports enumeration |
| 2 | processes_elastic | ✅ | All | [363d](kibana/osquery_saved_query/osquery_manager-363d6a30-b4a9-11ec-8f39-bf9c07530bbb.json) | General process listing (all processes) |
| 3 | logged_in_users_elastic | ✅ | All | [ccd3](kibana/osquery_saved_query/osquery_manager-ccd3f850-b4a5-11ec-8f39-bf9c07530bbb.json) | Currently logged in users |
| 4 | users_elastic | ✅ | All | [cebd](kibana/osquery_saved_query/osquery_manager-cebd7b00-b4b4-11ec-8f39-bf9c07530bbb.json) | System user accounts enumeration |
| 5 | file_info_elastic | ✅ | All | [128b](kibana/osquery_saved_query/osquery_manager-128b90b0-b4a6-11ec-8f39-bf9c07530bbb.json) | File metadata queries by path |
| 6 | file_info_by_type_elastic | ✅ | All | [fc4e](kibana/osquery_saved_query/osquery_manager-fc4e34b0-b4a5-11ec-8f39-bf9c07530bbb.json) | File information by extension type |
| 7 | system_os_elastic | ✅ | All | [23af](kibana/osquery_saved_query/osquery_manager-23af51c0-d75f-11ec-879b-83915b27217e.json) | Operating system information |
| 8 | system_info_elastic | ✅ | All | [47d9](kibana/osquery_saved_query/osquery_manager-47d96fe0-d75f-11ec-879b-83915b27217e.json) | System hardware information |
| 9 | system_memory_linux_elastic | ✅ |Linux | [315b](kibana/osquery_saved_query/osquery_manager-315bfda0-d75f-11ec-879b-83915b27217e.json) | Memory information (Linux specific) |
| 10 | applications_mac_elastic | ✅ | Mac | [5c14](kibana/osquery_saved_query/osquery_manager-5c144ac0-b4a5-11ec-8f39-bf9c07530bbb.json) | Installed applications enumeration |
| 10a | applications_windows_elastic | ✅ | Win | [a887](kibana/osquery_saved_query/osquery_manager-a8870ff0-b4a5-11ec-8f39-bf9c07530bbb.json) | Installed applications enumeration |
| 11 | usb_devices_mac_or_linux_elastic | ✅ | Mac+Linux | [7ee7](kibana/osquery_saved_query/osquery_manager-7ee71870-b4b4-11ec-8f39-bf9c07530bbb.json) | USB device enumeration (non-Windows) |
| 12 | registry_windows_elastic | ✅ | Win | [6fc0](kibana/osquery_saved_query/osquery_manager-6fc00190-b4b4-11ec-8f39-bf9c07530bbb.json) | General registry queries |
| 13 | persisted_apps_elastic | ✅ | Win | [2de2](kibana/osquery_saved_query/osquery_manager-2de24900-b4a9-11ec-8f39-bf9c07530bbb.json) | Persistence applications (non-executables) |
| 14 | persisted_apps_executables_windows_elastic | ✅ | Win | [239d](kibana/osquery_saved_query/osquery_manager-239dce60-b4a9-11ec-8f39-bf9c07530bbb.json) | Persistence applications (executables) |
| 15 | posh_logging_windows_elastic | ✅ | Win | [5595](kibana/osquery_saved_query/osquery_manager-55955db0-0c07-11ed-a49c-6b13b058b135.json) | PowerShell logging configuration status |
| 16 | defender_exclusions_windows_elastic | ✅ | Win | [157d](kibana/osquery_saved_query/osquery_manager-157d5550-fd27-11ec-8645-83a23bc513b5.json) | Windows Defender exclusion paths |
| 17 | firewall_rules_windows_elastic | ✅ | Win | [e640](kibana/osquery_saved_query/osquery_manager-e640e200-b4a8-11ec-8f39-bf9c07530bbb.json) | Windows Firewall rules enumeration |
| 18 | loaded_drivers_windows_elastic | ✅ | Win | [f864](kibana/osquery_saved_query/osquery_manager-f8649710-b4a8-11ec-8f39-bf9c07530bbb.json) | Loaded kernel drivers |
| 19 | services_running_on_user_accounts_windows_elastic | ✅ | Win | [ee58](kibana/osquery_saved_query/osquery_manager-ee586dc0-1801-11ed-89c6-331eb0db6d01.json) | Services running under user accounts (not SYSTEM) |
| 20 | wdigest_uselogoncredential_windows_elastic | ✅ | Win | [a08d](kibana/osquery_saved_query/osquery_manager-a08d7320-1823-11ed-89c6-331eb0db6d01.json) | WDigest credential caching configuration |
| 21 | winbaseobj_mutex_search_windows_elastic | ✅ | Win | [0f61](kibana/osquery_saved_query/osquery_manager-0f61edf0-17e1-11ed-89c6-331eb0db6d01.json) | Mutex objects for malware IOC detection |
| 22 | unsigned_processes_vt_windows_elastic | ✅ | Win | [3e71](kibana/osquery_saved_query/osquery_manager-3e7155d0-0db5-11ed-a49c-6b13b058b135.json) | Unsigned running processes with VirusTotal integration |
| 23 | unsigned_services_vt_windows_elastic | ✅ | Win | [8386](kibana/osquery_saved_query/osquery_manager-83869f40-0dab-11ed-a49c-6b13b058b135.json) | Unsigned services with VirusTotal integration |
| 24 | unsigned_startup_items_vt_windows_elastic | ✅ | Win | [b068](kibana/osquery_saved_query/osquery_manager-b0683c20-0dbb-11ed-a49c-6b13b058b135.json) | Unsigned startup items with VirusTotal integration |
| 25 | unsigned_dlls_on_system_folders_vt_windows_elastic | ✅ | Win | [63c1](kibana/osquery_saved_query/osquery_manager-63c1fe20-176f-11ed-89c6-331eb0db6d01.json) | Unsigned DLLs in system folders with VirusTotal integration |
| 26 | executables_or_drivers_in_temp_folder_vt_windows_elastic | ✅ | Win | [3e55](kibana/osquery_saved_query/osquery_manager-3e553650-17fd-11ed-89c6-331eb0db6d01.json) | Executables/drivers in temp folders with VirusTotal integration |

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
- ✅ AppCompatCache (Windows: shimcache table) - **Production query with signature-aware filtering**
- ✅ PowerShell History (Windows: powershell_events + windows_eventlog)
- ✅ Prefetch Files (Windows: native prefetch table - CORRECTED to use proper parsing, not file enumeration)
- ❌ AmCache (Not Available - Use AppCompatCache + Prefetch as alternatives)

### Persistence Mechanisms
- ✅ Startup Items - Windows (Dual-detection: Non-whitelisted binaries + LotL indicators - T1547.001, T1059.001, T1105)
- ✅ Startup Items - Linux (Dual-detection: User-created systemd/cron/XDG + LotL patterns - T1543.002, T1053.003, T1547.013, T1059.004, T1105)
- ✅ Startup Items - macOS (Dual-detection: Non-Apple signed LaunchAgents/Daemons + LotL patterns - T1543.001, T1547.015, T1059.004, T1105)
- ⚠️ Installed Services (All platforms: services table)
- ⚠️ Registry (Windows: registry table)
- ⚠️ Tasks (All platforms: scheduled_tasks table)
- ⚠️ WMI Config & Used Apps (Windows: wmi_cli_event_consumers, wmi_script_event_consumers)
- ⚠️ WMI Providers & Filters (Windows: wmi_event_filters, wmi_filter_consumer_binding)
- ✅ BITS Jobs Database (Windows: via windows_eventlog)

### User Activity
- ✅ LNK files (Windows: file table with native shortcut parsing using path LIKE pattern for full metadata + hash + authenticode enrichment + 8+ locations via users table)
- ✅ Shell History (Linux/Mac: shell_history table with anti-forensics detection)
- ✅ Shellbags (Windows: shellbags table)
- ⚠️ User Assist (Windows: userassist table)
- ⚠️ Browser URL History (All platforms: via ATC custom tables)
- ❌ Jumplists (Not Available - Use Shellbags + LNK Files as alternatives)

### File System/Forensics
- ⚠️ File Listing (All platforms: file and hash tables)
- ⚠️ NTFS USN Journal (Windows: ntfs_journal_events table)
- ❌ MFT (Not Available - Use NTFS USN Journal as alternative or Trail of Bits extension)

### Network/C2 Indicators
- ✅ ARP Cache (arp_cache + interface_details + interface_addresses tables with joins, includes ECS mappings)
- ✅ Network Interfaces & IP Configuration (Windows: DHCP/DNS config; Linux/macOS: IPv6 config with hop_limit, forwarding, redirect_accept)

### System Information
- ✅ Disks & Volumes (Windows: disk_info table, Linux/macOS: block_devices + mounts tables)
- ⚠️ Process Listing (All platforms: processes table)
- ❌ Open Handles (Not Available - PR #7835 open, EclecticIQ extension available)

---
