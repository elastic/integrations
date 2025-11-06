## Osquery Saved Queries - Forensic Artifact Coverage

This document tracks the coverage of forensic artifacts in Osquery.

**Last Updated**: 2025-11-06
**Total Core Artifacts**: 1 completed + 11 in progress + 5 not available = 17 total
**Total Queries**: 45 (18 core forensic variants + 27 additional)
**Completion Rate**: 5.9% (1/17 core artifacts fully validated)

---

## Coverage Summary

| Status | Count | Percentage |
|--------|-------|------------|
| ✅ Completed (Fully Validated) | 1 | 5.9% |
| ⚠️ In Progress (Needs Validation) | 11 | 64.7% |
| ❌ Not Available (Requires Extensions) | 5 | 29.4% |

---

## Core Forensic Artifacts Coverage

| # | Artifact                | ✓ | OS | Query | File | Description |
|:-:|-------------------------|:-:|:--:|-------|:----:|-------------|
| 1 | Services                | ✅ | Win | suspicious_services | [003](kibana/osquery_saved_query/osquery_manager-892ee425-60e7-4eb6-ba25-6e97dc3e2ea0.json) | Detect suspicious services running from user-writable directories or with generic names commonly used by malware |
| 1a | Services                | ✅ | Mac | suspicious_launchd_macos | [043](kibana/osquery_saved_query/osquery_manager-5823a22e-5add-416d-a142-de323400edb0.json) | Detect suspicious launch daemons and agents on macOS, excluding system paths but flagging user-writable directories |
| 1b | Services                | ✅ | Linux | suspicious_systemd_linux | [044](kibana/osquery_saved_query/osquery_manager-f8b0894b-772d-4242-8e19-dbc5d7ae2e06.json) | Detect suspicious systemd units on Linux, excluding system paths but flagging user-writable directories and unusual locations |
| 2 | Scheduled Tasks         | ⚠️ | Win | scheduled_tasks_persistence | - | Identify enabled scheduled tasks executing from suspicious locations or using LOLBins |
| 2a | Scheduled Tasks         | ⚠️ | Mac+Linux | crontab_persistence | - | Detect suspicious crontab entries used for persistence (unified query for both platforms) |
| 3 | Startup Items           | ⚠️ | Win | startup_items_persistence | - | Track startup items from registry and startup folders, focusing on non-Microsoft entries |
| 4 | Process Listing         | ⚠️ | All | suspicious_processes | - | Detect suspicious running processes including fileless malware and processes from temp folders |
| 5 | File Hashes             | ⚠️ | All | file_hashes_threat_intel | - | Enumerate recently modified executables with file hashes from suspicious locations |
| 6 | ARP Cache               | ⚠️ | All | arp_cache_lateral_movement | - | Monitor ARP cache for lateral movement indicators |
| 7 | Network Connections     | ⚠️ | All | network_connections_c2 | - | Identify active network connections to external IPs on common C2 and lateral movement ports |
| 8 | Registry                | ⚠️ | Win | registry_persistence | - | Monitor Windows registry Run keys and startup locations for persistence mechanisms |
| 8a | Startup / Persistence   | ⚠️ | Mac | startup_items_persistence_macos | - | Monitor macOS startup items for persistence mechanisms (equivalent to registry persistence) |
| 8b | Autostart / Persistence | ⚠️ | Linux | autostart_persistence_linux | - | Monitor Linux autostart mechanisms via user systemd units (equivalent to registry persistence) |
| 9 | LNK Files               | ⚠️ | Win | lnk_files_recent_activity | - | Analyze LNK shortcut files showing recently accessed documents and programs |
| 10 | BITS Jobs               | ⚠️ | Win | bits_jobs_database | - | Detect suspicious BITS transfers by filtering out known-good domains (Microsoft, Google, Adobe, etc.) and internal networks - **Windows-only (no macOS/Linux equivalent)** |
| 11 | Network Interfaces      | ⚠️ | All | network_interfaces_baseline | - | Document network configuration and identify anomalies like VPN or tunnel interfaces |
| 12 | Disk Info               | ⚠️ | Win | disk_drives_removable_windows | - | Enumerate logical drives on Windows systems focusing on removable media and unusual volumes (uses logical_drives table) |
| 12a | Disk Info               | ⚠️ | Mac+Linux | mounts_removable | - | Enumerate mounted volumes focusing on removable media and external drives (unified query for both platforms) |
| 13 | AmCache                 | ❌ | Win | - | - | **Not Available** - Alternative: Use Prefetch + File Hashes + Registry uninstall keys |
| 14 | Jumplists               | ❌ | Win | - | - | **Not Available** - Alternative: File enumeration + Shellbags + Office MRU |
| 15 | Browser History         | ❌ | All | - | - | **Not Available** - Alternative: Downloads folder + cache analysis + ATC extension |
| 16 | MFT                     | ❌ | Win | - | - | **Not Available** - Alternative: Trail of Bits extension + USN Journal + targeted queries |
| 17 | File Handles            | ❌ | All | - | - | **Not Available** - Alternative: process_open_sockets + file table + eclecticiq extension |

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
| 1 | AmCache | ❌ | PR #7261 closed due to SQL constraint problems | Use combination of Prefetch analysis, file system queries for recent executables, and registry uninstall keys |
| 2 | Jumplists | ❌ | PR #7260 closed due to OLE format complexity | File enumeration (list .automaticDestinations-ms files), manual offline analysis, or use Recent files from Shellbags/Office MRU |
| 3 | Browser History | ❌ | No native table, databases locked while browser running | Downloads folder analysis, file system queries for browser cache, or ATC custom tables (if deployed) |
| 4 | MFT | ❌ | Complex NTFS structure requires specialized parsing | Trail of Bits osquery extension (if deployed), USN Journal for recent activity, or targeted file system queries |
| 5 | File Handles | ❌ | PR #7835 still open, not merged | Network connections via process_open_sockets, file table for static analysis, or eclecticiq-osq-ext-bin extension |

### Alternative Coverage

While these artifacts are not directly available, the existing queries provide strong coverage through related artifacts:

**Execution Tracking**: Use Prefetch + File Hashes + Process Listing instead of AmCache
**User Activity**: Use Shellbags + LNK Files + Office Documents instead of Jumplists/Browser History
**File System Monitoring**: Use USN Journal + File Hashes instead of MFT
**Resource Access**: Use Network Connections + Process Listing instead of File Handles

---

## Legend

### Status Definitions

- ✅ Available in standard osquery with production-ready queries
- ⚠️ In Progress - Query exists but needs validation or refinement
- ❌ Not Available - Requires osquery extensions or not yet supported

---

## Artifacts by Category

### Persistence Mechanisms
- ✅ Services
- ⚠️ Scheduled Tasks
- ⚠️ Startup Items
- ⚠️ Registry

### Network/C2 Indicators
- ⚠️ BITS Jobs
- ⚠️ ARP Cache
- ⚠️ Network Interfaces
- ⚠️ Network Connections

### File Activity
- ⚠️ File Hashes
- ⚠️ LNK Files
- ❌ Jumplists (Not Available)
- ❌ MFT (Not Available)

### System Information
- ⚠️ Disk Info
- ⚠️ Process Listing
- ❌ File Handles (Not Available)

### Execution Artifacts
- ❌ AmCache (Not Available)

### User Activity
- ❌ Browser History (Not Available)

---
