## Osquery Saved Queries - Forensic Artifact Coverage

This document tracks the coverage of forensic artifacts from the Velociraptor to Osquery mapping analysis.

**Last Updated**: 2025-01-30
**Total Core Artifacts**: 26
**Supported**: 21 (80.8%)
**Not Supported**: 5 (19.2%)
**Total Queries**: 57 (30 core forensic + 27 additional)

---

## Core Forensic Artifacts Coverage

| Artifact | Status | Platform | Query ID | File | Description |
|----------|--------|----------|----------|------|-------------|
| AppCompatCache | ✅ Supported | Windows | shimcache_execution_elastic | [001](kibana/osquery_saved_query/osquery_manager-a1b2c3d4-5678-4abc-def0-123456789001.json) | Application compatibility cache showing executed binaries |
| Prefetch | ✅ Supported | Windows | prefetch_execution_elastic | [002](kibana/osquery_saved_query/osquery_manager-a1b2c3d4-5678-4abc-def0-123456789002.json) | Prefetch files tracking application execution with timing |
| Services | ✅ Supported | Windows | suspicious_services_elastic | [003](kibana/osquery_saved_query/osquery_manager-a1b2c3d4-5678-4abc-def0-123456789003.json) | Services running from suspicious locations |
| Scheduled Tasks | ✅ Supported | Windows | scheduled_tasks_persistence_elastic | [004](kibana/osquery_saved_query/osquery_manager-a1b2c3d4-5678-4abc-def0-123456789004.json) | Scheduled tasks for persistence detection |
| Startup Items | ✅ Supported | Windows | startup_items_persistence_elastic | [005](kibana/osquery_saved_query/osquery_manager-a1b2c3d4-5678-4abc-def0-123456789005.json) | Applications configured to run at startup |
| BITS Jobs | ✅ Supported | Windows | bits_transfers_c2_elastic | [018](kibana/osquery_saved_query/osquery_manager-a1b2c3d4-5678-4abc-def0-123456789018.json) | BITS transfers for C2 detection via Event ID 59 |
| ARP Cache | ✅ Supported | Windows, Linux, macOS | arp_cache_lateral_movement_elastic | [009](kibana/osquery_saved_query/osquery_manager-a1b2c3d4-5678-4abc-def0-123456789009.json) | ARP cache for lateral movement detection |
| Network Interfaces | ✅ Supported | Windows, Linux, macOS | network_interfaces_baseline_elastic | [019](kibana/osquery_saved_query/osquery_manager-a1b2c3d4-5678-4abc-def0-123456789019.json) | Network interface configuration baseline |
| PowerShell History | ✅ Supported | Windows | powershell_history_elastic<br>powershell_script_blocks_elastic | [015](kibana/osquery_saved_query/osquery_manager-a1b2c3d4-5678-4abc-def0-123456789015.json)<br>[021](kibana/osquery_saved_query/osquery_manager-a1b2c3d4-5678-4abc-def0-123456789021.json) | PowerShell command history files + Script Block events (Event ID 4104) |
| UserAssist | ✅ Supported | Windows | userassist_execution_elastic | [014](kibana/osquery_saved_query/osquery_manager-a1b2c3d4-5678-4abc-def0-123456789014.json) | Programs executed via Windows Explorer |
| Shellbags | ✅ Supported | Windows | shellbags_folder_access_elastic | [016](kibana/osquery_saved_query/osquery_manager-a1b2c3d4-5678-4abc-def0-123456789016.json) | Folder access patterns including network shares |
| LNK Files | ✅ Supported | Windows | lnk_files_recent_activity_elastic | [017](kibana/osquery_saved_query/osquery_manager-a1b2c3d4-5678-4abc-def0-123456789017.json) | Recently accessed documents and programs via LNK files |
| USN Journal | ✅ Supported | Windows | usn_journal_activity_elastic | [007](kibana/osquery_saved_query/osquery_manager-a1b2c3d4-5678-4abc-def0-123456789007.json) | NTFS journal tracking all file system changes |
| File Hashes | ✅ Supported | Windows, Linux, macOS | file_hashes_threat_intel_elastic | [008](kibana/osquery_saved_query/osquery_manager-a1b2c3d4-5678-4abc-def0-123456789008.json) | File hash enumeration for threat intelligence matching |
| Process Listing | ✅ Supported | Windows, Linux, macOS | suspicious_processes_elastic<br>suspicious_process_cmdlines_elastic | [006](kibana/osquery_saved_query/osquery_manager-a1b2c3d4-5678-4abc-def0-123456789006.json)<br>[027](kibana/osquery_saved_query/osquery_manager-a1b2c3d4-5678-4abc-def0-123456789027.json) | Running processes + suspicious command line patterns (50+ detections) |
| Disk Info | ✅ Supported | Linux, macOS | disk_drives_removable_elastic | [020](kibana/osquery_saved_query/osquery_manager-a1b2c3d4-5678-4abc-def0-123456789020.json) | Storage devices and volumes enumeration (uses mounts table) |
| Disk Info | ✅ Supported | Windows | disk_drives_removable_windows_elastic | [030](kibana/osquery_saved_query/osquery_manager-a1b2c3d4-5678-4abc-def0-123456789030.json) | Storage devices and volumes enumeration (uses logical_drives table) |
| WMI Consumers | ✅ Supported | Windows | wmi_persistence_elastic<br>wmi_event_filters_persistence_elastic | [013](kibana/osquery_saved_query/osquery_manager-a1b2c3d4-5678-4abc-def0-123456789013.json)<br>[023](kibana/osquery_saved_query/osquery_manager-a1b2c3d4-5678-4abc-def0-123456789023.json) | WMI event consumers + event filters for persistence |
| Registry | ✅ Supported | Windows | registry_persistence_elastic<br>autorun_registry_keys_elastic | [012](kibana/osquery_saved_query/osquery_manager-a1b2c3d4-5678-4abc-def0-123456789012.json)<br>[025](kibana/osquery_saved_query/osquery_manager-a1b2c3d4-5678-4abc-def0-123456789025.json) | Registry persistence keys (14 autorun locations) |
| Network Connections | ✅ Supported | Windows, Linux, macOS | network_connections_c2_elastic<br>network_share_connections_elastic | [010](kibana/osquery_saved_query/osquery_manager-a1b2c3d4-5678-4abc-def0-123456789010.json)<br>[026](kibana/osquery_saved_query/osquery_manager-a1b2c3d4-5678-4abc-def0-123456789026.json) | Active network connections for C2 + SMB share monitoring |
| Shell History | ✅ Supported | Linux, macOS | shell_history_suspicious_elastic | [011](kibana/osquery_saved_query/osquery_manager-a1b2c3d4-5678-4abc-def0-123456789011.json) | Bash/Zsh command history with suspicious pattern detection |
| RDP Connections | ✅ Supported | Windows | rdp_connection_events_elastic | [022](kibana/osquery_saved_query/osquery_manager-a1b2c3d4-5678-4abc-def0-123456789022.json) | RDP authentication events (Event ID 4624/4625) for lateral movement |
| USB Devices | ✅ Supported | Windows | usb_device_history_elastic | [024](kibana/osquery_saved_query/osquery_manager-a1b2c3d4-5678-4abc-def0-123456789024.json) | USB device history from USBSTOR registry keys |
| Office Documents | ✅ Supported | Windows | recent_office_documents_elastic | [028](kibana/osquery_saved_query/osquery_manager-a1b2c3d4-5678-4abc-def0-123456789028.json) | Recently accessed Office documents from ComDlg32 registry |
| Event Log Clearing | ✅ Supported | Windows | event_log_clearing_elastic | [029](kibana/osquery_saved_query/osquery_manager-a1b2c3d4-5678-4abc-def0-123456789029.json) | Event log clearing detection (Event ID 1102/104) |
| AmCache | ❌ Not Supported | Windows | - | - | Requires osquery extension (PR #7261 closed) |
| Jumplists | ❌ Not Supported | Windows | - | - | Binary OLE format (PR #7260 closed) |
| Browser History | ❌ Not Supported | Windows, Linux, macOS | - | - | Requires ATC custom tables extension |
| MFT | ❌ Not Supported | Windows | - | - | Requires Trail of Bits extension |
| File Handles | ❌ Not Supported | Windows, Linux, macOS | - | - | Not in core osquery (PR #7835 open) |

---

## Additional Queries (Original Repository)

These queries existed in the original repository and provide additional coverage beyond the core forensic artifacts listed above.

| Query ID | Status | Platform | File | Description |
|----------|--------|----------|------|-------------|
| listening_ports_elastic | ✅ Supported | Windows, Linux, macOS | [0796](kibana/osquery_saved_query/osquery_manager-0796f890-b4a9-11ec-8f39-bf9c07530bbb.json) | Network listening ports enumeration |
| processes_elastic | ✅ Supported | Windows, Linux, macOS | [363d](kibana/osquery_saved_query/osquery_manager-363d6a30-b4a9-11ec-8f39-bf9c07530bbb.json) | General process listing (all processes) |
| logged_in_users_elastic | ✅ Supported | Windows, Linux, macOS | [ccd3](kibana/osquery_saved_query/osquery_manager-ccd3f850-b4a5-11ec-8f39-bf9c07530bbb.json) | Currently logged in users |
| users_elastic | ✅ Supported | Windows, Linux, macOS | [cebd](kibana/osquery_saved_query/osquery_manager-cebd7b00-b4b4-11ec-8f39-bf9c07530bbb.json) | System user accounts enumeration |
| file_info_elastic | ✅ Supported | Windows, Linux, macOS | [128b](kibana/osquery_saved_query/osquery_manager-128b90b0-b4a6-11ec-8f39-bf9c07530bbb.json) | File metadata queries by path |
| file_info_by_type_elastic | ✅ Supported | Windows, Linux, macOS | [fc4e](kibana/osquery_saved_query/osquery_manager-fc4e34b0-b4a5-11ec-8f39-bf9c07530bbb.json) | File information by extension type |
| system_os_elastic | ✅ Supported | Windows, Linux, macOS | [23af](kibana/osquery_saved_query/osquery_manager-23af51c0-d75f-11ec-879b-83915b27217e.json) | Operating system information |
| system_info_elastic | ✅ Supported | Windows, Linux, macOS | [47d9](kibana/osquery_saved_query/osquery_manager-47d96fe0-d75f-11ec-879b-83915b27217e.json) | System hardware information |
| system_memory_linux_elastic | ✅ Supported | Linux | [315b](kibana/osquery_saved_query/osquery_manager-315bfda0-d75f-11ec-879b-83915b27217e.json) | Memory information (Linux specific) |
| applications_mac_elastic | ✅ Supported | macOS | [5c14](kibana/osquery_saved_query/osquery_manager-5c144ac0-b4a5-11ec-8f39-bf9c07530bbb.json) | Installed applications enumeration |
| usb_devices_mac_or_linux_elastic | ✅ Supported | Linux, macOS | [7ee7](kibana/osquery_saved_query/osquery_manager-7ee71870-b4b4-11ec-8f39-bf9c07530bbb.json) | USB device enumeration (non-Windows) |
| registry_windows_elastic | ✅ Supported | Windows | [6fc0](kibana/osquery_saved_query/osquery_manager-6fc00190-b4b4-11ec-8f39-bf9c07530bbb.json) | General registry queries |
| persisted_apps_elastic | ✅ Supported | Windows | [2de2](kibana/osquery_saved_query/osquery_manager-2de24900-b4a9-11ec-8f39-bf9c07530bbb.json) | Persistence applications (non-executables) |
| persisted_apps_executables_windows_elastic | ✅ Supported | Windows | [239d](kibana/osquery_saved_query/osquery_manager-239dce60-b4a9-11ec-8f39-bf9c07530bbb.json) | Persistence applications (executables) |
| posh_logging_windows_elastic | ✅ Supported | Windows | [5595](kibana/osquery_saved_query/osquery_manager-55955db0-0c07-11ed-a49c-6b13b058b135.json) | PowerShell logging configuration status |
| defender_exclusions_windows_elastic | ✅ Supported | Windows | [157d](kibana/osquery_saved_query/osquery_manager-157d5550-fd27-11ec-8645-83a23bc513b5.json) | Windows Defender exclusion paths |
| firewall_rules_windows_elastic | ✅ Supported | Windows | [e640](kibana/osquery_saved_query/osquery_manager-e640e200-b4a8-11ec-8f39-bf9c07530bbb.json) | Windows Firewall rules enumeration |
| loaded_drivers_windows_elastic | ✅ Supported | Windows | [f864](kibana/osquery_saved_query/osquery_manager-f8649710-b4a8-11ec-8f39-bf9c07530bbb.json) | Loaded kernel drivers |
| services_running_on_user_accounts_windows_elastic | ✅ Supported | Windows | [ee58](kibana/osquery_saved_query/osquery_manager-ee586dc0-1801-11ed-89c6-331eb0db6d01.json) | Services running under user accounts (not SYSTEM) |
| wdigest_uselogoncredential_windows_elastic | ✅ Supported | Windows | [a08d](kibana/osquery_saved_query/osquery_manager-a08d7320-1823-11ed-89c6-331eb0db6d01.json) | WDigest credential caching configuration |
| winbaseobj_mutex_search_windows_elastic | ✅ Supported | Windows | [0f61](kibana/osquery_saved_query/osquery_manager-0f61edf0-17e1-11ed-89c6-331eb0db6d01.json) | Mutex objects for malware IOC detection |
| unsigned_processes_vt_windows_elastic | ✅ Supported | Windows | [3e71](kibana/osquery_saved_query/osquery_manager-3e7155d0-0db5-11ed-a49c-6b13b058b135.json) | Unsigned running processes with VirusTotal integration |
| unsigned_services_vt_windows_elastic | ✅ Supported | Windows | [8386](kibana/osquery_saved_query/osquery_manager-83869f40-0dab-11ed-a49c-6b13b058b135.json) | Unsigned services with VirusTotal integration |
| unsigned_startup_items_vt_windows_elastic | ✅ Supported | Windows | [b068](kibana/osquery_saved_query/osquery_manager-b0683c20-0dbb-11ed-a49c-6b13b058b135.json) | Unsigned startup items with VirusTotal integration |
| unsigned_dlls_on_system_folders_vt_windows_elastic | ✅ Supported | Windows | [63c1](kibana/osquery_saved_query/osquery_manager-63c1fe20-176f-11ed-89c6-331eb0db6d01.json) | Unsigned DLLs in system folders with VirusTotal integration |
| executables_or_drivers_in_temp_folder_vt_windows_elastic | ✅ Supported | Windows | [3e55](kibana/osquery_saved_query/osquery_manager-3e553650-17fd-11ed-89c6-331eb0db6d01.json) | Executables/drivers in temp folders with VirusTotal integration |

**Note**: Queries with VirusTotal integration require the VirusTotal extension configured in osquery.

---

## Legend

### Status Definitions

- ✅ **Supported**: Available in standard osquery with production-ready queries
- ❌ **Not Supported**: Requires osquery extensions or not available in core osquery

---

## Artifacts by Category

### Execution Artifacts
- ✅ AppCompatCache (Supported)
- ✅ Prefetch (Supported)
- ✅ UserAssist (Supported)
- ✅ PowerShell History (Supported)
- ✅ Process Listing (Supported)
- ❌ AmCache (Not Supported)

### Persistence Mechanisms
- ✅ Services (Supported)
- ✅ Scheduled Tasks (Supported)
- ✅ Startup Items (Supported)
- ✅ WMI Consumers (Supported)
- ✅ Registry (Supported)

### Network/C2 Indicators
- ✅ BITS Jobs (Supported)
- ✅ ARP Cache (Supported)
- ✅ Network Interfaces (Supported)
- ✅ RDP Connections (Supported)
- ✅ Network Connections (Supported)

### User Activity
- ✅ Shellbags (Supported)
- ✅ Office Documents (Supported)
- ✅ Shell History (Supported)
- ❌ Browser History (Not Supported)

### File Activity
- ✅ USN Journal (Supported)
- ✅ File Hashes (Supported)
- ✅ LNK Files (Supported)
- ❌ Jumplists (Not Supported)
- ❌ MFT (Not Supported)

### System Information
- ✅ Disk Info (Supported)
- ✅ USB Devices (Supported)
- ✅ Event Log Clearing (Supported)
- ❌ File Handles (Not Supported)

---

## Not Available Artifacts - Alternative Approaches

### AmCache
**Issue**: PR #7261 closed due to SQL constraint problems
**Alternative**: Use combination of:
- Prefetch analysis (execution artifacts)
- File system queries (recent executables)
- Registry analysis (uninstall keys)

### Jumplists
**Issue**: PR #7260 closed due to OLE format complexity
**Alternative**:
- File enumeration (list .automaticDestinations-ms files)
- Manual offline analysis with specialized tools
- Recent files from other sources (Shellbags, Office MRU)

### Browser History
**Issue**: No native table, databases locked while browser running
**Alternative**:
- Downloads folder analysis
- File system queries for browser cache locations
- ATC custom tables (if deployed)

### MFT
**Issue**: Complex NTFS structure, requires specialized parsing
**Alternative**:
- Trail of Bits osquery extension (if deployed)
- USN Journal for recent file activity
- File system queries for targeted analysis

### File Handles
**Issue**: PR #7835 still open, not merged
**Alternative**:
- Network connections via process_open_sockets
- File table for static file analysis
- External extension (eclecticiq-osq-ext-bin)

---