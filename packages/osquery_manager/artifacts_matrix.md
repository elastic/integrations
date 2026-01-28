## Osquery Saved Queries - Forensic Artifact Coverage

This document tracks the coverage of forensic artifacts in Osquery.

**Last Updated**: 2026-01-28
**Total Core Artifacts**: 48 available + 6 in progress = 54 total variants
**Total Queries**: 71
**Completion Rate**: 88.9% (48/54 core artifacts fully supported)

---

### Metadata conventions (saved query JSON)

The saved queries in `kibana/osquery_saved_query/*.json` are Kibana saved objects. Some fields are used by Kibana, while others are used by Osquery/Fleet.
- **`attributes.platform`**: Target OS. Single platform is one of `windows`, `linux`, `darwin`. Cross-platform uses a comma-separated list (alphabetical, e.g. `darwin,linux,windows`).
- **`coreMigrationVersion`**: Kibana saved object migration version (not the Elastic Agent minimum version). Agent requirements (e.g. “Elastic Agent v9.3.0+”) are documented in the query description and/or implementation notes.
- **`version`**: Kibana saved object version metadata from export; this is not a semantic “query version”.

---

## Coverage Summary

| Status                             | Count | Percentage |
|------------------------------------|-------|------------|
| ✅ Available (Fully Supported)      | 48    | 88.9%      |
| ⚠️ In Progress (Needs Validation)  | 6     | 11.1%      |

---

## Core Forensic Artifacts Coverage

| #   | Artifact                              | ✓ | OS    | Query                                      | File                                                                                             | Implementation Notes                                                                                                                                                                                                                        |
|-----|---------------------------------------|---|-------|--------------------------------------------|--------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1   | AppCompatCache                        | ✅ | Win   | appcompatcache_shimcache_windows_elastic   | [4a7c](kibana/osquery_saved_query/osquery_manager-4a7c3e8f-9d5b-4c2a-b1e4-7f8a6d3c9e2b.json)     | shimcache table with signature-aware filtering (unsigned/untrusted binaries, suspicious paths), hash enrichment, excludes valid Microsoft-signed binaries                                                                                   |
| 2   | AmCache                               | ⚠️ | Win   | -                                          | -                                                                                                | In progress                                                                                                                                                                                                                                 |
| 3   | BITS Jobs Database                    | ✅ | Win   | bits_monitoring_windows_elastic            | [4b2e](kibana/osquery_saved_query/osquery_manager-4b2e8f3a-9d5c-4e2a-b8f1-7c6d3e9a2b1f.json)     | Not a native table, but can be queried via windows_eventlog (EventID 59)                                                                                                                                                                    |
| 4   | Browser URL History Suspicious        | ✅ | All   | browser_history_suspicious_elastic         | [b352f3c9](kibana/osquery_saved_query/osquery_manager-b352f3c9-c630-47ec-83bb-5887fe0bb874.json) | Requires Elastic Agent v9.3.0+. Cross-platform (Windows, macOS, Linux). Multi-browser support (Chrome, Edge, Firefox, Safari). No ATC configuration needed.                                                                                 |
| 4a  | Browser URL History (Full Collection) | ✅ | All   | browser_history_elastic                    | [2a5c0d4a](kibana/osquery_saved_query/osquery_manager-2a5c0d4a-21b8-4a37-8d71-2d5d2c8a0f45.json) | Complete browser history collection for forensic analysis. Requires Elastic Agent v9.3.0+. Discovers Chrome, Edge, Firefox, Safari histories.                                                                                               |
| 5   | File Hash Info                        | ✅ | Win   | file_hash_info_windows_elastic             | [f8e71a30](kibana/osquery_saved_query/osquery_manager-f8e71a30-b621-11ef-9c4a-8b2c7c5a1d3e.json) | Files with hash & authenticode in staging directories (T1036, T1105, T1564.001)                                                                                                                                                             |
| 5a  | File Hash Info                        | ✅ | Linux | file_hash_info_linux_elastic               | [b7d63c50](kibana/osquery_saved_query/osquery_manager-b7d63c50-b623-11ef-9c4a-8b2c7c5a1d40.json) | Files with hash & container/namespace awareness (T1036, T1105, T1565.001)                                                                                                                                                                   |
| 5b  | File Hash Info                        | ✅ | Mac   | file_hash_info_darwin_elastic              | [a3c52b40](kibana/osquery_saved_query/osquery_manager-a3c52b40-b622-11ef-9c4a-8b2c7c5a1d3f.json) | Files with hash & Gatekeeper signature validation (T1036, T1105, T1564.001)                                                                                                                                                                 |
| 6   | Installed Services                    | ✅ | Win   | services_suspicious_windows_elastic        | [892e](kibana/osquery_saved_query/osquery_manager-892ee425-60e7-4eb6-ba25-6e97dc3e2ea0.json)     | Detects suspicious Windows services: unsigned binaries, unusual paths, FailureCommand persistence, ServiceDLL hijacking. Excludes Microsoft-signed services.                                                                                |
| 6a  | Installed Services                    | ✅ | Linux | services_suspicious_linux_elastic          | [f8b0](kibana/osquery_saved_query/osquery_manager-f8b0894b-772d-4242-8e19-dbc5d7ae2e06.json)     | Detects suspicious systemd services in user directories, /tmp, ~/.config/systemd. Hash enrichment and file age tracking.                                                                                                                    |
| 6b  | Installed Services                    | ✅ | Mac   | services_suspicious_darwin_elastic         | [5823](kibana/osquery_saved_query/osquery_manager-5823a22e-5add-416d-a142-de323400edb0.json)     | Detects ALL non-Apple-signed launchd services plus Apple-signed services in suspicious locations (/tmp, /Users, hidden dirs). Derives executable from program or program_arguments. Signature and hash enrichment.                          |
| 7   | Jumplists                             | ⚠️ | Win   | -                                          | -                                                                                                | In progress                                                                                                                                                                                                                                 |
| 8   | LNK files                             | ✅ | Win   | lnk_forensics_windows_elastic              | [a1b2](kibana/osquery_saved_query/osquery_manager-a1b2c3d4-lnk1-11ef-8f39-bf9c07530bbb.json)     | file table with native shortcut parsing; can enrich with hash + authenticode; enumerate common locations via users table                                                                                                                    |
| 9   | ARP Cache (Enriched)                  | ✅ | All   | arp_cache_elastic                          | [b2c3](kibana/osquery_saved_query/osquery_manager-b2c3d4e5-f6a7-11ef-89c6-331eb0db6d02.json)     | Enriched ARP cache with local interface details (local IP, local MAC). Combines arp_cache with interface_details and interface_addresses tables. Includes ECS mappings for destination.ip/mac, source.ip/mac, interface.name, network.type. |
| 10  | Disks & Volumes                       | ✅ | Win   | disk_info_windows_elastic                  | [d8a1](kibana/osquery_saved_query/osquery_manager-d8a1b2c3-d4e5-11ef-a6b7-12c3d4e5f678.json)     | disk_info table                                                                                                                                                                                                                             |
| 10a | Disks & Volumes                       | ✅ | Linux | disk_info_linux_darwin_elastic              | [e9f2](kibana/osquery_saved_query/osquery_manager-e9f2c3d4-e5f6-11ef-b8c9-23d4e5f6a789.json)     | block_devices + mounts tables                                                                                                                                                                                                               |
| 10b | Disks & Volumes                       | ✅ | Mac   | disk_info_linux_darwin_elastic              | [e9f2](kibana/osquery_saved_query/osquery_manager-e9f2c3d4-e5f6-11ef-b8c9-23d4e5f6a789.json)     | block_devices + mounts tables                                                                                                                                                                                                               |
| 11  | Network Interfaces & IP Configuration | ✅ | Win   | network_interfaces_windows_elastic         | [9307](kibana/osquery_saved_query/osquery_manager-9307c448-d8e2-49a3-aeca-469881183087.json)     | interface_details + interface_addresses with DHCP/DNS configuration                                                                                                                                                                         |
| 11a | Network Interfaces & IP Configuration | ✅ | Linux | network_interfaces_linux_darwin_elastic     | [c251](kibana/osquery_saved_query/osquery_manager-c251aeb1-698f-44a4-9526-cdd349b9ccbe.json)     | interface_details + interface_addresses + interface_ipv6 (hop_limit, forwarding, redirect_accept)                                                                                                                                           |
| 11b | Network Interfaces & IP Configuration | ✅ | Mac   | network_interfaces_linux_darwin_elastic     | [c251](kibana/osquery_saved_query/osquery_manager-c251aeb1-698f-44a4-9526-cdd349b9ccbe.json)     | interface_details + interface_addresses + interface_ipv6 (hop_limit, forwarding, redirect_accept)                                                                                                                                           |
| 12  | NTFS USN Journal                      | ✅ | Win   | ntfs_usn_journal_events_windows_elastic    | [e4eb](kibana/osquery_saved_query/osquery_manager-e4ebcc53-fbb9-420a-9418-b8edc1f8f2df.json)     | ntfs_journal_events table. Requires: `enable_ntfs_event_publisher=true`, `disable_events=false`                                                                                                                                             |
| 12a | File System Events                    | ✅ | Linux | file_system_events_linux_elastic           | [521f](kibana/osquery_saved_query/osquery_manager-521f7c0d-7ef4-4ff4-9510-e899bbc1b285.json)     | file_events table (inotify). Includes hashes. Requires: `enable_file_events=true`                                                                                                                                                           |
| 12b | File System Events                    | ✅️ | Mac   | file_system_events_darwin_elastic          | [6954](kibana/osquery_saved_query/osquery_manager-6954690d-32c3-4c50-a973-3fae66114349.json)     | file_events (FSEvents). Includes hashes. Requires: `enable_file_events=true`                                                                                                                                                                |
| 13  | Open Handles                          | ⚠️ | Win   | -                                          | -                                                                                                | In progress                                                                                                                                                                                                                                 | |
| 14  | Startup Items                         | ✅ | Win   | startup_items_windows_elastic              | [d4e5](kibana/osquery_saved_query/osquery_manager-d4e5f6a7-b8c9-12de-f345-678901234567.json)     | Dual-detection approach: (1) Non-whitelisted binaries, (2) LotL indicators (PowerShell -e, certutil, wscript abuse). Filters known-good tasks while flagging suspicious patterns.                                                           |
| 14a | Startup Items                         | ✅ | Linux | startup_items_linux_elastic                | [e5f6](kibana/osquery_saved_query/osquery_manager-e5f6a7b8-c9d0-23ef-4567-890123456789.json)     | Dual-detection approach: (1) User-created systemd/cron/XDG autostart, (2) LotL patterns (bash -c, curl pipe bash, base64 -d). Location-based filtering for cross-distro compatibility.                                                      |
| 14b | Startup Items                         | ✅ | Mac   | startup_items_darwin_elastic               | [f6a7](kibana/osquery_saved_query/osquery_manager-f6a7b8c9-d0e1-34f0-5678-901234567890.json)     | Dual-detection approach: (1) Non-Apple signed LaunchAgents/Daemons, (2) LotL patterns (bash -c, curl pipe bash, osascript -e). Signature-based filtering with comprehensive LotL coverage.                                                  |
| 15  | PowerShell History                    | ✅ | Win   | powershell_history_windows_elastic         | [a1b2](kibana/osquery_saved_query/osquery_manager-a1b2c3d4-e5f6-11ed-8f39-bf9c07530bbb.json)     | powershell_events                                                                                                                                                                                                                           | Comprehensive PowerShell forensic monitoring (Event IDs 4103, 4104, 4688) for fileless malware detection |
| 16  | Prefetch Files                        | ✅ | Win   | prefetch_windows_elastic                   | [c9f4](kibana/osquery_saved_query/osquery_manager-c9f4e1a0-a7e4-11ef-9b3d-94b24cd614c6.json)     | Native prefetch table. Parses .pf files to extract executable names, run counts, last run times, and accessed resources                                                                                                                     |
| 17  | Process Listing                       | ✅ | Win   | process_listing_windows_elastic            | [8be8](kibana/osquery_saved_query/osquery_manager-8be8f7d8-270c-4bf3-bba4-4b99e4c56485.json)     | Full forensic listing + suspicious detection query                                                                                                                                                                                          |
| 17a | Process Listing                       | ✅ | Linux | process_listing_linux_elastic              | [a0c7](kibana/osquery_saved_query/osquery_manager-a0c7b358-f7eb-4bb8-9e08-52bd1afe8987.json)     | Full forensic listing + suspicious detection query                                                                                                                                                                                          |
| 17b | Process Listing                       | ✅ | Mac   | process_listing_darwin_elastic             | [888a](kibana/osquery_saved_query/osquery_manager-888ac365-4095-4de8-9990-41d96a792356.json)     | Full forensic listing + suspicious detection query                                                                                                                                                                                          |
| 17c | Suspicious Processes                  | ✅ | Win   | suspicious_processes_windows_elastic       | [4537](kibana/osquery_saved_query/osquery_manager-45375d5b-c4a6-4cea-8f1b-eb1cbd3c6e9d.json)     | Suspicious process detection: LOLBins, unsigned, unusual paths (MITRE T1059, T1218)                                                                                                                                                         |
| 17d | Suspicious Processes                  | ✅ | Linux | suspicious_processes_linux_elastic         | [4da8](kibana/osquery_saved_query/osquery_manager-4da83919-be77-48df-ad50-4f5b464c2bab.json)     | Suspicious process detection: reverse shells, crypto-miners, container escapes                                                                                                                                                              |
| 17e | Suspicious Processes                  | ✅ | Mac   | suspicious_processes_darwin_elastic        | [2b1b](kibana/osquery_saved_query/osquery_manager-2b1b604c-e355-4e23-b8b4-d014a0aa3197.json)     | Suspicious process detection: unsigned, osascript abuse, quarantine bypass                                                                                                                                                                  |
| 18  | Registry                              | ✅ | Win   | registry_persistence_windows_elastic       | [5dd4](kibana/osquery_saved_query/osquery_manager-5dd4e2a9-eea7-4740-a1ec-1b1b7d120d77.json)     | registry table - Persistence detection covering Run, RunOnce, Policy Run, Winlogon (Shell/Userinit), Active Setup with hash/signature enrichment.                                                                                           |
| 19  | Shell History                         | ✅ | Linux | shell_history_linux_darwin_elastic         | [8476](kibana/osquery_saved_query/osquery_manager-8476c6fe-9c0b-447b-a334-c5ecc0779d9d.json)     | shell_history table with LEFT JOIN for anti-forensics detection (users with no history).                                                                                                                                                    |
| 19a | Shell History                         | ✅ | Mac   | shell_history_linux_darwin_elastic         | [8476](kibana/osquery_saved_query/osquery_manager-8476c6fe-9c0b-447b-a334-c5ecc0779d9d.json)     | shell_history table with LEFT JOIN for anti-forensics detection (users with no history).                                                                                                                                                    |
| 20  | Shellbags                             | ✅ | Win   | shellbags_windows_elastic                  | [a4b2](kibana/osquery_saved_query/osquery_manager-a4b2c8d0-8876-11f0-b4d1-4f9e8c3a1b2e.json)     | shellbags table - tracks directory access via Windows Explorer                                                                                                                                                                              |
| 21  | Scheduled Tasks                       | ✅ | Win   | scheduled_tasks_suspicious_windows_elastic | [265051dd](kibana/osquery_saved_query/osquery_manager-265051dd-bc20-491a-a998-98ebc2f00af7.json) | T1053.005, T1059.001, T1105                                                                                                                                                                                                                 | **Full Coverage Triage** - Detects ALL suspicious Windows scheduled tasks without hash enrichment. Catches tasks even when executable files are orphaned/deleted. Use for initial triage. |
| 21a | Scheduled Tasks                       | ✅ | Win   | scheduled_tasks_enriched_windows_elastic   | [94a743fd](kibana/osquery_saved_query/osquery_manager-94a743fd-5f84-44f3-b38a-2732d8b6f51b.json) | T1053.005, T1059.001, T1105                                                                                                                                                                                                                 | **Deep Investigation** - Enriched analysis with file hash (SHA256/SHA1/MD5) and code signature data. Uses CROSS JOIN for reliable osquery hash/authenticode table enrichment. Only returns tasks with existing executable files. |
| 21b | Scheduled Tasks                       | ✅ | Linux | crontab_linux_elastic                      | [crontab](kibana/osquery_saved_query/osquery_manager-b2c3d4e5-f6a7-8901-bcde-f12345678901.json)  | T1053.003, T1059.004, T1105                                                                                                                                                                                                                 | Detects suspicious Linux cron jobs using system directory filtering and LOTL patterns (curl\|bash, nc -e, base64 -d, etc.). Multi-distro support. |
| 21c | Scheduled Tasks                       | ✅ | Mac   | launchd_darwin_elastic                     | [launchd](kibana/osquery_saved_query/osquery_manager-c3d4e5f6-a7b8-9012-cdef-012345678902.json)  | T1543.001, T1543.004, T1059.004, T1105, T1547.011                                                                                                                                                                                           | Detects suspicious macOS Launch Agents/Daemons using code signature filtering and LOTL patterns (curl, osascript, bash -c, base64 -D, etc.). Filters unsigned/non-Apple signed binaries. |
| 22  | User Assist                           | ✅ | Win   | userassist_windows_elastic                 | [e9e5](kibana/osquery_saved_query/osquery_manager-e9e51a33-b2a2-47b4-a00e-7de8a205d55b.json)     | userassist table with user resolution and hash enrichment                                                                                                                                                                                   |
| 23  | WMI Config & Used Apps                | ✅ | Win   | wmi_persistence_event_subscriptions_windows_elastic | [4003](kibana/osquery_saved_query/osquery_manager-40033716-3580-48fe-a17d-441a838acd8a.json)     | wmi_cli_event_consumers, wmi_script_event_consumers - Combined with #24 into single comprehensive query                                                                                                                                     |
| 24  | WMI Providers & Filters               | ✅ | Win   | wmi_persistence_event_subscriptions_windows_elastic | [4003](kibana/osquery_saved_query/osquery_manager-40033716-3580-48fe-a17d-441a838acd8a.json)     | wmi_event_filters, wmi_filter_consumer_binding - Combined with #23 into single comprehensive query                                                                                                                                          |
| 25  | MFT                                   | ⚠️  | Win   | -                                          | -                                                                                                | In progress                                                                                                                                                                                                                                 |
| 26  | Remote Desktop Protocol               | ✅ | Win   | rdp_authentication_windows_elastic         | [d8d7](kibana/osquery_saved_query/osquery_manager-d8d79510-6f58-44e1-b7fc-63a073158096.json)     | Comprehensive RDP authentication and session lifecycle events via windows_eventlog (Security + TerminalServices + System channels)                                                                                                          |
| 27  | DNS Cache                             | ✅ | Win   | dns_cache_snapshot_windows_elastic         | [ae61](kibana/osquery_saved_query/osquery_manager-ae619588-47a8-4ba8-a378-375244fbef23.json)     | dns_cache table - enumerates cached DNS queries for threat hunting, C2 detection. Filters reverse lookups and AD noise                                                                                                                      |
| 27a | DNS Event Log                         | ✅ | Win   | dns_event_log_windows_elastic              | [66ee](kibana/osquery_saved_query/osquery_manager-66ee8c5f-7030-4641-a14b-f4a45d1edd6a.json)     | windows_eventlog (DNS Client Operational, Event ID 3008) with process context via LEFT JOIN. Requires DNS logging enabled                                                                                                                   |
| 28  | Event Log Cleared                     | ✅ | Win   | event_log_cleared_windows_elastic          | [f2a9](kibana/osquery_saved_query/osquery_manager-f2a9c7d5-e3b1-4f8a-9c2e-6d4b8a1e3f5c.json)     | Defense Evasion: Detects Security/System event log clearing (Event IDs 1102, 104) via windows_eventlog.                                                                                                        |
| 29  | Security Products Disabled            | ✅ | Win   | security_products_disabled_windows_elastic | [a8f3](kibana/osquery_saved_query/osquery_manager-a8f3c5e7-d9b4-4a21-8f6c-2e9d1b3a5c7e.json)     | Defense Evasion: Detects disabled security products (14+ vendors) via services and Windows Defender registry tampering (12 values).                                                                            |

---

## Additional Queries (Original Repository)

These queries existed in the original repository and provide additional coverage beyond the core forensic artifacts
listed above.

|  #  | Query                                                    | ✓ |    OS     |                                             File                                             | Description                                                                                                                                                                                                                                                            |
|:---:|----------------------------------------------------------|:-:|:---------:|:--------------------------------------------------------------------------------------------:|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|  1  | listening_ports_elastic                                  | ✅ |    All    | [0796](kibana/osquery_saved_query/osquery_manager-0796f890-b4a9-11ec-8f39-bf9c07530bbb.json) | Network listening ports enumeration                                                                                                                                                                                                                                    |
|  2  | processes_elastic                                        | ✅ |    All    | [363d](kibana/osquery_saved_query/osquery_manager-363d6a30-b4a9-11ec-8f39-bf9c07530bbb.json) | General process listing (all processes)                                                                                                                                                                                                                                |
|  3  | logged_in_users_elastic                                  | ✅ |    All    | [ccd3](kibana/osquery_saved_query/osquery_manager-ccd3f850-b4a5-11ec-8f39-bf9c07530bbb.json) | Cross-platform logged-in users enumeration with session details (login time, logon type, TTY, remote host, PID). Windows includes SID and registry hive. Use cases: user activity forensics, lateral movement detection (remote sessions), active session enumeration. |
|  4  | users_elastic                                            | ✅ |    All    | [cebd](kibana/osquery_saved_query/osquery_manager-cebd7b00-b4b4-11ec-8f39-bf9c07530bbb.json) | System user accounts enumeration                                                                                                                                                                                                                                       |
|  5  | file_info_elastic                                        | ✅ |    All    | [128b](kibana/osquery_saved_query/osquery_manager-128b90b0-b4a6-11ec-8f39-bf9c07530bbb.json) | File metadata queries by path                                                                                                                                                                                                                                          |
|  6  | file_info_by_type_elastic                                | ✅ |    All    | [fc4e](kibana/osquery_saved_query/osquery_manager-fc4e34b0-b4a5-11ec-8f39-bf9c07530bbb.json) | File information by extension type                                                                                                                                                                                                                                     |
|  7  | system_os_elastic                                        | ✅ |    All    | [23af](kibana/osquery_saved_query/osquery_manager-23af51c0-d75f-11ec-879b-83915b27217e.json) | Operating system information                                                                                                                                                                                                                                           |
|  8  | system_info_elastic                                      | ✅ |    All    | [47d9](kibana/osquery_saved_query/osquery_manager-47d96fe0-d75f-11ec-879b-83915b27217e.json) | System hardware information                                                                                                                                                                                                                                            |
|  9  | system_memory_linux_elastic                              | ✅ |   Linux   | [315b](kibana/osquery_saved_query/osquery_manager-315bfda0-d75f-11ec-879b-83915b27217e.json) | Memory information (Linux specific)                                                                                                                                                                                                                                    |
| 10  | applications_mac_elastic                                 | ✅ |    Mac    | [5c14](kibana/osquery_saved_query/osquery_manager-5c144ac0-b4a5-11ec-8f39-bf9c07530bbb.json) | Installed applications enumeration                                                                                                                                                                                                                                     |
| 10a | applications_windows_elastic                             | ✅ |    Win    | [a887](kibana/osquery_saved_query/osquery_manager-a8870ff0-b4a5-11ec-8f39-bf9c07530bbb.json) | Installed applications enumeration                                                                                                                                                                                                                                     |
| 11  | usb_devices_mac_or_linux_elastic                         | ✅ | Mac+Linux | [7ee7](kibana/osquery_saved_query/osquery_manager-7ee71870-b4b4-11ec-8f39-bf9c07530bbb.json) | USB device enumeration (non-Windows)                                                                                                                                                                                                                                   |
| 12  | registry_windows_elastic                                 | ✅ |    Win    | [6fc0](kibana/osquery_saved_query/osquery_manager-6fc00190-b4b4-11ec-8f39-bf9c07530bbb.json) | General registry queries                                                                                                                                                                                                                                               |
| 13  | persisted_apps_elastic                                   | ✅ |    Win    | [2de2](kibana/osquery_saved_query/osquery_manager-2de24900-b4a9-11ec-8f39-bf9c07530bbb.json) | Persistence applications (non-executables)                                                                                                                                                                                                                             |
| 14  | persisted_apps_executables_windows_elastic               | ✅ |    Win    | [239d](kibana/osquery_saved_query/osquery_manager-239dce60-b4a9-11ec-8f39-bf9c07530bbb.json) | Persistence applications (executables)                                                                                                                                                                                                                                 |
| 15  | posh_logging_windows_elastic                             | ✅ |    Win    | [5595](kibana/osquery_saved_query/osquery_manager-55955db0-0c07-11ed-a49c-6b13b058b135.json) | PowerShell logging configuration status                                                                                                                                                                                                                                |
| 16  | defender_exclusions_windows_elastic                      | ✅ |    Win    | [157d](kibana/osquery_saved_query/osquery_manager-157d5550-fd27-11ec-8645-83a23bc513b5.json) | Windows Defender exclusion paths                                                                                                                                                                                                                                       |
| 17  | firewall_rules_windows_elastic                           | ✅ |    Win    | [e640](kibana/osquery_saved_query/osquery_manager-e640e200-b4a8-11ec-8f39-bf9c07530bbb.json) | Windows Firewall rules enumeration                                                                                                                                                                                                                                     |
| 18  | loaded_drivers_windows_elastic                           | ✅ |    Win    | [f864](kibana/osquery_saved_query/osquery_manager-f8649710-b4a8-11ec-8f39-bf9c07530bbb.json) | Loaded kernel drivers                                                                                                                                                                                                                                                  |
| 19  | services_running_on_user_accounts_windows_elastic        | ✅ |    Win    | [ee58](kibana/osquery_saved_query/osquery_manager-ee586dc0-1801-11ed-89c6-331eb0db6d01.json) | Services running under user accounts (not SYSTEM)                                                                                                                                                                                                                      |
| 20  | wdigest_uselogoncredential_windows_elastic               | ✅ |    Win    | [a08d](kibana/osquery_saved_query/osquery_manager-a08d7320-1823-11ed-89c6-331eb0db6d01.json) | WDigest credential caching configuration                                                                                                                                                                                                                               |
| 21  | winbaseobj_mutex_search_windows_elastic                  | ✅ |    Win    | [0f61](kibana/osquery_saved_query/osquery_manager-0f61edf0-17e1-11ed-89c6-331eb0db6d01.json) | Mutex objects for malware IOC detection                                                                                                                                                                                                                                |
| 22  | unsigned_processes_vt_windows_elastic                    | ✅ |    Win    | [3e71](kibana/osquery_saved_query/osquery_manager-3e7155d0-0db5-11ed-a49c-6b13b058b135.json) | Unsigned running processes with VirusTotal integration                                                                                                                                                                                                                 |
| 23  | unsigned_services_vt_windows_elastic                     | ✅ |    Win    | [8386](kibana/osquery_saved_query/osquery_manager-83869f40-0dab-11ed-a49c-6b13b058b135.json) | Unsigned services with VirusTotal integration                                                                                                                                                                                                                          |
| 24  | unsigned_startup_items_vt_windows_elastic                | ✅ |    Win    | [b068](kibana/osquery_saved_query/osquery_manager-b0683c20-0dbb-11ed-a49c-6b13b058b135.json) | Unsigned startup items with VirusTotal integration                                                                                                                                                                                                                     |
| 25  | unsigned_dlls_on_system_folders_vt_windows_elastic       | ✅ |    Win    | [63c1](kibana/osquery_saved_query/osquery_manager-63c1fe20-176f-11ed-89c6-331eb0db6d01.json) | Unsigned DLLs in system folders with VirusTotal integration                                                                                                                                                                                                            |
| 26  | executables_or_drivers_in_temp_folder_vt_windows_elastic | ✅ |    Win    | [3e55](kibana/osquery_saved_query/osquery_manager-3e553650-17fd-11ed-89c6-331eb0db6d01.json) | Executables/drivers in temp folders with VirusTotal integration                                                                                                                                                                                                        |

**Note**: Queries with VirusTotal integration require the VirusTotal extension configured in osquery.

---

## Legend

### Status Definitions

- ✅ Available in standard osquery with production-ready queries
- ⚠️ In Progress - Query exists but needs validation or refinement
- ❌ Not Available - Requires osquery extensions or not yet supported

---

## Artifacts by Investigative Goal

Queries are organized by investigative goal to support both **scheduled monitoring** and **on-demand forensic execution** via osquery packs.

### Process Execution

- ✅ **Prefetch** (Windows) - Recently executed binaries with run counts and timestamps. Query: `prefetch_windows_elastic`
- ✅ **Shimcache / AppCompatCache** (Windows) - Application compatibility cache with signature-aware filtering. Query: `appcompatcache_shimcache_windows_elastic`
- ✅ **Process Listing** (All) - Full forensic process listing with parent/child relationships. Queries: `process_listing_windows_elastic`, `process_listing_linux_elastic`, `process_listing_darwin_elastic`
- ✅ **Suspicious Processes** (All) - LOLBins, unsigned binaries, unusual paths. Queries: `suspicious_processes_windows_elastic`, `suspicious_processes_linux_elastic`, `suspicious_processes_darwin_elastic`
- ⚠️ **AmCache** - In Progress
- ⚠️ **Jumplists** - In Progress

### Persistence

- ✅ **Services** (All) - Suspicious service detection (unsigned, unusual paths, ServiceDLL hijacking). Queries: `services_suspicious_windows_elastic`, `services_suspicious_linux_elastic`, `services_suspicious_darwin_elastic`
- ✅ **Scheduled Tasks** (All) - Windows scheduled tasks (triage + enriched), Linux cron jobs, macOS launch agents/daemons. Queries: `scheduled_tasks_suspicious_windows_elastic`, `scheduled_tasks_enriched_windows_elastic`, `crontab_linux_elastic`, `launchd_darwin_elastic`
- ✅ **Registry Keys** (Windows) - Persistence detection covering Run, RunOnce, Winlogon, Active Setup with hash/signature enrichment. Query: `registry_persistence_windows_elastic`
- ✅ **Startup Items** (All) - Dual-detection: non-whitelisted binaries + LotL indicators. Queries: `startup_items_windows_elastic`, `startup_items_linux_elastic`, `startup_items_darwin_elastic`
- ✅ **WMI Persistence** (Windows) - Event consumers, filters, and filter-consumer bindings. Query: `wmi_persistence_event_subscriptions_windows_elastic`
- ✅ **BITS Jobs** (Windows) - Background Intelligent Transfer Service monitoring via windows_eventlog. Query: `bits_monitoring_windows_elastic`

### User Activity

- ✅ **PowerShell History** (Windows) - Forensic monitoring (Event IDs 4103, 4104, 4688) for fileless malware detection. Query: `powershell_history_windows_elastic`
- ✅ **Shell History** (Linux/macOS) - Shell history with LEFT JOIN for anti-forensics detection (users with no history). Query: `shell_history_linux_darwin_elastic`
- ✅ **User Assist** (Windows) - UserAssist registry with user resolution and hash enrichment. Query: `userassist_windows_elastic`
- ✅ **Browser History** (All) - Native `elastic_browser_history` table (requires Elastic Agent v9.3.0+). Multi-browser support (Chrome, Edge, Firefox, Safari). Queries: `browser_history_elastic`, `browser_history_suspicious_elastic`
- ✅ **Remote Desktop Sessions** (Windows) - RDP authentication and session lifecycle via windows_eventlog (Security + TerminalServices + System). Query: `rdp_authentication_windows_elastic`
- ✅ **Logon Users** (All) - Cross-platform logged-in users with session details, lateral movement detection. Query: `logged_in_users_elastic`
- ✅ **LNK Files** (Windows) - Shortcut file forensics with hash + authenticode enrichment. Query: `lnk_forensics_windows_elastic`
- ✅ **Shellbags** (Windows) - Directory access tracking via Windows Explorer. Query: `shellbags_windows_elastic`
- ⚠️ **Jumplists** - In progress

### Lateral Movement & C2 Communication

- ✅ **DNS Cache** (Windows) - Cached DNS queries for threat hunting, C2 beacon detection. Query: `dns_cache_snapshot_windows_elastic`
- ✅ **DNS Event Log** (Windows) - DNS Client Operational log with process context (requires DNS logging enabled). Query: `dns_event_log_windows_elastic`
- ✅ **Network Listening Ports** (All) - Network listening ports enumeration. Query: `listening_ports_elastic`
- ✅ **ARP Cache** (All) - Enriched ARP cache with local interface details. Query: `arp_cache_elastic`
- ✅ **Network Interfaces** (All) - Interface details with DHCP/DNS config (Windows), IPv6 config (Linux/macOS). Queries: `network_interfaces_windows_elastic`, `network_interfaces_linux_darwin_elastic`
- ✅ **Remote Desktop Sessions** (Windows) - See User Activity above. Query: `rdp_authentication_windows_elastic`
- ✅ **WMI Execution** (Windows) - See Persistence above. Query: `wmi_persistence_event_subscriptions_windows_elastic`
- ✅ **BITS Transfers** (Windows) - See Persistence above. Query: `bits_monitoring_windows_elastic`

### Credential Access & Privilege Escalation

- ✅ **UAC Bypass Indicators** (Windows) - Covered by suspicious process detection (LOLBins, unsigned binaries in unusual paths). Query: `suspicious_processes_windows_elastic`
- ✅ **Password Dumping Tools** (Windows) - Covered by suspicious process detection (mimikatz, procdump patterns). Query: `suspicious_processes_windows_elastic` — *verify coverage of specific tool signatures*
- ✅ **Logon Users** (All) - See User Activity above. Query: `logged_in_users_elastic`
- ⚠️ **SAM / Security Hive Access** (Windows) - Can be detected via `ntfs_journal_events` filtered by SAM, SYSTEM, SECURITY paths. Partially covered by `ntfs_usn_journal_events_windows_elastic` — *needs dedicated filter or standalone query*
- ⚠️ **Logon Sessions** - `logon_sessions` table not yet covered by a dedicated query

### Malware Execution & Injection

- ✅ **Unsigned Executables & Drivers** (All) - Suspicious process detection + VirusTotal integration. Queries: `suspicious_processes_windows_elastic`, `suspicious_processes_linux_elastic`, `suspicious_processes_darwin_elastic`, `unsigned_processes_vt_windows_elastic`
- ✅ **Code Execution from Non-Standard Paths** (All) - File hash info in staging directories with signature validation. Queries: `file_hash_info_windows_elastic`, `file_hash_info_linux_elastic`, `file_hash_info_darwin_elastic`
- ✅ **Suspicious New Services** (All) - See Persistence above. Queries: `services_suspicious_windows_elastic`, `services_suspicious_linux_elastic`, `services_suspicious_darwin_elastic`
- ⚠️ **Process Injection Attempts** - Requires `process_open_handles` (PR #7835 open) and `process_memory_map`. In Progress

### Data Exfiltration & Collection

- ✅ **Shell / PowerShell History** (All) - See User Activity above. Queries: `powershell_history_windows_elastic`, `shell_history_linux_darwin_elastic`
- ✅ **External Device Usage** (Linux/macOS) - USB device enumeration. Query: `usb_devices_mac_or_linux_elastic`
- ⚠️ **Sensitive Directory Access** - Partially covered by suspicious process queries (processes accessing sensitive paths). *Needs dedicated file access monitoring query*
- ⚠️ **Screenshot Taken** (Windows) - In progress
- ⚠️ **Large File Copies / Archival Tools** - In Progress
- ⚠️ **Disk Events** (Windows) - In progress

### Defense Evasion

- ✅ **Defender Exclusions** (Windows) - Windows Defender exclusion paths. Query: `defender_exclusions_windows_elastic`
- ✅ **Disabled Security Tools** (Windows) - Detects stopped/paused security services across major vendors and Windows Defender registry tampering (12 values). Query: `security_products_disabled_windows_elastic` ([a8f3](kibana/osquery_saved_query/osquery_manager-a8f3c5e7-d9b4-4a21-8f6c-2e9d1b3a5c7e.json)) — MITRE ATT&CK: TA0005, T1562.001
- ✅ **Cleared Event Logs** (Windows) - Detects Security/System event log clearing via Event IDs 1102 and 104 (windows_eventlog). Query: `event_log_cleared_windows_elastic` ([f2a9](kibana/osquery_saved_query/osquery_manager-f2a9c7d5-e3b1-4f8a-9c2e-6d4b8a1e3f5c.json)) — MITRE ATT&CK: TA0005, T1070.001
- ⚠️ **Timestomping Detection** - In Progress

### File System Forensics (Supporting)

These queries provide cross-cutting forensic support used across multiple investigative goals.

- ✅ **NTFS USN Journal** (Windows) - File system change tracking. Query: `ntfs_usn_journal_events_windows_elastic`
- ✅ **File System Events** (Linux/macOS) - Real-time file monitoring via inotify/FSEvents. Queries: `file_system_events_linux_elastic`, `file_system_events_darwin_elastic`
- ✅ **File Hash Info** (All) - File hashing with signature validation. Queries: `file_hash_info_windows_elastic`, `file_hash_info_linux_elastic`, `file_hash_info_darwin_elastic`
- ✅ **Disks & Volumes** (All) - Storage device enumeration. Queries: `disk_info_windows_elastic`, `disk_info_linux_darwin_elastic`
- ⚠️ **MFT** (Windows) - In Progress

### System Information (Supporting)

- ✅ **OS Information** (All) - Query: `system_os_elastic`
- ✅ **System Hardware** (All) - Query: `system_info_elastic`
- ✅ **Memory Information** (Linux) - Query: `system_memory_linux_elastic`
- ✅ **Installed Applications** (Windows/macOS) - Queries: `applications_windows_elastic`, `applications_mac_elastic`
- ✅ **User Accounts** (All) - Query: `users_elastic`
- ✅ **Loaded Drivers** (Windows) - Query: `loaded_drivers_windows_elastic`
- ✅ **Firewall Rules** (Windows) - Query: `firewall_rules_windows_elastic`

---

## Cross-Platform File System Monitoring Reference

This section documents the equivalent file monitoring capabilities across platforms for forensic investigations.

### Platform Comparison Matrix

| Feature                   | Windows (USN Journal) | Linux (inotify)       | macOS (FSEvents)    |
|---------------------------|-----------------------|-----------------------|---------------------|
| **Table**                 | `ntfs_journal_events` | `file_events`         | `file_events`       |
| **File hashes**           | ❌                     | ✅ md5, sha1, sha256   | ✅ md5, sha1, sha256 |
| **Deleted file tracking** | ✅ Excellent           | ⚠️ Limited            | ⚠️ Limited          |
| **Historical events**     | ✅ Journal persists    | ❌ Real-time only      | ❌ Real-time only    |
| **Scale**                 | High                  | Medium (watch limits) | Medium              |
| **Noise level**           | Medium                | Configurable          | Configurable        |

---
