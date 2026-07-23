# Nextron THOR Cloud

[Nextron THOR Cloud](https://www.nextron-systems.com/thor-cloud/) is a cloud-based compromise assessment platform that runs the THOR forensic scanner on endpoints through the THOR Cloud Launcher. This integration polls the THOR Cloud API and ingests scan findings into Elastic Security for centralized threat hunting and incident response.

## Agentless Enabled Integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).
Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

## Data streams

The Nextron THOR Cloud integration collects one type of data:

- **Thor Forwarding** — Scan results and findings from the THOR Cloud API, including detected threats, malware signatures, suspicious files, and security events identified during endpoint scans.

## Requirements

### THOR Cloud

- A [THOR Cloud](https://www.nextron-systems.com/thor-cloud/) or [THOR Cloud Lite](https://www.nextron-systems.com/thor-cloud/) account with API access.
- **THOR Cloud Launcher** deployed on at least one endpoint and at least one completed scan before data appears in Elastic.
- Scan reports must be **unencrypted** (`logs_encrypted` must be `false`). This integration does not ingest encrypted THOR reports.
- Scans must include `thor.json` in `available_logs`.
- Supported endpoint platforms: **Windows**, **Linux**, and **macOS**.

### Compatibility

This integration has been tested with:

| Component | Minimum tested version |
| --- | --- |
| THOR Cloud API | v1 (`https://thor-cloud.nextron-services.com/ui/api-documentation`) |
| THOR scanner | 10.7.x |
| THOR JSON log format | v2 (`log_version: v2.0.0`) |

THOR Cloud Lite is supported when scans produce unencrypted `thor.json` logs through the same API.

### Elastic Stack

This integration supports Agentless and Elastic Agent-based data collection.

For agent-based collection, install Elastic Agent using the [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

## How it works

Data flows from endpoints to Elastic as follows:

1. **Endpoint** — THOR Cloud Launcher runs a THOR scan on the endpoint.
2. **THOR Cloud** — Scan results and `thor.json` logs are uploaded and stored.
3. **THOR Cloud API** — The integration polls `/v1/scan/search` and `/v1/scan/log` for new scans.
4. **Elastic Agent (CEL input)** — Retrieves logs over HTTPS and ships raw events.
5. **Elasticsearch data stream** — The `nextron_thor_apt_scanner.thor_forwarding` ingest pipeline normalizes events to ECS.

The integration uses a CEL input to poll the THOR Cloud REST API. It does not require syslog or log file receivers on the Elastic Agent host.

## Setup

### Step 1: Prepare THOR Cloud

1. Log into your [THOR Cloud dashboard](https://thor-cloud.nextron-services.com/).
2. Deploy the **THOR Cloud Launcher** on at least one endpoint (Windows, Linux, or macOS).
3. Run a scan and confirm it completes successfully.
4. In the THOR Cloud dashboard, verify the scan report is **not encrypted** and that `thor.json` is listed in the scan's available logs.
5. Navigate to **General Settings** → **API Key**, click **Generate**, and copy the API key. You will not be able to copy it after this step.
6. Note the **API Endpoint URL** (default: `https://thor-cloud.nextron-services.com/api`).

### Step 2: Add the integration in Elastic

1. In Kibana, navigate to **Management** → **Integrations**.
2. Search for **Nextron THOR Cloud** and add the integration.
3. Configure the required parameters:
   - **API URL**: THOR Cloud API endpoint URL from Step 1
   - **API Key**: API key from Step 1
   - **Initial Interval**: How far back to pull scan logs on first run (default: `24h`)
   - **Interval**: Duration between API requests (default: `5m`)
4. Save and deploy the integration.

### Step 3: Verify data collection

1. In **Discover**, open the `logs-*` data view.
2. Filter documents by `data_stream.dataset : "nextron_thor_apt_scanner.thor_forwarding"`.
3. Confirm events from your completed scan appear within the configured polling interval.
4. If no data appears, check the following:
   - The scan completed with status `successful` or `failed` in THOR Cloud.
   - **`logs_encrypted` is `false`** for the scan. Encrypted reports are skipped by this integration and will not produce events in Elastic.
   - `thor.json` is listed in `available_logs` for the scan.
   - The API key is valid and the **Initial Interval** covers the scan completion time.

**Note:**
- Scan data is fetched incrementally based on `last_launcher_update` and the configured initial interval.
- The integration supports batch processing with configurable batch sizes for optimal performance.

## Exported fields
**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |  |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |  |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |  |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |  |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |  |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |  |
| input.type | Type of filebeat input. | keyword |  |
| log.offset | Log offset. | long |  |
| thor.active | Whether a user account is active. | boolean |  |
| thor.alerts | Number of alerts generated during the THOR scan. | long | counter |
| thor.app.company | Company name from PE file metadata of a WER application. | keyword |  |
| thor.app.created | Creation time of the WER application file. | date |  |
| thor.app.description | File description from PE file metadata of a WER application. | keyword |  |
| thor.app.exists | Whether the WER application file exists on the filesystem. | keyword |  |
| thor.app.first_bytes | First bytes of the WER application file in hexadecimal format. | keyword |  |
| thor.app.imphash | Import hash (imphash) of the WER application PE file. | keyword |  |
| thor.app.internal_name | Internal name from PE file metadata of a WER application. | keyword |  |
| thor.app.legal_copyright | Legal copyright information from PE file metadata of a WER application. | keyword |  |
| thor.app.md5 | MD5 hash of the WER application file. | keyword |  |
| thor.app.original_name | Original filename from PE file metadata of a WER application. | keyword |  |
| thor.app.owner | Owner of the WER application file. | keyword |  |
| thor.app.permissions | File permissions or access control list (ACL) of the WER application. | keyword |  |
| thor.app.product | Product name from PE file metadata of a WER application. | keyword |  |
| thor.app.sha1 | SHA1 hash of the WER application file. | keyword |  |
| thor.app.sha256 | SHA256 hash of the WER application file. | keyword |  |
| thor.app.size | Size of the WER application file in bytes. | long |  |
| thor.app.type | File type classification of the WER application (for example, EXE, DLL). | keyword |  |
| thor.apppath | Application path from a Windows Error Reporting (WER) event. | keyword |  |
| thor.arch | CPU architecture of the scanned system (for example, ARM64, AMD64). | keyword |  |
| thor.archive.accessed | Last access time of the archive file. | date |  |
| thor.archive.created | Creation time of the archive file. | date |  |
| thor.archive.first_bytes | First bytes of the archive file in hexadecimal format. | keyword |  |
| thor.archive.md5 | MD5 hash of the archive file. | keyword |  |
| thor.archive.modified | Modification time of the archive file. | date |  |
| thor.archive.owner | Owner of the archive file. | keyword |  |
| thor.archive.path | Full path to the archive file. | keyword |  |
| thor.archive.permissions | File permissions or access control list (ACL) of the archive file. | keyword |  |
| thor.archive.sha1 | SHA1 hash of the archive file. | keyword |  |
| thor.archive.sha256 | SHA256 hash of the archive file. | keyword |  |
| thor.archive.size | Size of the archive file in bytes. | long |  |
| thor.archive.type | File type classification of the archive (for example, ZIP, RAR). | keyword |  |
| thor.arguments | Command-line arguments for an autostart entry. | keyword |  |
| thor.badpwcount | Number of bad password attempts for a user account. | long |  |
| thor.build_number | Operating system build number. | keyword |  |
| thor.campaign_id | Campaign ID of a THOR scan. | keyword |  |
| thor.caption | Caption or description for a Windows hotfix. | keyword |  |
| thor.command | Command line or executable path associated with a scheduled task, service, or process. | wildcard |  |
| thor.comment | Comment associated with a user account. | keyword |  |
| thor.connection_count | Total number of network connections associated with a process. | long | gauge |
| thor.created | creation time | date |  |
| thor.date | Date of a Windows Error Reporting (WER) event. | date |  |
| thor.description | Description text for a service, file, or other system object. | keyword |  |
| thor.directory | Directory path being analyzed. | keyword |  |
| thor.drive | Drive letter being analyzed. | keyword |  |
| thor.duration | Duration of a THOR scan module execution in seconds. | long |  |
| thor.enabled | Whether a scheduled task or service is enabled. | boolean |  |
| thor.entries | Number of entries in a cache or hive analysis. | long |  |
| thor.entry | Registry entry value or cache entry (e.g., URL in MS Office connection cache). | wildcard |  |
| thor.error | Error message from a Windows Error Reporting (WER) event. | wildcard |  |
| thor.errors | Number of errors encountered during the THOR scan. | float |  |
| thor.event_channel | Windows event log channel name. | keyword |  |
| thor.event_consumer | WMI event consumer configuration or command. | keyword |  |
| thor.event_consumer_name | Name of a WMI event consumer used for persistence. | keyword |  |
| thor.event_filter | WMI event filter query (e.g., WQL SELECT statement). | keyword |  |
| thor.event_filter_name | Name of a WMI event filter used for persistence. | keyword |  |
| thor.event_id | Windows event log event ID. | long |  |
| thor.event_level | Windows event log level (for example, Information, Warning). | keyword |  |
| thor.event_time | Timestamp of a Windows event log entry. | date |  |
| thor.exe | Executable name from a Windows Error Reporting (WER) event. | keyword |  |
| thor.exe_group | Group owner of an executable file (Linux/Unix systems). | keyword |  |
| thor.exe_magic | Detected file type based on magic bytes. | keyword |  |
| thor.exe_mode | File permissions mode of an executable (Linux/Unix systems). | keyword |  |
| thor.exe_owner | Owner of an executable file. | keyword |  |
| thor.exec_flag | Whether the autostart entry is flagged as executable. | boolean |  |
| thor.executable | Path to an executable file. | keyword |  |
| thor.expires | License expiration date. | keyword |  |
| thor.failure_command | Failure recovery command for a Windows service. | wildcard |  |
| thor.fault_in_module | Module where a fault occurred in a Windows Error Reporting (WER) event. | keyword |  |
| thor.file.company | Company name from PE file metadata. | keyword |  |
| thor.file.created | creation time of the file | date |  |
| thor.file.description | File description from PE file metadata. | keyword |  |
| thor.file.exists | Whether the file exists on the filesystem. | keyword |  |
| thor.file.ext | File extension of a detected file. | keyword |  |
| thor.file.first_bytes | First bytes of a file in hexadecimal format, often with ASCII representation. | keyword |  |
| thor.file.imphash | Import hash (imphash) of a PE file, used for malware classification. | keyword |  |
| thor.file.internal_name | Internal name from PE file metadata. | keyword |  |
| thor.file.legal_copyright | Legal copyright information from PE file metadata. | keyword |  |
| thor.file.original_name | Original filename from PE file metadata. | keyword |  |
| thor.file.permissions | File permissions or access control list (ACL) information. | keyword |  |
| thor.file.product | Product name from PE file metadata. | keyword |  |
| thor.file.target | Link target path for shortcut (LNK) files. | keyword |  |
| thor.file.type | File type classification (e.g., EXE, DLL, UNKNOWN, Import). | keyword |  |
| thor.files.accessed | Last access time of a file in a files array. | date |  |
| thor.files.company | Company name from PE file metadata in a files array. | keyword |  |
| thor.files.created | creation time of the file | date |  |
| thor.files.description | File description from PE file metadata in a files array. | keyword |  |
| thor.files.exists | Whether a file exists on the filesystem (e.g., "yes", "no"). | keyword |  |
| thor.files.first_bytes | First bytes of a file in hexadecimal format in a files array. | keyword |  |
| thor.files.group | Group owner of a file in a files array (Linux/Unix systems). | keyword |  |
| thor.files.imphash | Import hash (imphash) of a PE file in a files array. | keyword |  |
| thor.files.internal_name | Internal name from PE file metadata in a files array. | keyword |  |
| thor.files.legal_copyright | Legal copyright information from PE file metadata in a files array. | keyword |  |
| thor.files.md5 | MD5 hash of a file in a files array. | keyword |  |
| thor.files.modified | Modification time of a file in a files array. | date |  |
| thor.files.original_name | Original filename from PE file metadata in a files array. | keyword |  |
| thor.files.owner | Owner of a file in a files array. | keyword |  |
| thor.files.path | Full path to a file in a files array. | keyword |  |
| thor.files.permissions | File permissions of a file in a files array. | keyword |  |
| thor.files.product | Product name from PE file metadata in a files array. | keyword |  |
| thor.files.sha1 | SHA1 hash of a file in a files array. | keyword |  |
| thor.files.sha256 | SHA256 hash of a file in a files array. | keyword |  |
| thor.files.size | Size of a file in bytes in a files array. | long |  |
| thor.files.type | File type classification in a files array (e.g., EXE, Windows At Job). | keyword |  |
| thor.filter_type | Type of WMI event filter (e.g., NTEventLogEventConsumer). | keyword |  |
| thor.full_name | Full name or display name of a user account. | keyword |  |
| thor.groupid | Group ID (GID) of a user account (Linux/Unix systems). | keyword |  |
| thor.hive | Path to a Windows registry hive file being analyzed. | keyword |  |
| thor.home | Home directory path of a user account. | keyword |  |
| thor.hotfix_id | Windows hotfix identifier (for example, KB5066128). | keyword |  |
| thor.image.accessed | access time of the image | date |  |
| thor.image.changed | Change time (ctime) of an image/executable file (Linux/Unix systems). | date |  |
| thor.image.company | Company name from PE file metadata of an image/executable. | keyword |  |
| thor.image.created | creation time of the image | date |  |
| thor.image.description | File description from PE file metadata of an image/executable. | keyword |  |
| thor.image.exists | Whether the image or executable file exists on the filesystem. | keyword |  |
| thor.image.first_bytes | First bytes of an image/executable file in hexadecimal format. | keyword |  |
| thor.image.group | Group owner of an image/executable file (Linux/Unix systems). | keyword |  |
| thor.image.imphash | Import hash (imphash) of an image/executable PE file. | keyword |  |
| thor.image.internal_name | Internal name from PE file metadata of an image/executable. | keyword |  |
| thor.image.legal_copyright | Legal copyright information from PE file metadata of an image/executable. | keyword |  |
| thor.image.md5 | MD5 hash of an image/executable file. | keyword |  |
| thor.image.modified | modification time of the image | date |  |
| thor.image.original_name | Original filename from PE file metadata of an image/executable. | keyword |  |
| thor.image.owner | Owner of an image/executable file. | keyword |  |
| thor.image.path | Full path to an image/executable file. | keyword |  |
| thor.image.permissions | File permissions or access control list (ACL) of an image/executable. | keyword |  |
| thor.image.product | Product name from PE file metadata of an image/executable. | keyword |  |
| thor.image.sha1 | SHA1 hash of an image/executable file. | keyword |  |
| thor.image.sha256 | SHA256 hash of an image/executable file. | keyword |  |
| thor.image.size | Size of an image/executable file in bytes. | long |  |
| thor.image.type | File type classification of an image/executable (e.g., EXE, DLL). | keyword |  |
| thor.image_name | Image or executable name for an autostart entry. | keyword |  |
| thor.image_path | Image path or executable path for a Windows service. | keyword |  |
| thor.installed_by | Account that installed a Windows hotfix. | keyword |  |
| thor.installed_on | Date a Windows hotfix or component was installed. | date |  |
| thor.ip | Local IP address for a process connection event. | ip |  |
| thor.is_admin | Whether the user account has administrator rights. | boolean |  |
| thor.job | Path to a Windows At Job (scheduled task) file. | keyword |  |
| thor.key | Full path to a registry key or WMI binding key. | keyword |  |
| thor.key_name | Name of a registry key or service name. | keyword |  |
| thor.last_logon | Last logon time for a user account. | date |  |
| thor.last_run | Last execution time of a scheduled task. | date |  |
| thor.launch_string | Launch string for an autostart entry. | wildcard |  |
| thor.license | Path to the THOR license file. | keyword |  |
| thor.listen_ports | Network ports on which a process is listening. | keyword |  |
| thor.location | Registry location for an autostart entry. | keyword |  |
| thor.locked | Whether a user account is locked. | boolean |  |
| thor.log_accessed | Last access time of a log file. | date |  |
| thor.log_created | Creation time of a log file. | date |  |
| thor.log_modified | Modification time of a log file. | date |  |
| thor.logontype | Logon type for a scheduled task or service. | keyword |  |
| thor.md5 | MD5 hash of a file at the top level of a THOR event. | keyword |  |
| thor.memory_usage | Memory usage information for a process or system. | keyword |  |
| thor.modified | Modification time of a file, registry key, or other object. | date |  |
| thor.name | Name of a scheduled task, service, or other system object. | keyword |  |
| thor.next_run | Next scheduled execution time of a scheduled task. | date |  |
| thor.no_expire | Whether a user account password is configured to never expire. | boolean |  |
| thor.notices | Number of notices generated during the THOR scan. | float |  |
| thor.num_logons | Number of logons for a user account. | long |  |
| thor.other_domains | Other domains associated with a logged-in user. | keyword |  |
| thor.owner | Owner of a process, file, THOR license or other system object. | keyword |  |
| thor.parent | Path to the parent process executable. | keyword |  |
| thor.pass_age | Password age in days for a user account. | double |  |
| thor.path | Path to a file, scheduled task, or other system object. | keyword |  |
| thor.pid | Process ID (PID) of a running process. | long |  |
| thor.port | Network port associated with a process connection or firewall event. | long |  |
| thor.ppid | Parent process ID (PPID) of a running process. | long |  |
| thor.proc | Processor description for the scanned system. | keyword |  |
| thor.process_name | Name of a running process executable. | keyword |  |
| thor.protocol | Network protocol for a process connection event (e.g., TCP, UDP). | keyword |  |
| thor.reason | Reason for a detection or alert (e.g., "Password is too short", "Port explicitly specified"). | keyword |  |
| thor.reasons.matched.context | Contextual data surrounding a signature match (surrounding bytes or text). | keyword |  |
| thor.reasons.matched.data | Actual data that matched a signature rule (matched string or pattern). | keyword |  |
| thor.reasons.matched.field | Field name that matched in a Sigma or signature rule. | keyword |  |
| thor.reasons.matched.offset | Byte offset within a file where a signature match occurred. | long |  |
| thor.reasons.name | Name or description of a detection reason (e.g., YARA rule name with description). | keyword |  |
| thor.reasons.score | Threat score assigned to a specific detection reason. | long |  |
| thor.reasons.sigclass | Signature class or type (e.g., YARA Rule, Filename IOC, Sigma Rule). | keyword |  |
| thor.reasons.signature.author | Author of a signature rule. | keyword |  |
| thor.reasons.signature.description | Description of a signature or Sigma rule. | keyword |  |
| thor.reasons.signature.falsepositives | Known false positive conditions for a signature rule. | keyword |  |
| thor.reasons.signature.id | Identifier of a signature or Sigma rule. | keyword |  |
| thor.reasons.signature.ref | Reference or source of a signature rule (e.g., threat intelligence feed, research). | keyword |  |
| thor.reasons.signature.ruledate | Date when a signature rule was created or last updated. | date |  |
| thor.reasons.signature.rulename | Name of a signature rule (e.g., YARA rule name). | keyword |  |
| thor.reasons.signature.tags | Tags associated with a signature rule (e.g., MITRE ATT&CK techniques, threat categories). | keyword |  |
| thor.reasons.sigtype | Signature type classification (e.g., internal, custom). | keyword |  |
| thor.ref | Reference identifier for a THOR signature or rule. | keyword |  |
| thor.rip | Remote IP address for an established process connection. | ip |  |
| thor.rport | Remote port for an established process connection. | long |  |
| thor.rule | Identifier or name of a firewall or security rule. | keyword |  |
| thor.rule_name | Display name of a firewall or security rule. | keyword |  |
| thor.run_as_group | Group under which a systemd service runs. | keyword |  |
| thor.run_as_user | User account under which a systemd service runs. | keyword |  |
| thor.runlevel | Run level or privilege level for a scheduled task (e.g., LeastPrivilege). | keyword |  |
| thor.scan_id | Unique identifier for a THOR scan. | keyword |  |
| thor.scanned | Number of event log entries scanned. | long |  |
| thor.scanned_elements | Number of elements scanned with a module. | long | counter |
| thor.scanner | THOR scanner product name from the license file. | keyword |  |
| thor.score | Threat score assigned to a detection (higher scores indicate higher severity). | long |  |
| thor.server | Server or host name for a logged-in user session. | keyword |  |
| thor.service_name | Name or display name of a Windows service. | keyword |  |
| thor.session | Session identifier for a process (e.g., Console, Services) | keyword |  |
| thor.sha1 | SHA1 hash of a file. | keyword |  |
| thor.sha256 | SHA256 hash of a file at the top level of a THOR event. | keyword |  |
| thor.share_name | Name of a network share. | keyword |  |
| thor.shell | Login shell path for a user account (Linux/Unix systems). | keyword |  |
| thor.signature | Signature identifier associated with a detection. | keyword |  |
| thor.start | Start time or start condition for a scheduled task. | date |  |
| thor.start_time | THOR scan start time. | date |  |
| thor.start_type | Startup type of a Windows service (e.g., AUTO_START, MANUAL, DISABLED). | keyword |  |
| thor.starts | License start date. | keyword |  |
| thor.string | String value from a registry or configuration check. | wildcard |  |
| thor.timestamp | Timestamp of a SHIM cache entry. | date |  |
| thor.type | Type classification for a THOR module event (for example, run_key, SIGMA, Server). | keyword |  |
| thor.unit | Name of a systemd unit (Linux systems). | keyword |  |
| thor.unit_group | Group owner of a systemd unit file (Linux systems). | keyword |  |
| thor.unit_mode | File permissions mode of a systemd unit file (Linux systems). | keyword |  |
| thor.unit_owner | Owner of a systemd unit file (Linux systems). | keyword |  |
| thor.unit_path | Path to a systemd unit file (Linux systems). | keyword |  |
| thor.valid | Whether the THOR license is valid. | boolean |  |
| thor.value | Registry or configuration value from a THOR check. | wildcard |  |
| thor.var | Environment variable name from EnvCheck module. | keyword |  |
| thor.version | Operating system or component version string. | keyword |  |
| thor.warnings | Number of warnings generated during the THOR scan. | float |  |


## Example Event

An example event for `thor_forwarding` looks as following:

```json
{
    "@timestamp": "2025-11-10T17:52:49.000Z",
    "agent": {
        "ephemeral_id": "c49e6fe5-4695-4c62-b15a-f3ed2644576e",
        "id": "ca9ab007-37d7-41f4-bd82-73d9b25415a0",
        "name": "elastic-agent-63513",
        "type": "filebeat",
        "version": "9.2.0"
    },
    "data_stream": {
        "dataset": "nextron_thor_apt_scanner.thor_forwarding",
        "namespace": "40187",
        "type": "logs"
    },
    "ecs": {
        "version": "9.4.0"
    },
    "elastic_agent": {
        "id": "ca9ab007-37d7-41f4-bd82-73d9b25415a0",
        "snapshot": false,
        "version": "9.2.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "configuration"
        ],
        "dataset": "nextron_thor_apt_scanner.thor_forwarding",
        "ingested": "2026-07-02T10:45:27Z",
        "kind": "event",
        "module": "AtJobs",
        "type": [
            "info"
        ],
        "version": "v2.0.0"
    },
    "host": {
        "name": "myhostname"
    },
    "input": {
        "type": "cel"
    },
    "log": {
        "level": "Info"
    },
    "message": "At Job detected",
    "related": {
        "hosts": [
            "myhostname"
        ]
    },
    "tags": [
        "forwarded"
    ],
    "thor": {
        "campaign_id": "2b054111-bad7-4bac-a14e-8fa8a88f1111",
        "job": "C:\\Windows\\System32\\Tasks\\Microsoft\\Windows\\Task Manager\\Interactive",
        "scan_id": "S-VavZi0stuDo"
    }
}
```
