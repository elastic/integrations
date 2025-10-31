# macOS Integration for Elastic

## Overview

The macOS integration for Elastic allows you to collect and analyze unified logs from macOS systems. This integration leverages macOS's unified logging system to provide comprehensive visibility into system activities, security events, and application behaviors on macOS endpoints.

macOS unified logging is Apple's centralized logging system that captures log messages from the kernel, system processes, and applications. This integration enables security teams to monitor macOS endpoints for suspicious activities, troubleshoot system issues, and maintain compliance with security policies.

### Compatibility

The macOS integration is compatible with macOS systems that support unified logging (macOS 10.12 Sierra and later).

### How it works

This integration uses the `unifiedlogs` input to collect log data from the macOS unified logging system. It can collect logs in real-time or from archived log files, with configurable filtering based on predicates, processes, and log levels.

## What data does this integration collect?

This integration collects unified log messages from macOS systems using configurable predicates to filter specific event types, including:

- **Authentication logs**: User login/logout events, authentication failures, and credential-related activities
  ```
  - 'process contains "sudo" OR composedMessage CONTAINS "sudo" OR process contains "su"'
  - 'process contains "loginwindow" and composedMessage CONTAINS "sessionDidLogin"'
  - 'process == "sshd"'
  ```
- **User & Account management**: User account creation, modification, and deletion events
  ```
  - 'process == "sysadminctl" AND composedMessage CONTAINS "Creating user"'
  - 'process == "dscl" AND composedMessage CONTAINS "create"'
  - 'process == "sysadminctl" AND composedMessage CONTAINS "Deleting user"'
  - 'process == "dscl" AND composedMessage CONTAINS "delete"'
  - '(process == "dscl" OR process == "opendirectoryd") AND composedMessage CONTAINS "admin"'
  ```
- **Process execution monitoring**: Process creation, termination, and execution details
  ```
  - 'eventMessage CONTAINS[c] "exec" OR eventMessage CONTAINS[c] "fork" OR eventMessage CONTAINS[c] "exited" OR eventMessage CONTAINS[c] "terminated"'
  - 'subsystem == "com.apple.securityd" AND (composedMessage CONTAINS "code signing" OR composedMessage CONTAINS "not valid")'
  - 'composedMessage CONTAINS "com.apple.quarantine"'
  ```
- **Network activity**: Network connections, DNS queries, and network-related events
  ```
  - 'composedMessage CONTAINS "connect" AND (composedMessage CONTAINS "TCP" OR composedMessage CONTAINS "UDP")'
  - 'composedMessage CONTAINS "disconnect" OR composedMessage CONTAINS "closed connection"'
  - 'subsystem == "com.apple.necp" AND composedMessage CONTAINS "new connection"'
  - 'eventMessage CONTAINS[c] "listening" AND eventMessage CONTAINS[c] "service"'
  ```
- **File reads/writes**: File system access, modifications, and permission changes
  ```
  - '(eventMessage CONTAINS "open" OR eventMessage CONTAINS "write" OR eventMessage CONTAINS "unlink" OR eventMessage CONTAINS "rename") AND ((processImagePath BEGINSWITH "/System") OR (processImagePath BEGINSWITH "/bin") OR (processImagePath BEGINSWITH "/sbin") OR (processImagePath BEGINSWITH "/usr" AND NOT processImagePath BEGINSWITH "/usr/local") OR (processImagePath BEGINSWITH "/etc"))'
  - 'subsystem == "com.apple.quarantine" OR eventMessage CONTAINS "com.apple.quarantine"'
  ```
- **System changes**: System configuration changes, software installations, and updates
  ```
  - 'subsystem == "com.apple.security" OR subsystem == "com.apple.systempolicy" OR subsystem == "com.apple.installer" OR process == "Installer" OR process == "softwareupdated" OR eventMessage CONTAINS[c] "removed package" OR eventMessage CONTAINS[c] "forget package"'
  ```
- **Advanced monitoring**: Detailed system and application behavior logs
  ```
  - '(composedMessage CONTAINS ".plist" AND (composedMessage CONTAINS "write" OR composedMessage CONTAINS "modified")) OR (composedMessage CONTAINS ".ssh" AND (composedMessage CONTAINS "write" OR composedMessage CONTAINS "modified")) OR (process == "kernel" AND composedMessage CONTAINS "boot") OR (process == "launchd" AND (composedMessage CONTAINS "started" OR composedMessage CONTAINS "listening")) OR (process == "loginwindow" AND composedMessage CONTAINS "sessionDidLogin") OR (composedMessage CONTAINS "posix_spawn" OR composedMessage CONTAINS "exec") OR (subsystem == "com.apple.securityd" AND (composedMessage CONTAINS "code signing" OR composedMessage CONTAINS "not valid"))'
  ```

### Supported use cases
The macOS integration in Elastic enables comprehensive monitoring and analysis of system activities, network traffic, and application behavior across macOS devices. It supports use cases such as detecting security incidents, tracking network usage, auditing system events, and analyzing performance trends. By collecting and visualizing unified logs, it helps security and IT teams gain real-time visibility, identify anomalies, ensure compliance, and enhance overall endpoint security within macOS environments.

## What do I need to use this integration?

### From Elastic

- Elastic Agent must be installed on the macOS system you want to monitor
- Appropriate permissions to read system logs on the macOS system

### From macOS

The integration requires:

- macOS 10.12 Sierra or later (for unified logging support)
- Appropriate system permissions to access unified logs
- For some log categories, administrative privileges may be required

## How do I deploy this integration?

This integration requires Elastic Agent to be installed on the macOS systems you want to monitor.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

## Setup

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **macOS**.
3. Select the **macOS** integration from the search results.
4. Select **Add macOS** to add the integration.
5. Enable and configure only the collection methods which you will use.

    **Basic Configuration:**
    - Enable the log categories you want to collect:
      - Authentication
      - User & Account management
      - Process execution monitoring
      - Network activity
      - File reads/writes
      - System changes
      - Advanced monitoring

    **Advanced Configuration (Optional):**
    - **Predicate**: Use NSPredicate-based filtering to collect specific log messages
    - **Process**: Specify particular processes to monitor (by PID or name)
    - **Start/End dates**: Define time ranges for historical log collection
    - **Log levels**: Configure which log levels to include (info, debug, backtrace, signpost)
    - **Archive/Trace files**: Specify log archive or trace files to process

6. Select **Save and continue** to save the integration.

### Validation

#### Dashboards populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **macOS**.
3. Select a dashboard for the dataset you are collecting, and verify the dashboard information is populated.

## Performance and scaling

- Unified log collection can generate significant data volume, especially with debug-level logging enabled
- Consider using predicates to filter logs and reduce data volume
- Monitor system performance impact when collecting high-volume log categories

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### ECS field reference

#### Unified logs

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| macos.unified_log.activity_identifier |  | keyword |
| macos.unified_log.backtrace.frames.image.offset |  | keyword |
| macos.unified_log.backtrace.frames.image.uuid |  | keyword |
| macos.unified_log.boot_uuid |  | keyword |
| macos.unified_log.category |  | keyword |
| macos.unified_log.event.message.account_id |  | keyword |
| macos.unified_log.event.message.accurate_ecn_client |  | keyword |
| macos.unified_log.event.message.accurate_ecn_server |  | keyword |
| macos.unified_log.event.message.ack |  | keyword |
| macos.unified_log.event.message.acks_compressed |  | long |
| macos.unified_log.event.message.acks_delayed |  | long |
| macos.unified_log.event.message.alpn |  | keyword |
| macos.unified_log.event.message.attribution |  | keyword |
| macos.unified_log.event.message.base_rtt_ms |  | keyword |
| macos.unified_log.event.message.bundle_id |  | keyword |
| macos.unified_log.event.message.bytes_in |  | long |
| macos.unified_log.event.message.bytes_out |  | long |
| macos.unified_log.event.message.cache_hit |  | boolean |
| macos.unified_log.event.message.cipher_suite |  | keyword |
| macos.unified_log.event.message.client_ip |  | ip |
| macos.unified_log.event.message.client_port |  | long |
| macos.unified_log.event.message.connection |  | long |
| macos.unified_log.event.message.connection_detail |  | keyword |
| macos.unified_log.event.message.connection_duration_ms |  | long |
| macos.unified_log.event.message.connection_id |  | keyword |
| macos.unified_log.event.message.connection_identifier |  | keyword |
| macos.unified_log.event.message.connection_time |  | keyword |
| macos.unified_log.event.message.connection_uuid |  | keyword |
| macos.unified_log.event.message.delayed_acks_sent |  | long |
| macos.unified_log.event.message.description |  | keyword |
| macos.unified_log.event.message.dest_port |  | long |
| macos.unified_log.event.message.direct_logout_type |  | long |
| macos.unified_log.event.message.dns_duration |  | keyword |
| macos.unified_log.event.message.dns_start |  | keyword |
| macos.unified_log.event.message.domain_lookup_duration_ms |  | long |
| macos.unified_log.event.message.duration |  | keyword |
| macos.unified_log.event.message.ecn_acked |  | long |
| macos.unified_log.event.message.ecn_in |  | long |
| macos.unified_log.event.message.ecn_lost |  | long |
| macos.unified_log.event.message.ecn_marked |  | long |
| macos.unified_log.event.message.ecn_miss |  | long |
| macos.unified_log.event.message.ecn_out |  | long |
| macos.unified_log.event.message.ecn_sent |  | long |
| macos.unified_log.event.message.expected_workload |  | keyword |
| macos.unified_log.event.message.false_started |  | boolean |
| macos.unified_log.event.message.flags |  | keyword |
| macos.unified_log.event.message.flight_time |  | keyword |
| macos.unified_log.event.message.group |  | keyword |
| macos.unified_log.event.message.group_id |  | keyword |
| macos.unified_log.event.message.guest_account |  | long |
| macos.unified_log.event.message.home_directory_path |  | keyword |
| macos.unified_log.event.message.hostname |  | keyword |
| macos.unified_log.event.message.hostname_port |  | long |
| macos.unified_log.event.message.init_flag |  | long |
| macos.unified_log.event.message.interface |  | keyword |
| macos.unified_log.event.message.listener |  | boolean |
| macos.unified_log.event.message.mach |  | boolean |
| macos.unified_log.event.message.name |  | keyword |
| macos.unified_log.event.message.ocsp_received |  | boolean |
| macos.unified_log.event.message.offered_ticket |  | boolean |
| macos.unified_log.event.message.out_of_order_bytes |  | long |
| macos.unified_log.event.message.packets_in |  | long |
| macos.unified_log.event.message.packets_out |  | long |
| macos.unified_log.event.message.path_status |  | keyword |
| macos.unified_log.event.message.peer |  | boolean |
| macos.unified_log.event.message.pid |  | long |
| macos.unified_log.event.message.privacy_stance |  | keyword |
| macos.unified_log.event.message.private_relay |  | boolean |
| macos.unified_log.event.message.protocol |  | keyword |
| macos.unified_log.event.message.rd_t_in |  | long |
| macos.unified_log.event.message.rd_t_out |  | long |
| macos.unified_log.event.message.read_stalls |  | long |
| macos.unified_log.event.message.request_bytes |  | long |
| macos.unified_log.event.message.request_duration_ms |  | long |
| macos.unified_log.event.message.request_start_ms |  | long |
| macos.unified_log.event.message.response_bytes |  | long |
| macos.unified_log.event.message.response_duration_ms |  | long |
| macos.unified_log.event.message.response_start_ms |  | long |
| macos.unified_log.event.message.response_status |  | long |
| macos.unified_log.event.message.resumed |  | boolean |
| macos.unified_log.event.message.retransmitted_bytes |  | long |
| macos.unified_log.event.message.rtt |  | keyword |
| macos.unified_log.event.message.rtt_cache |  | keyword |
| macos.unified_log.event.message.rtt_nc_ms |  | keyword |
| macos.unified_log.event.message.rtt_updates |  | long |
| macos.unified_log.event.message.rtt_var_ms |  | keyword |
| macos.unified_log.event.message.rtt_var_nc_ms |  | keyword |
| macos.unified_log.event.message.sct_received |  | boolean |
| macos.unified_log.event.message.secure_connection_duration_ms |  | long |
| macos.unified_log.event.message.seq |  | keyword |
| macos.unified_log.event.message.server_id |  | keyword |
| macos.unified_log.event.message.server_port |  | long |
| macos.unified_log.event.message.session_agent_pid |  | keyword |
| macos.unified_log.event.message.session_uuid |  | keyword |
| macos.unified_log.event.message.signature_alg |  | keyword |
| macos.unified_log.event.message.src_port |  | long |
| macos.unified_log.event.message.state |  | keyword |
| macos.unified_log.event.message.syns |  | long |
| macos.unified_log.event.message.task_uid |  | keyword |
| macos.unified_log.event.message.tcp_duration |  | keyword |
| macos.unified_log.event.message.tcp_start |  | keyword |
| macos.unified_log.event.message.tfo_in |  | long |
| macos.unified_log.event.message.tfo_miss |  | long |
| macos.unified_log.event.message.tfo_out |  | long |
| macos.unified_log.event.message.timestamp_enabled |  | long |
| macos.unified_log.event.message.tls_duration |  | keyword |
| macos.unified_log.event.message.tls_version |  | keyword |
| macos.unified_log.event.message.traffic_class |  | keyword |
| macos.unified_log.event.message.transaction_duration_ms |  | long |
| macos.unified_log.event.message.tso_enabled |  | long |
| macos.unified_log.event.message.url |  | keyword |
| macos.unified_log.event.message.url_hash |  | keyword |
| macos.unified_log.event.message.user.guid |  | keyword |
| macos.unified_log.event.message.user.id |  | keyword |
| macos.unified_log.event.message.user.long_name |  | keyword |
| macos.unified_log.event.message.user.name |  | keyword |
| macos.unified_log.event.message.win |  | keyword |
| macos.unified_log.event.message.wr_t_in |  | long |
| macos.unified_log.event.message.wr_t_out |  | long |
| macos.unified_log.event.message.write_stalls |  | long |
| macos.unified_log.event.type |  | keyword |
| macos.unified_log.format_string |  | keyword |
| macos.unified_log.mach_timestamp |  | double |
| macos.unified_log.message_type |  | keyword |
| macos.unified_log.parent_activity_identifier |  | keyword |
| macos.unified_log.process.id |  | long |
| macos.unified_log.process.image_path |  | keyword |
| macos.unified_log.process.image_uuid |  | keyword |
| macos.unified_log.sender.image_path |  | keyword |
| macos.unified_log.sender.image_uuid |  | keyword |
| macos.unified_log.sender.program_counter |  | long |
| macos.unified_log.source |  | keyword |
| macos.unified_log.subsystem |  | keyword |
| macos.unified_log.thread_id |  | long |
| macos.unified_log.timestamp |  | date |
| macos.unified_log.timezone_name |  | keyword |
| macos.unified_log.trace_id |  | keyword |
| macos.unified_log.user_id |  | keyword |


### Inputs used

These inputs can be used in this integration:

- [Unified Logs](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-unifiedlogs)
