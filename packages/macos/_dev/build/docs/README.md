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

### Authentication

{{fields "authentication"}}

### File Read/Write

{{fields "file_read_write"}}

### Network Activity

{{fields "network_activity"}}

### Process Execution Monitoring

{{fields "process_execution_monitoring"}}

### System Change

{{fields "system_change"}}

### User and Account Management

{{fields "user_and_account_management"}}

### Inputs used

These inputs can be used in this integration:

- [Unified Logs](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-unifiedlogs)
