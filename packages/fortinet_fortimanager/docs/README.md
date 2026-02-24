# Fortinet FortiManager Logs Integration for Elastic

> **Note**: This AI-assisted guide was validated by our engineers. You may need to adjust the steps to match your environment.

## Overview

The Fortinet FortiManager Logs integration for Elastic enables you to collect and analyze logs from Fortinet FortiManager and FortiAnalyzer instances. This integration provides centralized visibility into your network operations and security events, helping you enhance your management and security posture.

This integration facilitates:
- Centralized security monitoring: Aggregate security events and alerts from multiple instances into your Elastic Stack for comprehensive threat detection, incident response, and forensic analysis.
- Compliance and auditing: Collect detailed system, device management, and logging status logs to meet regulatory compliance requirements and perform security audits.
- Operational visibility: Monitor administrative actions, configuration changes, firmware updates, and device management events across the Fortinet Security Fabric to maintain operational awareness and troubleshoot issues.
- Log management and archiving: Centralize logs for long-term storage, enabling historical analysis and ensuring log availability beyond local storage capabilities.

### Compatibility

This integration is compatible with Fortinet FortiManager and FortiAnalyzer versions 7.2.2 and expected to work in versions above. It has been specifically tested against version 7.2.2.

**NOTE**: As per the log availability, we are only supporting the event subtypes given in above table. For more details, look into [Log Reference](https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/5a0d548a-12b0-11ed-9eba-fa163e15d75b/FortiManager_%26_FortiAnalyzer_7.2.1_Log_Reference.pdf).

### How it works

The integration collects logs from your Fortinet devices through several methods. You can configure it to receive syslog data directly over TCP or UDP ports, or use the `filestream` input to read logs from active files. The integration parses these logs from the syslog format into structured events, covering various subtypes like System Manager (`system`), Device Manager (`devmgr`), Object Changes (`objcfg`), and Firmware Manager (`fmwmgr`). Once parsed, the Elastic Agent sends the data to your Elastic deployment where you can monitor and analyze it.

## What data does this integration collect?

The Fortinet FortiManager Logs integration collects log messages pushed using `tcp` or `udp`, or read from active log files using the `filestream` input. The integration parses Syslog-formatted data from the following functional areas:

| FortiManager                                   | FortiAnalyzer                  |
| -----------------------------------------------| -------------------------------|
| System Manager (system)                        | Log Files (logfile)            |
| FortiGuard Service (fgd)                       | Logging Status (logging)       |
| Security Console (scply)                       | Logging Device (logdev)        |
| Firmware Manager (fmwmgr)                      | Logging Database (logdb)       |
| Log Daemon (logd)                              | FortiAnalyzer System (fazsys)  |
| Debug IO Log (iolog)                           | Reports (report)               |
| FortiGate-FortiManager Protocol (fgfm)         |                                |
| Device Manager (devmgr/dvm)                    |                                |
| Deployment Manager (dm)                        |                                |
| Object Changes (objcfg)                        |                                |
| Script Manager (scrmgr)                        |                                |

### Supported use cases

Integrating Fortinet FortiManager logs with the Elastic Stack provides you with deep visibility into your network management infrastructure. You can use this integration for the following use cases:
*   Audit administrative changes: You'll have a clear record of which administrator changed a configuration object and when, which is essential for troubleshooting and regulatory compliance.
*   Monitor deployment health: You can track the success or failure of policy deployments across your entire network, allowing you to catch errors before they affect traffic.
*   Troubleshoot device connectivity: By monitoring the `fgfm` logs, you'll quickly identify and resolve issues with managed FortiGate devices losing connection to the FortiManager.
*   Centralized security logging: You can correlate management events with security events from other parts of your infrastructure within Elastic SIEM to build a complete picture of your security posture.

## What do I need to use this integration?

To get started with the Fortinet FortiManager integration, you'll need the following:

- Administrative access to the FortiManager or FortiAnalyzer device to configure log forwarding settings through both the web-based GUI and the command-line interface (CLI).
- Network connectivity between the FortiManager/FortiAnalyzer device and the Elastic Agent's host. You'll need to allow traffic on the specific syslog port, such as `514` or `9022` (TCP or UDP), in any intervening firewalls.
- The Elastic Agent's IP address or fully qualified domain name and the specific TCP or UDP port number it's configured to listen on for incoming syslog messages.
- Elastic Stack version `8.11.0` or newer.
- An installed and enrolled Elastic Agent running on a host machine that's network-accessible from your FortiManager/FortiAnalyzer devices.
- Network connectivity between the Elastic Agent and your Elasticsearch cluster to successfully send collected data for indexing and analysis.
- Sufficient system resources (CPU, memory, and disk I/O) on the host running the Elastic Agent to process and forward the anticipated volume of logs.
- Appropriate read permissions for the Elastic Agent to access the FortiManager/FortiAnalyzer log files if you use the `filestream` input method for logs stored locally or on an accessible network-mounted filesystem.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed on a host that has network access to your Fortinet FortiManager instance or access to its log files. For detailed installation instructions, refer to the Elastic Agent [installation guide](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the syslog or log file receiver and ship the data to Elastic, where the events will be processed using the integration's ingest pipelines.

### Set up steps in Fortinet FortiManager

#### Part 1: Add the Elastic Agent as a syslog server (GUI)

This step registers the Elastic Agent as a valid log destination in the FortiManager web interface.

1.  Log in to the FortiManager web UI using your administrative credentials.
2.  Navigate to **System Settings > Advanced > Syslog Server**. In some older versions, this option may be found under **System Settings > Syslog Server**.
3.  In the Syslog Server pane, click **Create New** to add a new syslog server entry.
4.  Configure the syslog server with the following settings:
    *   **Name**: Provide a descriptive name for the server, for example, `elastic-agent-syslog`.
    *   **IP address (or FQDN)**: Enter the IP address or fully qualified domain name of the server where the Elastic Agent is running and listening for logs.
    *   **Syslog Server Port**: Enter the port number that the Elastic Agent is configured to listen on. The standard default syslog port is `514`, but `9022` is a common alternative.
    *   **Reliable Connection**:
        *   To send logs using **UDP** (the default syslog protocol), leave this option disabled.
        *   To send logs using **TCP** (for guaranteed delivery), enable this option. This setting **must** match the protocol configured in the Elastic Agent integration.
5.  Click **OK** to save the syslog server configuration.

#### Part 2: Enable log forwarding to the syslog server (CLI)

This step activates the sending of logs to the server you previously configured. This can only be done using the CLI.

1.  Open the FortiManager CLI console. You can typically access this from the top-right corner of the FortiManager web GUI or using SSH.
2.  Enter the following commands to configure the local log syslog daemon settings:
    ```bash
    config system locallog syslogd setting
    ```
3.  Set the syslog server name to the one you created in Part 1 of the GUI steps:
    ```bash
    set syslog-name "elastic-agent-syslog"
    ```
4.  Set the minimum severity level of logs to be sent. To ensure all relevant logs are forwarded, it's recommended to set this to `information`:
    ```bash
    set severity information
    ```
5.  Enable the syslog service to start forwarding logs:
    ```bash
    set status enable
    ```
6.  Apply the configuration changes:
    ```bash
    end
    ```
7.  (Optional) You can verify the connection from the FortiManager GUI. Navigate back to **System Settings > Advanced > Syslog Server**, select your configured server, and click the **Test** button to send a test message.

#### Log file collection

For filestream collection, you must configure FortiManager or FortiAnalyzer to store logs locally on the system where the Elastic Agent is running, or on a network-mounted filesystem accessible by the agent. Common log paths can include `/var/log/fortinet/fortimanager.log*`. Ensure that the Elastic Agent has the necessary file system read permissions to access these log files. For more information, refer to the official Fortinet documentation regarding local log storage and retention.

#### Vendor resources

The following resources provide additional information on configuring FortiManager:
- [Syslog Server | FortiManager 7.6.4 | Fortinet Document Library](https://docs.fortinet.com/document/fortimanager/7.6.4/administration-guide/374190/syslog-server)
- [Send local logs to syslog server | FortiManager 7.4.5 | Fortinet Document Library](https://docs.fortinet.com/document/fortimanager/7.4.5/administration-guide/414141/send-local-logs-to-syslog-server)
- [Technical tip: Configure FortiManager to send logs to a syslog server - Fortinet Community](https://community.fortinet.com/t5/FortiManager/Technical-tip-Configure-FortiManager-to-send-logs-to-a-syslog/ta-p/191412)

### Set up steps in Kibana

To set up the integration in Kibana:

1.  In Kibana, navigate to **Management > Integrations**.
2.  Search for "Fortinet FortiManager Logs" and select the integration.
3.  Click **Add Fortinet FortiManager Logs**.
4.  Configure the integration by selecting an input type and providing the necessary settings. This integration supports `TCP`, `UDP`, and `Filestream` (Log file) inputs.

Choose the setup instructions below that match your configuration.

#### Filestream input configuration

Use this input if the Elastic Agent has direct access to FortiManager log files.

| Setting | Description |
|---|---|
| **Paths** | A list of glob-based paths to monitor (for example, `/var/log/fortinet/fortimanager.log*`). |
| **Timezone Offset** | Specify an IANA timezone or offset (for example, `Europe/Amsterdam` or `-05:00`) for logs with no timezone information. Default is `local`. |
| **Preserve original event** | If checked, a raw copy of the original log is stored in the `event.original` field. |

Under **Advanced Options**, you can configure the following optional parameters:
- **Tags**: Custom tags to add to the events (defaults to `forwarded`, `fortinet_fortimanager-log`).
- **Processors**: Add custom processors to enhance or reduce event fields before parsing.

#### TCP input configuration

Use this input to collect logs over a TCP socket.

| Setting | Description |
|---|---|
| **Listen Address** | The bind address for the TCP listener (for example, `localhost` or `0.0.0.0`). |
| **Listen Port** | The TCP port number to listen on (for example, `9022`). |
| **Preserve original event** | If checked, a raw copy of the original log is stored in the `event.original` field. |

Under **Advanced Options**, you can configure the following optional parameters:
- **Custom TCP Options**: Configure framing, message size, and connections.
- **SSL Configuration**: Configure SSL options for encrypted communication. See [SSL configuration documentation](https://www.elastic.co/guide/en/beats/filebeat/current/configuration-ssl.html#ssl-common-config) for details. You can configure certificate authorities and other SSL/TLS settings to secure the connection between FortiManager and the Elastic Agent.
- **Processors**: Add custom processors to enhance or reduce event fields before parsing.

#### UDP input configuration

Use this input to collect logs over a UDP socket.

| Setting | Description |
|---|---|
| **Listen Address** | The bind address for the UDP listener (for example, `localhost` or `0.0.0.0`). |
| **Listen Port** | The UDP port number to listen on (for example, `9022`). |
| **Preserve original event** | If checked, a raw copy of the original log is stored in the `event.original` field. |

Under **Advanced Options**, you can configure the following optional parameters:
- **Custom UDP Options**: Configure max message size and timeout.
- **Processors**: Add custom processors to enhance or reduce event fields before parsing.

After configuring the input, assign the integration to an agent policy and click **Save and continue**.

### Validation

To verify the integration is working correctly:

1.  Check the status of the Elastic Agent in Kibana. Navigate to **Management > Fleet > Agents** and ensure the agent assigned to the FortiManager policy is "Healthy" and "Online".
2.  Trigger data flow on the FortiManager device by performing one of the following actions:
    *   **Generate a configuration event**: Make a minor change in the GUI (for example, adding a comment) and save it.
    *   **Trigger a system event**: Run a command like `diagnose sys top` in the CLI.
    *   **Authentication**: Log out and log back in to the web GUI.
3.  Navigate to **Analytics > Discover** in Kibana.
4.  Enter the following KQL filter in the search bar: `data_stream.dataset : "fortinet_fortimanager.log"`
5.  Verify that logs appear in the results. Expand an entry and confirm the following fields are populated:
    *   `event.dataset` (should be `fortinet_fortimanager.log`)
    *   `source.ip` (IP address of the FortiManager device)
    *   `fortimanager.log.type` (for example, `event` or `traffic`)
    *   `fortimanager.log.subtype` (for example, `system`, `objcfg`, or `devmgr`)
    *   `message` (containing the raw log payload)
6.  Navigate to **Analytics > Dashboards** and search for "Fortinet FortiManager" to view the pre-built dashboards.

## Troubleshooting

For help with Elastic ingest tools, check the [common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems) documentation.

### Common configuration issues

You can resolve most integration issues by checking these common scenarios:
- No logs received by Elastic Agent: Verify that the `IP address (or FQDN)` and `Syslog Server Port` settings in the FortiManager GUI match the `Listen Address` and `Listen Port` configured in the integration. Check for network firewalls blocking ports like `514` or `9022`. Use `netstat -tulnp | grep <port>` on the host to confirm the agent is actively listening.
- Incorrect protocol configuration: Check the `Reliable Connection` option in the FortiManager Syslog Server settings. This option must be enabled when using the `tcp` input and disabled when using the `udp` input.
- Log forwarding not enabled or severity too low: Check the CLI configuration using the `config system locallog syslogd setting` command. Ensure that `set status enable` is active and `set severity information` (or another appropriate level) is set to capture the necessary logs.
- Filestream input permission issues: If you use the `filestream` input, ensure the Elastic Agent process has the required read permissions for the log file paths, such as `/var/log/fortinet/fortimanager.log*`.
- Parsing failures or incomplete events: Check for the presence of `error.message` fields in Kibana. Examine the `event.original` field for the raw log content to identify formatting issues. If logs appear truncated, increase the `max_message_size` in the `Custom TCP Options` or `Custom UDP Options` configuration.
- Missing or incorrect fields: Verify the `preserve_duplicate_custom_fields` setting in the integration configuration and ensure the source device is sending all expected log details.

## Performance and scaling

For more information on architectures that you can use for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

To ensure you get optimal performance in high-volume environments, consider the following:

- Transport and collection considerations: When you're collecting logs using syslog, choosing between `tcp` and `udp` is crucial. `tcp` offers reliable, ordered delivery, which is ideal for critical security logs where data integrity is paramount, though it might introduce slightly more overhead. `udp` provides faster, connectionless delivery, making it suitable for high-volume, less critical logs where some occasional packet loss is acceptable. For `filestream`, ensure the Elastic Agent has efficient access to log file paths and proper handling of log rotations so you don't encounter data gaps or performance bottlenecks.
- Data volume management: To optimize the performance of both the FortiManager or FortiAnalyzer and the Elastic Stack, configure your source device to filter or limit the types and severity of logs forwarded to the Elastic Agent. Only forward logs essential for your security monitoring, compliance, or operational analysis needs. While setting the minimum severity to `information` ensures comprehensive logging, you can adjust it to `warning` or `error` if data volume becomes unmanageably high.
- Elastic Agent scaling: A single Elastic Agent can handle a significant volume of logs, but for high-throughput environments, you'll want to consider deploying multiple Elastic Agents. Each agent can be configured to listen on a dedicated port or monitor specific subsets of log files, which distributes the ingestion load. Ensure your agents are adequately resourced with CPU, memory, and disk I/O, and are placed strategically (for example, on the same network segment) to minimize network latency to the FortiManager or FortiAnalyzer devices.

## Reference

### Inputs used

These inputs can be used with this integration:
<details>
<summary>filestream</summary>

## Setup

For more details about the Filestream input settings, check the [Filebeat documentation](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-filestream).


### Collecting logs from Filestream

To collect logs via Filestream, select **Collect logs via Filestream** and configure the following parameters:

- Filestream paths: The full path to the related log file.
</details>
<details>
<summary>tcp</summary>

## Setup

For more details about the TCP input settings, check the [Filebeat documentation](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-tcp).

### Collecting logs from TCP

To collect logs via TCP, select **Collect logs via TCP** and configure the following parameters:

**Required Settings:**
- Host
- Port

**Common Optional Settings:**
- Max Message Size - Maximum size of incoming messages
- Max Connections - Maximum number of concurrent connections
- Timeout - How long to wait for data before closing idle connections
- Line Delimiter - Character(s) that separate log messages

## SSL/TLS Configuration

To enable encrypted connections, configure the following SSL settings:

**SSL Settings:**
- Enable SSL*- Toggle to enable SSL/TLS encryption
- Certificate - Path to the SSL certificate file (`.crt` or `.pem`)
- Certificate Key - Path to the private key file (`.key`)
- Certificate Authorities - Path to CA certificate file for client certificate validation (optional)
- Client Authentication - Require client certificates (`none`, `optional`, or `required`)
- Supported Protocols - TLS versions to support (e.g., `TLSv1.2`, `TLSv1.3`)

**Example SSL Configuration:**
```yaml
ssl.enabled: true
ssl.certificate: "/path/to/server.crt"
ssl.key: "/path/to/server.key"
ssl.certificate_authorities: ["/path/to/ca.crt"]
ssl.client_authentication: "optional"
```
</details>
<details>
<summary>udp</summary>

## Setup

For more details about the UDP input settings, check the [Filebeat documentation](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-udp).

### Collecting logs from UDP

To collect logs via UDP, select **Collect logs via UDP** and configure the following parameters:

**Required Settings:**
- Host
- Port

**Common Optional Settings:**
- Max Message Size - Maximum size of UDP packets to accept (default: 10KB, max: 64KB)
- Read Buffer - UDP socket read buffer size for handling bursts of messages
- Read Timeout - How long to wait for incoming packets before checking for shutdown
</details>


### Data streams

#### log

The `log` data stream collects various log types from Fortinet FortiManager, including event, content, and system logs. These logs provide information about device management, configuration changes, and administrative activity.

##### log fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| container.id | Unique container id. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| fortimanager.log.action | Records the action taken. | keyword |
| fortimanager.log.address | IP address of login user. | ip |
| fortimanager.log.admin_prof | Login user admin profile. | keyword |
| fortimanager.log.adom.lock | Name of adom which is locked/unlocked. | keyword |
| fortimanager.log.adom.name | The name of admin ADOM. | keyword |
| fortimanager.log.adom.oid | The OID of target ADOM. | keyword |
| fortimanager.log.app | Application name. | keyword |
| fortimanager.log.appcat | Application category. | keyword |
| fortimanager.log.apprisk | Application risk. | keyword |
| fortimanager.log.attribute_name | Variable name of which value is changed. | keyword |
| fortimanager.log.auth_msg | SSH authentication message. | keyword |
| fortimanager.log.bid | BID. | keyword |
| fortimanager.log.capacity | The percentage of memory capacity is used. | long |
| fortimanager.log.category | Log category. | keyword |
| fortimanager.log.cause | Reason that causes HA status down. | keyword |
| fortimanager.log.cert.name | Name of certificate. | keyword |
| fortimanager.log.cert.type | Type of certificate. | keyword |
| fortimanager.log.changes | Changes done on fortimanager subtype. | match_only_text |
| fortimanager.log.cli_act | CLI command action. | keyword |
| fortimanager.log.cmd_from | CLI command from. | keyword |
| fortimanager.log.comment | The description of this policy package. | keyword |
| fortimanager.log.condition | DVM dev condition. | keyword |
| fortimanager.log.conf_status | Conf sync status. | keyword |
| fortimanager.log.connect_status | Status of connection to the device. | keyword |
| fortimanager.log.const_msg | Constant message. | keyword |
| fortimanager.log.cpu_usage | CPU usage. | long |
| fortimanager.log.crlevel | CR level. | keyword |
| fortimanager.log.crscore | CR score. | long |
| fortimanager.log.date | The year, month, and day when the event occurred in the format: YY-MM-DD. | date |
| fortimanager.log.db.status | DVM device status. | keyword |
| fortimanager.log.db.ver | The service database version. | keyword |
| fortimanager.log.desc | A description of the activity or event recorded by the FortiManager unit. | keyword |
| fortimanager.log.detail | The task details. | keyword |
| fortimanager.log.dev.grps | Device groups. | keyword |
| fortimanager.log.dev.id | An identification number for the device that recorded the event. | keyword |
| fortimanager.log.dev.log | Name of the device. | keyword |
| fortimanager.log.dev.name | The name of the device that recorded the event. | keyword |
| fortimanager.log.dev.oid | The OID of target device. | keyword |
| fortimanager.log.device.id | An identification number for the device that recorded the event. | keyword |
| fortimanager.log.device.name | Name of the device. | keyword |
| fortimanager.log.device_log.id | Device log id. | keyword |
| fortimanager.log.device_log.last_logging | Last logging device. | keyword |
| fortimanager.log.device_log.name | Device log name. | keyword |
| fortimanager.log.device_log.offline_duration | Offline durations of device. | keyword |
| fortimanager.log.direction | Direction. | keyword |
| fortimanager.log.disk.label | Raid disk label. | long |
| fortimanager.log.disk.status.before | RAID disk status before change. | keyword |
| fortimanager.log.disk.status.current | RAID disk status after change. | keyword |
| fortimanager.log.dm_state | Deployment manager states. | keyword |
| fortimanager.log.dstcountry | Destination country. | keyword |
| fortimanager.log.dste.pid | An identification number for the destination endpoint. | keyword |
| fortimanager.log.dste.uid | An identification number for the destination end user. | keyword |
| fortimanager.log.dstip | Destination IP. | ip |
| fortimanager.log.dstname | Destination name. | keyword |
| fortimanager.log.dvid | Device id. | keyword |
| fortimanager.log.dvmdb_obj | Dvm_db object type. | keyword |
| fortimanager.log.end_time | End time of the report. | date |
| fortimanager.log.epid | An identification number for the endpoint. | keyword |
| fortimanager.log.err_code | Error code. | keyword |
| fortimanager.log.error | Error detail. | keyword |
| fortimanager.log.euid | An identification number for the destination end user. | keyword |
| fortimanager.log.event.id | Event id. | keyword |
| fortimanager.log.event.type | The type of event recorded. | keyword |
| fortimanager.log.expiration | Expiration time of the license. | date |
| fortimanager.log.extra_info | SSH authentication extra information. | keyword |
| fortimanager.log.file | Filename of package/log file. | keyword |
| fortimanager.log.fips.err | FIPS test error code. | keyword |
| fortimanager.log.fips.method | FIPS self-test method. | keyword |
| fortimanager.log.function | The name of the function call. | keyword |
| fortimanager.log.id | A ten-digit number that identifies the log type. The first two digits represent the log type, and the following two digits represent the log subtype. The last six digits represent the message id number. | keyword |
| fortimanager.log.importance | dvm_db metafield mtype. | keyword |
| fortimanager.log.inst.adom | The name of ADOM which contains target device. | keyword |
| fortimanager.log.inst.dev | The name of device on which policy is installed. | keyword |
| fortimanager.log.inst.pkg | Name of policy package which is installed. | keyword |
| fortimanager.log.intfname | Interface name. | keyword |
| fortimanager.log.itime | Instruction time. | date |
| fortimanager.log.level | The severity level or priority of the event. | keyword |
| fortimanager.log.license_type | License type. | long |
| fortimanager.log.lickey_type | License key type. | keyword |
| fortimanager.log.lnk_path | The name of the link file being transferred to the server. | keyword |
| fortimanager.log.local_file | Local file include its path. | keyword |
| fortimanager.log.max_mb | License allowed maximum capacity in MB. | long |
| fortimanager.log.mem_usage | Memory usage. | long |
| fortimanager.log.meta_field.leng | Dvm_db metafield value size. | long |
| fortimanager.log.meta_field.name | Dvm_db metafield name. | keyword |
| fortimanager.log.meta_field.stat | Dvm_db metafield status. | keyword |
| fortimanager.log.module | Identifier of the HA sync module. | long |
| fortimanager.log.msg | The activity or event recorded by the FortiManager unit. | keyword |
| fortimanager.log.msg_rate | Message rate. | long |
| fortimanager.log.new.name | New object name being renamed to. | keyword |
| fortimanager.log.new.value | String representation of value after being changed. | keyword |
| fortimanager.log.new.version | New available version of the requested object. | keyword |
| fortimanager.log.obj.attr | CMDB config object attribute. | keyword |
| fortimanager.log.obj.name | Object name. | keyword |
| fortimanager.log.obj.path | CMDB config object path. | keyword |
| fortimanager.log.obj.type | Object type. | keyword |
| fortimanager.log.object | Filename of the requested object. | keyword |
| fortimanager.log.offline_stat | Offline mode enabled or disabled. | keyword |
| fortimanager.log.old_value | String representation of value before being changed. | keyword |
| fortimanager.log.oper_stat | The result of the operation. | keyword |
| fortimanager.log.operation | Operation name. | keyword |
| fortimanager.log.osname | OS name. | keyword |
| fortimanager.log.package.desc | Package description. | keyword |
| fortimanager.log.package.name | Name of package which is installed. | keyword |
| fortimanager.log.package.type | Identifier of package type. | keyword |
| fortimanager.log.path | The original log file. | keyword |
| fortimanager.log.peer | Serial number of HA peer. | keyword |
| fortimanager.log.percent | The percentage of this task being running. | long |
| fortimanager.log.performed_on | Details on which action was performed. | keyword |
| fortimanager.log.pid | Process id. | long |
| fortimanager.log.pkg.adom | Name of ADOM this policy package belongs to. | keyword |
| fortimanager.log.pkg.gname | Name of the global policy package that is assigned. | keyword |
| fortimanager.log.pkg.name | Name of the policy package which is locked/unlocked. | keyword |
| fortimanager.log.pkg.oid | The OID of the package to be installed. | keyword |
| fortimanager.log.pre_version | Previous version of the requested object. | keyword |
| fortimanager.log.pri | The severity level or priority of the event. | keyword |
| fortimanager.log.priority_number | Syslog priority number. | long |
| fortimanager.log.product | Fortinet product name. | keyword |
| fortimanager.log.prof_name | Device profile object name. | keyword |
| fortimanager.log.protocol | Transmission protocol used to backup all settings. | keyword |
| fortimanager.log.pty.err | Pty operation error no. | keyword |
| fortimanager.log.pty.oper | Pty operation type, get or put. | keyword |
| fortimanager.log.pty.sess | Pty session server type. | keyword |
| fortimanager.log.pty.step | Pty operation step. | keyword |
| fortimanager.log.quota | Disk quota ratio in percentage. | long |
| fortimanager.log.raid_state.before | RAID status before change. | keyword |
| fortimanager.log.raid_state.current | RAID status after change. | keyword |
| fortimanager.log.rate | How many requests are handled per minute. | long |
| fortimanager.log.rate_limit | Log rate limit. | long |
| fortimanager.log.rate_peak | Log rate peak. | long |
| fortimanager.log.rate_value | Log rate. | long |
| fortimanager.log.rcvdbyte | Number of bytes received. | long |
| fortimanager.log.reboot_reason | The reason for system reboot. | keyword |
| fortimanager.log.remote.filename | Remote filename on server side. | keyword |
| fortimanager.log.remote.host | Remote host name or host ip in string presentation. | keyword |
| fortimanager.log.remote.ip | Remote peer ip in string presentation. | ip |
| fortimanager.log.remote.path | Remote path on server side. | keyword |
| fortimanager.log.remote.port | Remote peer port number. | long |
| fortimanager.log.result | The result of the operation. | keyword |
| fortimanager.log.revision | The id of the revision that is operated. | long |
| fortimanager.log.rolling.cur_number | Log rolling number that currently reached. | long |
| fortimanager.log.rolling.max_allowed | Log rolling max number that is allowed. | long |
| fortimanager.log.run_from | Reports from where the run happen. | keyword |
| fortimanager.log.rundb_ver | Version of the running database. | keyword |
| fortimanager.log.script | Name of the script. | keyword |
| fortimanager.log.sensor.name | Sensor name. | keyword |
| fortimanager.log.sensor.st | Sensor status. | keyword |
| fortimanager.log.sensor.val | Sensor value. | keyword |
| fortimanager.log.sentbyte | Number of bytes sent. | long |
| fortimanager.log.serial | Serial number of the device. | keyword |
| fortimanager.log.service | Name of the starting service. | keyword |
| fortimanager.log.session_id | The session identification number. | keyword |
| fortimanager.log.setup | Whether it needs to setup or not. | long |
| fortimanager.log.shutdown_reason | The reason for system shutdown. | keyword |
| fortimanager.log.size | The size of log file that is rolling and uploaded. | long |
| fortimanager.log.srcip | Source IP. | ip |
| fortimanager.log.srcname | Source name. | keyword |
| fortimanager.log.srcport | Source port. | long |
| fortimanager.log.start_time | Start time of the report. | date |
| fortimanager.log.state | The state of the task. | keyword |
| fortimanager.log.status | Interface/Operation status. | keyword |
| fortimanager.log.subtype | The subtype of each log message. | keyword |
| fortimanager.log.sw_version | Current firmware software version. | keyword |
| fortimanager.log.time | The hour, minute, and second of when the event occurred. | keyword |
| fortimanager.log.title | The task title. | keyword |
| fortimanager.log.to_build | The build no of the firmware that is upgraded to. | long |
| fortimanager.log.to_release | The release of the firmware that is upgraded to. | keyword |
| fortimanager.log.to_version | The version of the firmware that is upgraded to. | keyword |
| fortimanager.log.type | Log type. | keyword |
| fortimanager.log.tz | Event timezone. | keyword |
| fortimanager.log.uid | UID of a fortiClient installation. | keyword |
| fortimanager.log.unauthuser | Unauthenticated user. | keyword |
| fortimanager.log.upddb_ver | Version of the updating database. | keyword |
| fortimanager.log.upg_act | Operation that is failed. | keyword |
| fortimanager.log.upgrade.adom | The name of ADOM to be upgraded. | keyword |
| fortimanager.log.upgrade.from | The version, mr, build or branchpoint before upgrade. | keyword |
| fortimanager.log.upgrade.to | The version, mr, build or branchpoint after upgrade. | keyword |
| fortimanager.log.uploading.cur_number | The number of uploading process that currently reached. | long |
| fortimanager.log.uploading.max_allowed | Max number of uploading process that is allowed. | long |
| fortimanager.log.uploading.oper | Upload operations. | keyword |
| fortimanager.log.uploading.pid | Process id of the uploading child process. | keyword |
| fortimanager.log.uploading.server_type | The type of server that accepts the uploaded log. | keyword |
| fortimanager.log.url | Web filtering requested URL. | keyword |
| fortimanager.log.use_mb | Used capacity in MB. | long |
| fortimanager.log.user.from | Login session user from. | keyword |
| fortimanager.log.user.id | PTY operation login user id. | keyword |
| fortimanager.log.user.name | User name. | keyword |
| fortimanager.log.user.type | Access restriction of session admin profile. | keyword |
| fortimanager.log.ustr | Extra log information. | keyword |
| fortimanager.log.valid | If ssh user is valid or not. | long |
| fortimanager.log.vdom | Virtual domain of a device. | keyword |
| fortimanager.log.vdoms | List of VDOMs to which revision is installed. | keyword |
| fortimanager.log.version | The new version of updated object. | keyword |
| fortimanager.log.whitelist_size | The size of white list table. | keyword |
| fortimanager.log.zip_path | The name of the gzip file being transferred to the server. | keyword |
| input.type | Type of filebeat input. | keyword |
| log.file.device_id | ID of the device containing the filesystem where the file resides. | keyword |
| log.file.fingerprint | The sha256 fingerprint identity of the file when fingerprinting is enabled. | keyword |
| log.file.idxhi | The high-order part of a unique identifier that is associated with a file. (Windows-only) | keyword |
| log.file.idxlo | The low-order part of a unique identifier that is associated with a file. (Windows-only) | keyword |
| log.file.inode | Inode number of the log file. | keyword |
| log.file.path | Full path to the log file this event came from. | keyword |
| log.file.vol | The serial number of the volume that contains a file. (Windows-only) | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Log offset. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| tags | User defined tags. | keyword |


##### log sample event

An example event for `log` looks as following:

```json
{
    "@timestamp": "2023-02-19T22:20:11.000Z",
    "agent": {
        "ephemeral_id": "8937d089-d80c-4225-9177-d6286824defd",
        "id": "1c091add-3dae-4323-a5e8-648158c83b7b",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.10.2"
    },
    "data_stream": {
        "dataset": "fortinet_fortimanager.log",
        "namespace": "ep",
        "type": "logs"
    },
    "device": {
        "id": "FMGVMSTM23000100"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "1c091add-3dae-4323-a5e8-648158c83b7b",
        "snapshot": false,
        "version": "8.10.2"
    },
    "event": {
        "action": "roll",
        "agent_id_status": "verified",
        "dataset": "fortinet_fortimanager.log",
        "ingested": "2023-10-03T09:57:15Z",
        "kind": "event",
        "original": "<134>date=2023-02-20 time=03:20:11 tz=\"+0500\" devname=Crest-Elastic-FMG-VM64 device_id=FMGVMSTM23000100 log_id=0031040026 type=event subtype=logfile pri=information desc=\"Rolling disk log file\" user=\"system\" userfrom=\"system\" msg=\"Rolled log file glog.1676746501.log of device SYSLOG-0A32041A [SYSLOG-0A32041A] vdom root.\" operation=\"Roll logfile\" performed_on=\"\" changes=\"Rolled log file.\" action=\"roll\"",
        "timezone": "+0500",
        "type": [
            "info"
        ]
    },
    "fortimanager": {
        "log": {
            "action": "roll",
            "changes": "Rolled log file.",
            "date": "2023-02-19T22:20:11.000Z",
            "desc": "Rolling disk log file",
            "dev": {
                "name": "Crest-Elastic-FMG-VM64"
            },
            "device": {
                "id": "FMGVMSTM23000100"
            },
            "id": "0031040026",
            "msg": "Rolled log file glog.1676746501.log of device SYSLOG-0A32041A [SYSLOG-0A32041A] vdom root.",
            "operation": "Roll logfile",
            "pri": "information",
            "priority_number": 134,
            "product": "fortianalyzer",
            "subtype": "logfile",
            "type": "event",
            "user": {
                "from": "system",
                "name": "system"
            }
        }
    },
    "host": {
        "hostname": "Crest-Elastic-FMG-VM64"
    },
    "input": {
        "type": "tcp"
    },
    "log": {
        "source": {
            "address": "192.168.224.5:58676"
        }
    },
    "message": "Rolled log file glog.1676746501.log of device SYSLOG-0A32041A [SYSLOG-0A32041A] vdom root.",
    "related": {
        "hosts": [
            "Crest-Elastic-FMG-VM64"
        ],
        "user": [
            "system"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "fortinet_fortimanager-log"
    ],
    "user": {
        "name": "system"
    }
}
```

### Vendor documentation links

You can find more information about FortiManager logs in the following vendor resources:
*   [FortiManager & FortiAnalyzer Log Reference](https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/5a0d548a-12b0-11ed-9eba-fa163e15d75b/FortiManager_%26_FortiAnalyzer_7.2.1_Log_Reference.pdf)
*   [FortiManager 7.6.4 Administration Guide - Syslog Server](https://docs.fortinet.com/document/fortimanager/7.6.4/administration-guide/374190/syslog-server)
*   [FortiManager 7.4.5 Administration Guide - Send local logs to syslog server](https://docs.fortinet.com/document/fortimanager/7.4.5/administration-guide/414141/send-local-logs-to-syslog-server)
*   [Fortinet Technical Tip: Configure FortiManager to send logs to a syslog server](https://community.fortinet.com/t5/FortiManager/Technical-tip-Configure-FortiManager-to-send-logs-to-a-syslog/ta-p/191412)
*   [Fortinet FortiManager VM Install Guide](https://help.fortinet.com/fmgr/vm-install/56/Resources/HTML/0000_OnlineHelp%20Cover.htm)
