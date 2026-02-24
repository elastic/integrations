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

To get started with the Fortinet FortiManager Logs integration, you'll need the following:

### Elastic prerequisites
You'll need these Elastic Stack components:
- Elastic Stack version `8.11.0` or higher.
- An installed and enrolled Elastic Agent on a host machine that's network-accessible from your FortiManager or FortiAnalyzer devices.
- Network connectivity between the Elastic Agent and your Elasticsearch cluster to successfully send collected data.
- Sufficient system resources like CPU, memory, and disk I/O on the host running the Elastic Agent to process and forward the anticipated volume of logs.

### Vendor prerequisites
You'll need these Fortinet-specific items:
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
        *   To send logs via UDP (the default protocol), leave this option disabled.
        *   To send logs via TCP, enable this option. This setting must match the protocol you configure in the Elastic Agent integration.
        *   **Optional TLS setup**: When you use TCP with Reliable Connection enabled, you can optionally enable **Secure Connection** to encrypt traffic using TLS/SSL. If you enable this, you'll need to specify a **Local Certificate CN** and optionally a **Peer Certificate CN**. This requires corresponding SSL configuration in the Elastic Agent integration's advanced options.
5.  Click **OK** to save the configuration.

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

{{ inputDocs }}

### Data streams

#### log

The `log` data stream collects various log types from Fortinet FortiManager, including event, content, and system logs. These logs provide information about device management, configuration changes, and administrative activity.

##### log fields

{{ fields "log" }}

##### log sample event

{{ event "log" }}

### Vendor documentation links

You can find more information about FortiManager logs in the following vendor resources:
*   [FortiManager & FortiAnalyzer Log Reference](https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/5a0d548a-12b0-11ed-9eba-fa163e15d75b/FortiManager_%26_FortiAnalyzer_7.2.1_Log_Reference.pdf)
*   [FortiManager 7.6.4 Administration Guide - Syslog Server](https://docs.fortinet.com/document/fortimanager/7.6.4/administration-guide/374190/syslog-server)
*   [FortiManager 7.4.5 Administration Guide - Send local logs to syslog server](https://docs.fortinet.com/document/fortimanager/7.4.5/administration-guide/414141/send-local-logs-to-syslog-server)
*   [Fortinet Technical Tip: Configure FortiManager to send logs to a syslog server](https://community.fortinet.com/t5/FortiManager/Technical-tip-Configure-FortiManager-to-send-logs-to-a-syslog/ta-p/191412)
*   [Fortinet FortiManager VM Install Guide](https://help.fortinet.com/fmgr/vm-install/56/Resources/HTML/0000_OnlineHelp%20Cover.htm)
