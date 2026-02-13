# Sophos Integration for Elastic

> **Note**: This documentation was generated using AI and should be reviewed for accuracy.

## Overview

> **Note**: This documentation was generated using AI and should be reviewed for accuracy.

The Sophos integration for Elastic allows you to ingest, parse, and visualize logs from Sophos Unified Threat Management (UTM) and Sophos XG Firewall (SFOS) devices. This integration provides comprehensive security monitoring, threat detection, and network traffic analysis capabilities within the Elastic Stack.

By collecting these logs, you can gain visibility into firewall activity, monitor security heartbeats, audit policy compliance, and troubleshoot network issues efficiently.

### Compatibility

This integration is compatible with the following third-party vendor products:
- Sophos XG Firewall (SFOS): Explicitly tested on versions 17.5.x and 18.0.x. Versions above 18.0.x are expected to be compatible.
- Sophos Unified Threat Management (UTM): Supports modern Sophos UTM/Astaro Security Gateway versions.

### How it works

This integration collects logs from Sophos firewalls by receiving syslog data over TCP or UDP, or by reading directly from log files. An Elastic Agent is deployed on a host that is configured as a syslog receiver or has access to the log files. The agent forwards the logs to your Elastic deployment, where they are parsed into the Elastic Common Schema (ECS) for unified analysis.

You can collect comprehensive firewall telemetry, including:
- Security heartbeats
- System events
- Traffic logs
- Specific log categories such as DNS, DHCP, HTTP, and packet filter logs

All logs are expected in the default Sophos syslog format.

## What data does this integration collect?

The Sophos integration collects the following types of log data:
* Sophos XG logs (`xg`): Comprehensive firewall telemetry including security heartbeats, system events, and traffic logs. These logs can be ingested via TCP, UDP, or by reading directly from a logfile.
* Sophos UTM logs (`utm`): Telemetry from Unified Threat Management (formerly Astaro) devices, covering specific log categories such as DNS, DHCP, HTTP, and Packet Filter logs.
* Security events: Captures Antivirus detections, Intrusion Prevention System (IPS) alerts, and Advanced Threat Protection (ATP) events.
* System activity: Tracks administrative logons, configuration changes, and system health notifications from the Sophos appliances.

All logs are expected in the default Sophos syslog format, which is then parsed into the Elastic Common Schema (ECS) for unified analysis.

### Supported use cases

The Sophos integration for Elastic Agent allows organizations to ingest, parse, and visualize logs from Sophos Unified Threat Management (UTM) and Sophos XG Firewall (SFOS) devices. This integration supports the following use cases:
* Threat detection and security monitoring: Monitor firewall logs, packet filter events, and intrusion prevention alerts to identify and respond to potential security threats in real-time.
* Network visibility and traffic analysis: Analyze DNS, DHCP, and HTTP traffic logs to understand network usage patterns and identify shadow IT or unauthorized resource access.
* Compliance and auditing: Maintain long-term storage of firewall activity and administrative changes to satisfy regulatory requirements and support forensic investigations.
* Troubleshooting and performance optimization: Use detailed log data to diagnose connectivity issues, identify misconfigured firewall rules, and monitor system health across the security estate.

## What do I need to use this integration?

Before you can use this integration, you need to ensure the following prerequisites are met.

### Vendor prerequisites

You need the following from the Sophos environment:
- Administrative credentials for the Sophos WebAdmin or XG Firewall web console to configure log export settings.
- Network connectivity between the firewall and the Elastic Agent host on the configured ports (default ports are UDP `9005`/`9549` or TCP `9005`/`9549`).
- For Sophos XG, the syslog format set to `Device Standard Format` or `Default` for correct parsing.
- Appropriate logging and reporting features enabled within your Sophos licensing tier.

### Elastic prerequisites

You need the following for the Elastic deployment:
- Elastic Stack version 8.0 or higher.
- An Elastic Agent installed and enrolled in Fleet on a host reachable by the Sophos devices.
- The Sophos integration added to the Elastic Agent policy in Kibana.
- The host running the Elastic Agent configured to listen on the selected ports (for example, `9005` or `9549`).

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the syslog or log file receiver and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Set up steps in Sophos

Configure your Sophos device to send logs to the Elastic Agent using the following instructions.

#### Sophos XG Firewall (SFOS)

To configure Sophos XG Firewall to send logs via syslog:

1.  Log in to the Sophos XG Firewall web admin console.
2.  Navigate to **System services > Log settings**.
3.  Click **Add** under the **Syslog server** section.
4.  Configure the syslog server with these settings:
    -   **Name**: Enter a descriptive name like `Elastic-Agent-XG`.
    -   **IP address/domain**: Enter the IP address of the Elastic Agent.
    -   **Port**: Enter the port (e.g., `9005`).
    -   **Facility**: Select `DAEMON`.
    -   **Severity level**: Select `Information`.
    -   **Format**: Select **Device Standard Format**.
5.  Click **Save**.
6.  Scroll down to the **Log settings** section on the main page.
7.  Check the boxes for all log modules you wish to forward (Firewall, IPS, Antivirus, etc.) in the column for your new syslog server.
8.  Click **Apply**.

#### Sophos UTM

To configure Sophos UTM to send logs via syslog:

1.  Log in to the Sophos UTM WebAdmin interface.
2.  Navigate to **Logging & Reporting > Log Settings**.
3.  Click on the **Remote Syslog Server** tab.
4.  Toggle the **Syslog Server Status** to enabled.
5.  In the **Syslog Servers** section, click the **Plus (+)** icon.
6.  Configure the server:
    -   **Name**: `Elastic-Agent-UTM`.
    -   **Server**: Select or create the network definition for the Elastic Agent IP.
    -   **Port**: Enter the port (e.g., `9549`).
7.  Click **Save**.
8.  Under **Remote Syslog Log Selection**, check the log types to forward (e.g., Firewall, Packet Filter).
9.  Click **Apply**.

#### Vendor resources

-   [Sophos Firewall: Add a syslog server](https://docs.sophos.com/nsg/sophos-firewall/22.0/help/en-us/webhelp/onlinehelp/AdministratorHelp/SystemServices/LogSettings/SyslogServerAdd/)
-   [Sophos Firewall: Log settings](https://docs.sophos.com/nsg/sophos-firewall/20.0/Help/en-us/webhelp/onlinehelp/AdministratorHelp/SystemServices/LogSettings/)
-   [Sophos Community: XGS Firewall Syslog Communication](https://community.sophos.com/sophos-xg-firewall/f/discussions/149328/xgs-firewall-is-not-communicating-with-syslog-server)

### Set up steps in Kibana

1.  In Kibana, navigate to **Management > Integrations** and search for **Sophos**.
2.  Click **Add Sophos**.
3.  Select the input type that matches your configuration (UDP, TCP, or File).

#### UDP input configuration

Select **Collecting syslog from Sophos via UDP** and configure the settings for your specific device type.

**For Sophos XG logs:**

-   **Syslog Host** (`syslog_host`): The interface to listen on. Default: `localhost`. Use `0.0.0.0` to bind to all interfaces.
-   **Syslog Port** (`syslog_port`): The port to listen on. Default: `9005`.
-   **Default Host Name** (`default_host_name`): Fallback observer name. Default: `firewall.localgroup.local`.
-   **Known Devices** (`known_devices`): Maps serial numbers to hostnames.
-   **Preserve original event** (`preserve_original_event`): Default: `False`.
-   **Tags** (`tags`): Default: `['sophos-xg', 'forwarded']`.
-   **Timezone** (`tz_offset`): IANA time zone for syslog timestamps. Default: `UTC`.
-   **Timezone Map** (`tz_map`): Advanced mapping for Sophos XG log timezones.
-   **Custom UDP Options** (`udp_options`): Configure `read_buffer` or `max_message_size`.
-   **Processors** (`processors`): Add custom pre-parsing logic.

**For Sophos UTM logs:**

-   **UDP host to listen on** (`udp_host`): The interface to listen on. Default: `localhost`.
-   **UDP port to listen on** (`udp_port`): The port to listen on. Default: `9549`.
-   **Timezone offset** (`tz_offset`): The timezone offset (e.g., `Europe/Amsterdam` or `+05:00`). Default: `UTC`.
-   **Preserve original event** (`preserve_original_event`): Default: `False`.
-   **Tags** (`tags`): Default: `['sophos-utm', 'forwarded']`.
-   **Processors** (`processors`): Add custom pre-parsing logic.

#### TCP input configuration

Select **Collecting syslog from Sophos via TCP** and configure the settings for your specific device type.

**For Sophos XG logs:**

-   **Syslog Host** (`syslog_host`): The interface to listen on. Default: `localhost`.
-   **Syslog Port** (`syslog_port`): The port to listen on. Default: `9005`.
-   **Default Host Name** (`default_host_name`): Fallback observer name. Default: `firewall.localgroup.local`.
-   **Known Devices** (`known_devices`): Serial number to hostname mapping.
-   **Preserve original event** (`preserve_original_event`): Default: `False`.
-   **Tags** (`tags`): Default: `['sophos-xg', 'forwarded']`.
-   **Timezone** (`tz_offset`): Default: `UTC`.
-   **Timezone Map** (`tz_map`): Mapping for Sophos log timezones.
-   **SSL Configuration** (`ssl`): Configure `certificate` and `key` for encrypted TCP.
-   **Custom TCP Options** (`tcp_options`): Configure `max_connections` and `framing`.
-   **Processors** (`processors`): Add custom pre-parsing logic.

**For Sophos UTM logs:**

-   **TCP host to listen on** (`tcp_host`): The interface to listen on. Default: `localhost`.
-   **TCP port to listen on** (`tcp_port`): The port to listen on. Default: `9549`.
-   **Timezone offset** (`tz_offset`): The timezone offset (e.g., `Europe/Amsterdam` or `+05:00`). Default: `UTC`.
-   **Preserve original event** (`preserve_original_event`): Default: `False`.
-   **Tags** (`tags`): Default: `['sophos-utm', 'forwarded']`.
-   **Processors** (`processors`): Add custom pre-parsing logic.

#### Log file input configuration

Select **Collecting syslog from Sophos via file** and configure the settings for your specific device type.

**For Sophos XG logs:**

-   **Paths** (`paths`): List of paths to monitor.
-   **Default Host Name** (`default_host_name`): Fallback observer name. Default: `firewall.localgroup.local`.
-   **Known Devices** (`known_devices`): Serial number to hostname mapping.
-   **Preserve original event** (`preserve_original_event`): Default: `False`.
-   **Tags** (`tags`): Default: `['sophos-xg', 'forwarded']`.
-   **Timezone** (`tz_offset`): Default: `UTC`.
-   **Timezone Map** (`tz_map`): Mapping for Sophos log timezones.
-   **Processors** (`processors`): Add custom pre-parsing logic.

**For Sophos UTM logs:**

-   **Paths** (`paths`): Paths to UTM logs (e.g., `['/var/log/sophos-utm.log']`).
-   **Timezone offset** (`tz_offset`): The timezone offset (e.g., `Europe/Amsterdam` or `+05:00`). Default: `UTC`.
-   **Preserve original event** (`preserve_original_event`): Default: `False`.
-   **Tags** (`tags`): Default: `['sophos-utm', 'forwarded']`.
-   **Processors** (`processors`): Add custom pre-parsing logic.

### Validation

After configuration is complete, follow these steps to verify data is flowing correctly from Sophos to the Elastic Stack.

1.  **Verify Elastic Agent status**: Navigate to **Management > Fleet > Agents** in Kibana and ensure the Elastic Agent status is "Healthy" and "Active".
2.  **Trigger data flow on Sophos**:
    -   **Generate Traffic Event**: From a client machine behind the Sophos firewall, browse to several public websites to generate HTTP and Firewall log entries.
    -   **Generate Admin Event**: Log out of the Sophos WebAdmin/Web Console and log back in to trigger authentication and system audit events.
    -   **Generate Config Event**: Make a minor, non-disruptive change to a description field in a firewall rule and click **Save** or **Apply** to trigger a configuration log.
3.  **Check data in Kibana**:
    -   Navigate to **Analytics > Discover**.
    -   Select the `logs-*` data view.
    -   Enter the following KQL filter: `data_stream.dataset : "sophos.xg" OR data_stream.dataset : "sophos.utm"`.
    -   Verify logs appear in the results. Expand a log entry and confirm these fields are populated:
        -   `event.dataset` (should match `sophos.xg` or `sophos.utm`)
        -   `source.ip` and/or `destination.ip`
        -   `event.action` or `event.outcome`
        -   `message` (containing the raw Sophos syslog payload)
    -   Navigate to **Analytics > Dashboards** and search for "Sophos" to view pre-built visualizations for traffic and security events.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Common configuration issues

The following are common configuration issues and their solutions:

-   Format mismatch:
    *   Ensure the Sophos XG is set to **Device Standard Format**. Other formats like CEF or JSON are not currently supported by this integration's parsers.
-   Timezone displacement:
    *   If logs appear in the future or past, check the **Timezone** or **Timezone Map** settings in the integration. Sophos XG often uses non-standard abbreviations that require explicit mapping.
-   Port binding conflicts:
    *   If the Elastic Agent fails to start the input, verify that no other service is using the configured UDP/TCP ports (e.g., `9005` or `9549`).
-   Serial number mapping issues:
    *   If hostnames appear as `firewall.localgroup.local`, ensure you have correctly mapped the firewall's serial number to a hostname in the **Known Devices** configuration section.
-   Parsing failures:
    *   Check for the `error.message` field in Kibana. This often occurs if the Sophos device sends logs in a non-default format or if a new SFOS version introduces unexpected log fields.
    *   Enable **Preserve original event** in the integration settings to see the raw log in `event.original` for debugging.
-   Incomplete UTM data:
    *   If specific UTM logs (like DNS) are missing, verify that those specific categories are checked in the **Remote Syslog Log Selection** menu on the UTM device.

### Vendor resources

For more information, refer to the following vendor resources:

-   [Sophos Firewall: Add a syslog server](https://docs.sophos.com/nsg/sophos-firewall/22.0/help/en-us/webhelp/onlinehelp/AdministratorHelp/SystemServices/LogSettings/SyslogServerAdd/)
-   [Sophos Firewall: Log settings](https://docs.sophos.com/nsg/sophos-firewall/20.0/Help/en-us/webhelp/onlinehelp/AdministratorHelp/SystemServices/LogSettings/)
-   [Sophos Community: XGS Firewall Syslog Communication](https://community.sophos.com/sophos-xg-firewall/f/discussions/149328/xgs-firewall-is-not-communicating-with-syslog-server)
-   [Sophos XG/SFOS Documentation](https://support.sophos.com/support/s/?language=en_US#t=AllTab&sort=relevancy)
-   [Sophos XG Syslog Guide (PDF)](https://docs.sophos.com/nsg/sophos-firewall/22.0/Help/en-us/webhelp/onlinehelp/index.html)

## Performance and scaling

To ensure optimal performance in high-volume environments, consider the following strategies:

### Transport and collection
This integration supports both UDP and TCP for syslog collection:
- **UDP**: Offers higher performance with lower overhead. It is often sufficient if the Elastic Agent and Sophos device are on the same local network.
- **TCP**: Recommended for high-volume environments or where data delivery guarantees are required to prevent log loss during network congestion.

### Data volume management
To optimize performance, you can filter data at the source:
- Use the **Log Settings** on the Sophos device to select only high-value log categories (e.g., Firewall, IPS) for export.
- Filter out high-noise events like "Allowed" packet filter logs to significantly reduce the volume of data processed by the Elastic Agent and stored in Elasticsearch.

### Elastic Agent scaling
For high-throughput environments processing logs from multiple large Sophos clusters:
- Deploy multiple Elastic Agents behind a network load balancer to distribute the syslog ingestion load and provide high availability.
- Place Agents close to the data source to minimize latency and potential packet loss.

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

### Vendor resources
- [Sophos Firewall: Log settings](https://docs.sophos.com/nsg/sophos-firewall/20.0/Help/en-us/webhelp/onlinehelp/AdministratorHelp/SystemServices/LogSettings/)
- [Sophos Community: XGS Firewall Syslog Communication](https://community.sophos.com/sophos-xg-firewall/f/discussions/149328/xgs-firewall-is-not-communicating-with-syslog-server)
- [Sophos XG Syslog Guide (PDF)](https://docs.sophos.com/nsg/sophos-firewall/22.0/Help/en-us/webhelp/onlinehelp/index.html)
- [Sophos XG/SFOS Documentation](https://support.sophos.com/support/s/?language=en_US#t=AllTab&sort=relevancy)

## Reference

### Inputs used
{{ inputDocs }}

### Vendor documentation links
This integration uses the following vendor documentation:
- [Sophos UTM Documentation](https://docs.sophos.com/nsg/sophos-utm/)
- [Sophos XG/SFOS Documentation](https://support.sophos.com/support/s/?language=en_US#t=AllTab&sort=relevancy)
- [Sophos XG Syslog Guide (PDF)](https://docs.sophos.com/nsg/sophos-firewall/22.0/Help/en-us/webhelp/onlinehelp/index.html)

### Data streams

#### utm

The `utm` data stream collects Sophos UTM logs.

##### utm fields

{{ fields "utm" }}

##### utm sample event

{{ event "utm" }}

#### xg

The `xg` data stream collects Sophos XG (SFOS) logs.

##### xg fields

{{ fields "xg" }}

##### xg sample event

{{ event "xg" }}
