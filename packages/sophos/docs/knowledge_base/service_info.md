# Service Info

## Common use cases

The Sophos integration for Elastic Agent allows organizations to ingest, parse, and visualize logs from Sophos Unified Threat Management (UTM) and Sophos XG Firewall (SFOS) devices.
- **Threat Detection and Security Monitoring:** Monitor firewall logs, packet filter events, and intrusion prevention alerts to identify and respond to potential security threats in real-time.
- **Network Visibility and Traffic Analysis:** Analyze DNS, DHCP, and HTTP traffic logs to understand network usage patterns and identify shadow IT or unauthorized resource access.
- **Compliance and Auditing:** Maintain long-term storage of firewall activity and administrative changes to satisfy regulatory requirements and support forensic investigations.
- **Troubleshooting and Performance Optimization:** Use detailed log data to diagnose connectivity issues, identify misconfigured firewall rules, and monitor system health across the security estate.

## Data types collected

This integration can collect the following types of data:

- **Sophos XG logs (xg):** Collect Sophos XG logs. This data stream captures comprehensive firewall telemetry including security heartbeats, system events, and traffic logs. It supports ingestion via **TCP**, **UDP**, or by reading directly from a **logfile**.
- **Sophos UTM logs (utm):** Collect Sophos UTM logs and Sophos UTM logs from file. This includes telemetry from Unified Threat Management (formerly Astaro) devices, covering specific log categories such as DNS, DHCP, HTTP, and Packet Filter logs.
- **Security Events:** Captures Antivirus detections, Intrusion Prevention System (IPS) alerts, and Advanced Threat Protection (ATP) events.
- **System Activity:** Tracks administrative logons, configuration changes, and system health notifications from the Sophos appliances.
- **Data Formats:** All logs are expected in the **Default** Sophos syslog format, which is then parsed into the Elastic Common Schema (ECS) for unified analysis.

## Compatibility

The Sophos integration is compatible with the following third-party vendor products:
- **Sophos XG Firewall (SFOS):** Explicitly tested on versions **17.5.x** and **18.0.x**. Versions above **18.0.x** are expected to be compatible.
- **Sophos Unified Threat Management (UTM):** Supports modern Sophos UTM/Astaro Security Gateway versions.

## Scaling and Performance

To ensure optimal performance in high-volume environments, consider the following:
- **Transport/Collection Considerations:** This integration supports both UDP and TCP for syslog collection. While UDP offers higher performance with lower overhead, TCP is recommended for high-volume environments or where data delivery guarantees are required to prevent log loss during network congestion. If the Elastic Agent and Sophos device are on the same local network, UDP is often sufficient.
- **Data Volume Management:** To optimize performance, administrators should use the "Log Settings" on the Sophos device to select only high-value log categories (e.g., Firewall, IPS) for export. Filtering out high-noise events like "Allowed" packet filter logs at the source can significantly reduce the volume of data processed by the Elastic Agent and stored in Elasticsearch.
- **Elastic Agent Scaling:** For high-throughput environments processing logs from multiple large Sophos clusters, deploy multiple Elastic Agents behind a network load balancer to distribute the syslog ingestion load and provide high availability. Place Agents close to the data source to minimize latency and potential packet loss.

# Set Up Instructions

## Vendor prerequisites

- **Administrative Access:** You must have administrative credentials for the Sophos WebAdmin or XG Firewall web console to configure log export settings.
- **Network Connectivity:** Ensure the firewall can reach the Elastic Agent host on the configured ports (Default ports: UDP 9005/9549, TCP 9005/9549, or custom ports as specified).
- **Log Format Requirement:** For Sophos XG, the syslog format must be set to **Device Standard Format** or **Default** for the integration to parse fields correctly.
- **License Requirements:** Ensure the appropriate logging and reporting features are enabled within your Sophos licensing tier.

## Elastic prerequisites

- **Elastic Stack Version:** This integration requires Elastic Stack version 8.0 or higher.
- **Elastic Agent Installation:** An Elastic Agent must be installed and enrolled in Fleet on a host reachable by the Sophos devices.
- **Integration Policy:** The Sophos integration must be added to the Elastic Agent policy in Kibana.
- **Network Path:** The host running the Elastic Agent must have its local firewall configured to listen on the selected ports (e.g., `9005`, `9549`).

## Vendor set up steps

### For Sophos XG Firewall (SFOS):
1. Log in to the Sophos XG Firewall web admin console.
2. Navigate to **System services > Log settings**.
3. Click **Add** under the **Syslog server** section.
4. Configure the syslog server with these settings:
    - **Name**: Enter a descriptive name like `Elastic-Agent-XG`.
    - **IP address/domain**: Enter the IP address of the Elastic Agent.
    - **Port**: Enter the port (e.g., `9005`).
    - **Facility**: Select `DAEMON`.
    - **Severity level**: Select `Information`.
    - **Format**: Select **Device Standard Format**.
5. Click **Save**.
6. Scroll down to the **Log settings** section on the main page.
7. Check the boxes for all log modules you wish to forward (Firewall, IPS, Antivirus, etc.) in the column for your new syslog server.
8. Click **Apply**.

### For Sophos UTM:
1. Log in to the Sophos UTM WebAdmin interface.
2. Navigate to **Logging & Reporting > Log Settings**.
3. Click on the **Remote Syslog Server** tab.
4. Toggle the **Syslog Server Status** to enabled.
5. In the **Syslog Servers** section, click the **Plus (+)** icon.
6. Configure the server:
    - **Name**: `Elastic-Agent-UTM`.
    - **Server**: Select or create the network definition for the Elastic Agent IP.
    - **Port**: Enter the port (e.g., `9549`).
7. Click **Save**.
8. Under **Remote Syslog Log Selection**, check the log types to forward (e.g., Firewall, Packet Filter).
9. Click **Apply**.

### Vendor Set up Resources

- [Sophos Firewall: Add a syslog server](https://docs.sophos.com/nsg/sophos-firewall/22.0/help/en-us/webhelp/onlinehelp/AdministratorHelp/SystemServices/LogSettings/SyslogServerAdd/) - Guide on configuring remote syslog targets.
- [Sophos Firewall: Log settings](https://docs.sophos.com/nsg/sophos-firewall/20.0/Help/en-us/webhelp/onlinehelp/AdministratorHelp/SystemServices/LogSettings/) - Instructions for managing log modules and severity.
- [Sophos Community: XGS Firewall Syslog Communication](https://community.sophos.com/sophos-xg-firewall/f/discussions/149328/xgs-firewall-is-not-communicating-with-syslog-server) - Community discussion for troubleshooting connectivity.

## Kibana set up steps

### Collecting syslog from Sophos via UDP
1. In Kibana, navigate to **Management > Integrations** and search for **Sophos**.
2. Click **Add Sophos** and select the **Collecting syslog from Sophos via UDP** input.
3. For **Sophos XG** logs, configure:
   - **Syslog Host** (`syslog_host`): The interface to listen on. Default: `localhost`. Use `0.0.0.0` to bind to all interfaces.
   - **Syslog Port** (`syslog_port`): The port to listen on. Default: `9005`.
   - **Default Host Name** (`default_host_name`): Fallback observer name. Default: `firewall.localgroup.local`.
   - **Known Devices** (`known_devices`): Maps serial numbers to hostnames.
   - **Preserve original event** (`preserve_original_event`): Default: `False`.
   - **Tags** (`tags`): Default: `['sophos-xg', 'forwarded']`.
   - **Timezone** (`tz_offset`): IANA time zone for syslog timestamps. Default: `UTC`.
   - **Timezone Map** (`tz_map`): Advanced mapping for Sophos XG log timezones.
   - **Custom UDP Options** (`udp_options`): Configure `read_buffer` or `max_message_size`.
   - **Processors** (`processors`): Add custom pre-parsing logic.
4. For **Sophos UTM** logs, configure:
   - **UDP host to listen on** (`udp_host`): The interface to listen on. Default: `localhost`.
   - **UDP port to listen on** (`udp_port`): The port to listen on. Default: `9549`.
   - **Timezone offset** (`tz_offset`): The timezone offset (e.g., `Europe/Amsterdam` or `+05:00`). Default: `UTC`.
   - **Preserve original event** (`preserve_original_event`): Default: `False`.
   - **Tags** (`tags`): Default: `['sophos-utm', 'forwarded']`.
   - **Processors** (`processors`): Add custom pre-parsing logic.
5. Save the integration to the desired policy.

### Collecting syslog from Sophos via TCP
1. Select the **Collecting syslog from Sophos via TCP** input in the integration configuration.
2. For **Sophos XG** logs, configure:
   - **Syslog Host** (`syslog_host`): The interface to listen on. Default: `localhost`.
   - **Syslog Port** (`syslog_port`): The port to listen on. Default: `9005`.
   - **Default Host Name** (`default_host_name`): Fallback observer name. Default: `firewall.localgroup.local`.
   - **Known Devices** (`known_devices`): Serial number to hostname mapping.
   - **Preserve original event** (`preserve_original_event`): Default: `False`.
   - **Tags** (`tags`): Default: `['sophos-xg', 'forwarded']`.
   - **Timezone** (`tz_offset`): Default: `UTC`.
   - **Timezone Map** (`tz_map`): Mapping for Sophos log timezones.
   - **SSL Configuration** (`ssl`): Configure `certificate` and `key` for encrypted TCP.
   - **Custom TCP Options** (`tcp_options`): Configure `max_connections` and `framing`.
   - **Processors** (`processors`): Add custom pre-parsing logic.
3. For **Sophos UTM** logs, configure:
   - **TCP host to listen on** (`tcp_host`): The interface to listen on. Default: `localhost`.
   - **TCP port to listen on** (`tcp_port`): The port to listen on. Default: `9549`.
   - **Timezone offset** (`tz_offset`): The timezone offset (e.g., `Europe/Amsterdam` or `+05:00`). Default: `UTC`.
   - **Preserve original event** (`preserve_original_event`): Default: `False`.
   - **Tags** (`tags`): Default: `['sophos-utm', 'forwarded']`.
   - **Processors** (`processors`): Add custom pre-parsing logic.
4. Save and deploy the integration.

### Collecting syslog from Sophos via file
1. Select the **Collecting syslog from Sophos via file.** input in the integration configuration.
2. For **Sophos XG** logs, configure:
   - **Paths** (`paths`): List of paths to monitor.
   - **Default Host Name** (`default_host_name`): Fallback observer name. Default: `firewall.localgroup.local`.
   - **Known Devices** (`known_devices`): Serial number to hostname mapping.
   - **Preserve original event** (`preserve_original_event`): Default: `False`.
   - **Tags** (`tags`): Default: `['sophos-xg', 'forwarded']`.
   - **Timezone** (`tz_offset`): Default: `UTC`.
   - **Timezone Map** (`tz_map`): Mapping for Sophos log timezones.
   - **Processors** (`processors`): Add custom pre-parsing logic.
3. For **Sophos UTM** logs, configure:
   - **Paths** (`paths`): Paths to UTM logs (e.g., `['/var/log/sophos-utm.log']`).
   - **Timezone offset** (`tz_offset`): The timezone offset (e.g., `Europe/Amsterdam` or `+05:00`). Default: `UTC`.
   - **Preserve original event** (`preserve_original_event`): Default: `False`.
   - **Tags** (`tags`): Default: `['sophos-utm', 'forwarded']`.
   - **Processors** (`processors`): Add custom pre-parsing logic.
4. Save and deploy the integration.

# Validation Steps

After configuration is complete, follow these steps to verify data is flowing correctly from Sophos to the Elastic Stack.

### 1. Trigger Data Flow on Sophos:
- **Generate Traffic Event:** From a client machine behind the Sophos firewall, browse to several public websites to generate HTTP and Firewall log entries.
- **Generate Admin Event:** Log out of the Sophos WebAdmin/Web Console and log back in to trigger authentication and system audit events.
- **Generate Config Event:** Make a minor, non-disruptive change to a description field in a firewall rule and click **Save** or **Apply** to trigger a configuration log.

### 2. Check Data in Kibana:
1. Navigate to **Analytics > Discover**.
2. Select the `logs-*` data view.
3. Enter the following KQL filter: `data_stream.dataset : "sophos.xg" OR data_stream.dataset : "sophos.utm"`.
4. Verify logs appear in the results. Expand a log entry and confirm these fields are populated:
   - `event.dataset` (should match `sophos.xg` or `sophos.utm`)
   - `source.ip` and/or `destination.ip`
   - `event.action` or `event.outcome`
   - `message` (containing the raw Sophos syslog payload)
5. Navigate to **Analytics > Dashboards** and search for "Sophos" to view pre-built visualizations for traffic and security events.

# Troubleshooting

## Common Configuration Issues

- **Format Mismatch**: Ensure the Sophos XG is set to "Device Standard Format". Other formats like CEF or JSON are not currently supported by this integration's parsers.
- **Timezone Displacement**: If logs appear in the future or past, check the `Timezone` or `Timezone Map` settings in the integration. Sophos XG often uses non-standard abbreviations that require explicit mapping.
- **Port Binding Conflicts**: If the Elastic Agent fails to start the input, verify that no other service is using the configured UDP/TCP ports (e.g., 9005 or 9549).
- **Serial Number Mapping**: If hostnames appear as "firewall.localgroup.local", ensure you have correctly mapped the firewall's serial number to a hostname in the **Known Devices** configuration section.

## Ingestion Errors

- **Parsing Failures**: Check for the `error.message` field in Kibana. This often occurs if the Sophos device sends logs in a non-default format or if a new SFOS version introduces unexpected log fields.
- **Original Event Preservation**: If you need to debug parsing, enable `Preserve original event` in the integration settings to see the raw log in `event.original`.
- **Incomplete UTM Categories**: If specific UTM logs (like DNS) are missing, verify that those specific categories are checked in the **Remote Syslog Log Selection** menu on the UTM device.

## Vendor Resources

- Sophos UTM Documentation - General documentation hub for UTM devices.
- [Sophos XG/SFOS Documentation](https://support.sophos.com/support/s/?language=en_US#t=AllTab&sort=relevancy) - Support portal for Sophos Firewall.
- [Sophos XG Syslog Guide (PDF)](https://docs.sophos.com/nsg/sophos-firewall/22.0/Help/en-us/webhelp/onlinehelp/index.html) - Detailed technical reference for log formats.

# Documentation sites

- [Sophos XG Syslog Guide (PDF)](https://docs.sophos.com/nsg/sophos-firewall/22.0/Help/en-us/webhelp/onlinehelp/index.html) - Technical reference for syslog field definitions.
- [Sophos Integration Reference](https://www.elastic.co/docs/reference/integrations/sophos) - Elastic documentation for the Sophos integration.
