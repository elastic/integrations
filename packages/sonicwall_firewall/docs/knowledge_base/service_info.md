# Service Info

## Common use cases

This integration collects syslog messages from SonicWall Firewalls, providing essential visibility into network security events and device activities.
-   **Security Monitoring:** Monitor firewall access rules, application firewall events, flood protection, intrusion prevention (IPS), anti-spyware, anti-virus, and botnet filter events to detect and respond to threats.
-   **Network Operations:** Gain insights into network events such as ARP, DNS, IP, TCP, and interface activities, helping administrators troubleshoot connectivity and performance issues.
-   **User Activity Auditing:** Track user authentication access, RADIUS authentication, and SSO Agent authentication events to maintain a comprehensive audit trail and ensure compliance.
-   **Configuration Change Tracking:** Log system administration, settings, and configuration auditing events to monitor changes made to the firewall, aiding in change management and incident investigation.

## Data types collected

This integration primarily collects **SonicWall Firewall logs**, encompassing various security and network event logs. These logs are normalized into the `sonicwall_firewall.log` dataset within the Elastic Stack, providing comprehensive visibility into network activity and potential threats.

Specifically, the integration collects data through the following data streams:
- **Syslog logs (logs)**: Collects Enhanced Syslog messages from SonicWall firewalls via UDP, including firewall access rules, application firewall, advanced settings, flood protection, network events (ARP, DNS, IP, TCP), security services (anti-spyware, anti-virus, IPS, content filter), system administration, and user authentication events.
- **Log files (logs)**: Collects logs from specified file paths, useful for scenarios where syslog forwarding is not preferred or supplemental log collection is needed. This stream captures the same types of firewall log data, but sourced directly from files on the agent's host.

## Supported messages

This integration features generic support for enhanced syslog messages produced by SonicOS and features
more detailed ECS enrichment for the following messages:

| Category | Subcategory | Message IDs |
|----------|-------------|-------------|
| Firewall | Access Rules | 440-442, 646, 647, 734, 735 |
| Firewall | Application Firewall | 793, 1654 |
| Firewall Settings | Advanced | 428, 1473, 1573, 1576, 1590 |
| Firewall Settings | Checksum Enforcement | 883-886, 1448, 1449 |
| Firewall Settings | FTP | 446, 527, 528, 538 |
| Firewall Settings | Flood Protection | 25, 856-860, 862-864, 897, 898, 901, 904, 905, 1180, 1213, 1214, 1366, 1369, 1450-1452 |
| Firewall Settings | Multicast | 683, 690, 694, 1233 |
| Firewall Settings | SSL Control | 999, 1001-1006, 1081 |
| High Availability | Cluster | 1149, 1152 |
| Log | Configuration Auditing | 1382, 1383, 1674 |
| Network | ARP | 45, 815, 1316 |
| Network | DNS | 1098, 1099 |
| Network | DNS Security | 1593 |
| Network | ICMP | 38, 63, 175, 182, 188, 523, 597, 598, 1254-1257, 1431, 1433, 1458 |
| Network | IP | 28, 522, 910, 1301-1303, 1429, 1430 |
| Network | IPcomp | 651-653 |
| Network | IPv6 Tunneling | 1253 |
| Network | Interfaces | 58 |
| Network | NAT | 339, 1197, 1436 |
| Network | NAT Policy | 1313-1315 |
| Network | Network Access | 41, 46, 98, 347, 524, 537, 590, 714, 1304 |
| Network | TCP | 36, 48, 173, 181, 580, 708, 709, 712, 713, 760, 887-896, 1029-1031, 1384, 1385, 1628, 1629 |
| Security Services | Anti-Spyware | 794-796 |
| Security Services | Anti-Virus | 123-125, 159, 408, 482 |
| Security Services | Application Control | 1154, 1155 |
| Security Services | Attacks | 22, 23, 27, 81-83, 177-179, 267, 606, 1373-1376, 1387, 1471 |
| Security Services | Botnet Filter | 1195, 1200, 1201, 1476, 1477, 1518, 1519 |
| Security Services | Content Filter | 14, 16, 1599-1601 |
| Security Services | Geo-IP Filter | 1198, 1199, 1474, 1475 |
| Security Services | IDP | 789, 790 |
| Security Services | IPS | 608, 609 |
| Security Services | Next-Gen Anti-Virus | 1559-1562 |
| Security Services | RBL Filter | 797, 798 |
| System | Administration | 340, 341 |
| System | Cloud Backup | 1511-1516 |
| System | Restart | 93-95, 164, 599-601, 1046, 1047, 1392, 1393 |
| System | Settings | 573, 574, 1049, 1065, 1066, 1160, 1161, 1268, 1269, 1336-1340, 1432, 1494, 1520, 1521, 1565-1568, 1636, 1637 |
| System | Status | 4, 53, 521, 1107, 1196, 1332, 1495, 1496 |
| Users | Authentication Access | 24, 29-35, 199, 200, 235-238, 246, 261-265, 328, 329, 438, 439, 486, 506-509, 520, 549-551, 557-562, 564, 583, 728, 729, 759, 986, 987, 994-998, 1008, 1035, 1048, 1080, 1117-1124, 1157, 1158, 1243, 1333-1335, 1341, 1342, 1517, 1570-1572, 1585, 1627, 1655, 1672 |
| Users | Radius Authentication | 243-245, 744-751, 753-757, 1011 |
| Users | SSO Agent Authentication | 988-991 |
| VPN | DHCP Relay | 229 |
| Wireless | RF Monitoring | 879 |
| Wireless | WLAN | 1363 |
| Wireless | WLAN IDS | 546, 548 |

## Compatibility

This integration is compatible with **SonicWall Firewall** devices running SonicOS 6.5 and 7.0. It has been tested against these specific versions, ensuring support for the Enhanced Syslog format.

## Scaling and Performance

To ensure optimal performance and reliable data ingestion in high-volume environments, consider the following:
- **Transport/Collection Considerations:** The SonicWall Firewall integration primarily uses UDP Syslog for log collection. UDP offers high speed and low overhead, making it suitable for high-volume log streams. However, UDP is an unreliable protocol, meaning there is no guarantee of delivery or order. For environments where log loss is unacceptable, it is crucial to ensure network reliability between the firewall and the Elastic Agent, potentially by implementing network quality-of-service (QoS) or ensuring sufficient buffer sizes.
- **Data Volume Management:** To manage data volume and reduce the load on both the SonicWall firewall and the Elastic Agent, it is highly recommended to filter or limit the data at the source. Configure the SonicWall firewall to only send relevant log categories and severity levels to the Syslog server. Excessive logging of low-priority events can consume significant network bandwidth and processing resources on both ends.
- **Elastic Agent Scaling:** A single Elastic Agent can handle a significant volume of syslog data, but for extremely high-throughput environments or to ensure redundancy, deploying multiple Elastic Agents is recommended. Place Elastic Agents strategically, ideally in the same network segment as the firewall or within close proximity, to minimize network latency. Monitor agent resource utilization (CPU, memory, disk I/O) to size resources appropriately and scale out by adding more agents as needed.

# Set Up Instructions

## Vendor prerequisites

-   Administrative access to the SonicWall firewall web interface is required to configure Syslog settings.
-   The Elastic Agent must be reachable from the SonicWall firewall over the network using the UDP protocol on the configured Syslog port (default `9514`). Ensure no firewalls or security groups are blocking this communication.
-   The SonicWall firewall must be configured to send logs in **Enhanced Syslog** format.
-   It is highly recommended to enable **Display UTC in logs (instead of local time)** under the firewall's *Device > Settings > Time* menu to ensure correct timestamp parsing and avoid timezone-related issues.
-   The IP address of the Elastic Agent where the syslog listener is running needs to be known.

## Elastic prerequisites

-   **Elastic Agent:** An Elastic Agent must be installed and enrolled in Fleet.
-   **Elastic Stack Version:** Compatible with Elastic Stack 7.17.0 or higher, and 8.x.
-   **Network Connectivity:** The Elastic Agent must have network connectivity to the SonicWall firewall to receive syslog messages on the configured UDP port.

## Vendor set up steps

### For SonicOS 7.x:
1.  Log in to your SonicWall firewall's administration interface.
2.  Navigate to **Device > Log > Syslog**.
3.  Under "Syslog Servers", click the **Add** button.
4.  In the "Add Syslog Server" window, enter the IP address of your Elastic Agent in the **Name or IP Address** field.
5.  From the **Syslog Format** dropdown menu, select **Enhanced Syslog**.
6.  (Optional) Enter a **Syslog ID**. The default is `firewall`. This ID is used to differentiate logs from multiple firewalls and is mapped to the `observer.name` field in Elastic.
7.  Click **OK** to save the syslog server configuration.
8.  Navigate to **Device > Log > Settings**.
9.  For each category of events you wish to forward (e.g., System, Firewall, Network), enable the Syslog checkbox (often represented by a small paper airplane icon).
10. Set the desired logging level for each category. It is recommended to set the level to **Informational** to capture sufficient detail.
11. Click **Accept** or **Save** at the bottom of the page to apply the changes.
12. Navigate to **Device > Settings > Time**.
13. Under "Display Time Zone", select the option **Display UTC in logs (instead of local time)**.
14. Click **Accept** to save the time setting.

### For SonicOS 6.5:
1.  Log in to your SonicWall firewall's administration interface.
2.  Navigate to **Manage > Log Settings > SYSLOG**.
3.  Click the **Add** button.
4.  In the "Add Syslog Server" window, enter the name or IP address of your Elastic Agent in the **Name or IP Address** field. The port will default to `514 (UDP)`.
5.  From the **Syslog Format** dropdown menu, select **Enhanced Syslog**.
6.  (Optional) Set the **Syslog ID**. The default is `firewall`. This ID is used to differentiate logs from multiple firewalls and is mapped to the `observer.name` field in Elastic.
7.  Click **OK** to save the syslog server configuration.
8.  Navigate to **Manage > Log Settings > Base Setup**.
9.  For each category of events you wish to forward (e.g., System, Firewall, Network), enable the Syslog checkbox (often represented by a small paper airplane icon).
10. Set the desired logging level for each category. It is recommended to set the level to **Informational** to capture sufficient detail.
11. Click **Accept** or **Save** at the bottom of the page to apply the changes.
12. Navigate to **Manage > System Setup > Time**.
13. Under "Display Time Zone", select the option **Display UTC in logs (instead of local time)**.
14. Click **Accept** to save the time setting.

## Kibana set up steps

To set up the SonicWall Firewall integration in Kibana:

1.  In Kibana, navigate to **Integrations** > **SonicWall Firewall**.
2.  Click **Add SonicWall Firewall**.
3.  Follow the prompts to add the integration to an existing Elastic Agent policy or create a new one.

Depending on how you intend to collect logs from your SonicWall firewall, choose one of the following input types:

### Collecting logs via syslog

Use this input to receive real-time syslog messages directly from your SonicWall firewall.

1.  Select the **Collecting logs via syslog** input type.
2.  Configure the following input-specific fields:
    -   **Listen address**: `syslog_host` - Address where the Elastic Agent will accept syslog messages. Use `0.0.0.0` to receive syslog on all interfaces.
        *   _Default:_ `0.0.0.0`
    -   **Listen Port**: `syslog_port` - UDP Port where the Elastic Agent will receive syslog messages.
        *   _Default:_ `9514`
    -   **Custom UDP Options**: `udp_options` - Specify custom configuration options for the UDP input. This can be used for advanced tuning of the UDP listener, such as buffer sizes or timeouts.
        *   _Default:_ `#read_buffer: 100MiB
#max_message_size: 50KiB
#timeout: 300s
`
3.  Configure these general integration settings (available across all input types):
    -   **Timezone Offset**: `tz_offset` - By default, datetimes in the logs will be interpreted as relative to the timezone configured in the host where the agent is running. If ingesting logs from a host on a different timezone (e.g., if you did not enable UTC on the firewall), use this field to set the timezone offset so that datetimes are correctly parsed. Acceptable timezone formats are: a canonical ID (e.g., "Europe/Amsterdam"), abbreviated (e.g., "EST") or an HH:mm differential (e.g., "-05:00") from UTC.
        *   _Default:_ `local`
    -   **Preserve original event**: `preserve_original_event` - If enabled, preserves a raw copy of the original event, added to the field `event.original`. This can be useful for debugging or auditing.
        *   _Default:_ `false`
4.  Save the integration. The Elastic Agent will automatically update its configuration.

### Collecting logs from file

Use this input to collect logs directly from specified file paths on the host where the Elastic Agent is running. This is useful when syslog forwarding is not preferred or supplemental log collection is needed from local files.

1.  Select the **Collecting logs from file** input type.
2.  Configure the following input-specific fields:
    -   **Paths**: `paths` - A list of file paths to monitor for new log entries. The Elastic Agent will read new lines appended to these files.
        *   _Default:_ `['/var/log/sonicwall-firewall.log']`
3.  Configure these general integration settings (available across all input types):
    -   **Timezone Offset**: `tz_offset` - By default, datetimes in the logs will be interpreted as relative to the timezone configured in the host where the agent is running. If ingesting logs from a host on a different timezone, use this field to set the timezone offset so that datetimes are correctly parsed. Acceptable timezone formats are: a canonical ID (e.g., "Europe/Amsterdam"), abbreviated (e.g., "EST") or an HH:mm differential (e.g., "-05:00") from UTC.
        *   _Default:_ `local`
    -   **Preserve original event**: `preserve_original_event` - If enabled, preserves a raw copy of the original event, added to the field `event.original`. This can be useful for debugging or auditing.
        *   _Default:_ `false`
4.  Save the integration. The Elastic Agent will automatically update its configuration.

# Validation Steps

After configuration is complete, follow these steps to verify data is flowing correctly from SonicWall Firewall to the Elastic Stack.

### 1. Trigger Data Flow on SonicWall Firewall:
1.  **Generate network traffic:** From a client behind the firewall, browse several websites (e.g., google.com, example.com) to generate firewall access rule logs.
2.  **Attempt a denied connection:** Try to access a blocked website or service to generate a firewall denial event.
3.  **Log in/out of the firewall:** Log out and then log back into the SonicWall administrative interface to generate authentication and administration logs.
4.  **Change a minor setting:** Navigate to a simple setting (e.g., `Device > Settings > Time`), change a non-critical option (if available, then revert), and click `Accept` to trigger a configuration audit log.

### 2. Check Data in Kibana:
1.  Navigate to **Analytics > Discover**.
2.  Select the `logs-*` data view or the specific integration data view.
3.  Enter the following KQL filter: `data_stream.dataset : "sonicwall_firewall.log"`
4.  Verify logs appear in the results. Expand a log entry and confirm these fields are populated:
    -   `event.dataset` (should be `sonicwall_firewall.log`)
    -   `source.ip` and/or `destination.ip` (for network-related events)
    -   `event.action` or `event.outcome` (for security events)
    -   `observer.name` (should reflect the Syslog ID configured on the firewall, e.g., `firewall`)
    -   `message` (containing the raw log payload)
    -   `sonicwall_firewall.mnemonic` (for specific SonicWall event mnemonics)
5.  Navigate to **Analytics > Dashboards** and search for "SonicWall Firewall" to view pre-built visualizations.

# Troubleshooting

## Common Configuration Issues

-   **Incorrect Syslog Format**:
    -   **Cause**: The SonicWall firewall is not configured to send logs in "Enhanced Syslog" format, which is required by this integration for proper parsing.
    -   **Solution**: Log in to the SonicWall admin interface, navigate to **Device > Log > Syslog**, and ensure that the "Syslog Format" for your configured Syslog server is set to **Enhanced Syslog**.
-   **Timezone Mismatch**:
    -   **Cause**: If the SonicWall firewall is sending logs with local time instead of UTC, and the integration's `Timezone Offset` is not configured, timestamps will be parsed incorrectly, leading to logs appearing at the wrong time in Kibana.
    -   **Solution**: It is highly recommended to enable **Display UTC in logs (instead of local time)** under the SonicWall's *Device > Settings > Time* menu. If this is not possible, ensure you configure the `Timezone Offset` setting in the Elastic Agent's SonicWall Firewall integration to match the firewall's local timezone.
-   **Network Connectivity Problems**:
    -   **Cause**: The SonicWall firewall cannot reach the Elastic Agent's IP address and UDP port, or network devices (e.g., firewalls) between them are blocking the traffic.
    -   **Solution**:
        1.  Verify the IP address and port configured on the SonicWall Syslog server match the `syslog_host` and `syslog_port` settings in the Elastic Agent integration.
        2.  Check network connectivity using tools like `ping` or `telnet` (if a TCP listener were available for testing, though Syslog is UDP) from the SonicWall's network to the Elastic Agent's IP address.
        3.  Ensure that no network firewalls (including host-based firewalls on the Agent machine) are blocking UDP traffic on the specified port.
-   **Logs Not Enabled for Categories**:
    -   **Cause**: Even if the Syslog server is configured, specific log categories on the SonicWall firewall may not have Syslog forwarding enabled, preventing certain types of events from being sent.
    -   **Solution**: Navigate to **Log > Settings** (or **Base Setup**) in the SonicWall admin interface. Review the logging categories and ensure that the **Syslog** checkbox is selected for all desired event categories.

## Ingestion Errors

-   **Parsing Failures in Kibana**:
    -   **Cause**: Malformed syslog messages from the SonicWall firewall or unexpected log formats not covered by the integration's parsing rules. This can sometimes happen with custom log configurations or unsupported message types.
    -   **Solution**:
        1.  In Kibana Discover, filter for logs with `error.message` fields or `_ingest.pipeline.grok_parse_failure` tags.
        2.  Examine the `message` field of these failed events to understand the raw log content. Compare it against the expected Enhanced Syslog format from the SonicWall documentation.
        3.  Ensure the SonicWall is configured to send `Enhanced Syslog` as specified in the `Vendor Set Up Steps`.

## Vendor Resources

-   [SonicOS 6.5.4 Log Events Reference Guide](https://www.sonicwall.com/techdocs/pdf/sonicos-6-5-4-log-events-reference-guide.pdf) - A comprehensive guide detailing log events for SonicOS 6.5.4.

# Documentation sites

-   [SonicOS 6.5.4 Log Events Reference Guide](https://www.sonicwall.com/techdocs/pdf/sonicos-6-5-4-log-events-reference-guide.pdf)
