# Service Info

## Common use cases

The Cisco ISE integration collects and parses security and operational data from Cisco Identity Services Engine using Syslog, enabling centralized monitoring and analysis of network access, authentication, and accounting events within the Elastic Stack.

-   **Monitor Authentication and Authorization Events:** Track successful and failed authentication attempts, authorization policies applied, and user access details to identify potential security breaches or policy violations.
-   **Analyze Network Access Behavior:** Gain insights into who is accessing the network, from where, and with what devices, by collecting detailed accounting data from Cisco ISE.
-   **Troubleshoot Network Connectivity Issues:** Utilize detailed system and operational logs to diagnose problems related to network access, policy enforcement, or RADIUS server communication.
-   **Ensure Compliance and Auditability:** Maintain a comprehensive audit trail of all network access activities, user authentications, and policy changes to meet regulatory compliance requirements.

## Data types collected

This integration can collect the following types of data:
- **Cisco_ISE logs** (type: logs, input: tcp): Collect Cisco ISE logs by TCP input. This datastream includes authentication, authorization, accounting (AAA) events, system messages, and policy-related logs.
- **Cisco_ISE logs** (type: logs, input: udp): Collect Cisco ISE logs by UDP input. This datastream includes authentication, authorization, accounting (AAA) events, system messages, and policy-related logs.
- **Cisco_ISE logs** (type: logs, input: filestream): Collect Cisco ISE logs by file input. This datastream collects logs from local files, typically used when direct syslog forwarding is not preferred or for ingesting historical data.

## Compatibility

This integration has been tested against and is compatible with **Cisco Identity Services Engine (ISE)** version 3.1.0.518 and above. It is recommended to use ISE version 3.1.0.518 or higher for full compatibility.

## Scaling and Performance

-   **Transport/Collection Considerations:** When configuring Syslog, choosing between TCP and UDP involves a trade-off. TCP (port `9025`) offers guaranteed delivery, ensuring no logs are lost, which is critical for security and compliance data. UDP (port `9026`) offers higher speed and lower overhead but does not guarantee delivery, making it suitable for less critical, high-volume log streams where some loss is acceptable. It is critical to set the Maximum Message Length in Cisco ISE to **`8192`** bytes to prevent log segmentation, which can lead to parsing issues and incorrect field mappings in Elastic Agent.
-   **Data Volume Management:** Cisco ISE can generate a significant volume of logs depending on network activity and configured policies. To manage data volume efficiently, it is recommended to carefully select which "Logging Categories" in Cisco ISE are forwarded to the Elastic Agent. Prioritize critical categories such as `Passed Authentications`, `Failed Attempts`, and `Radius Accounting`. Filtering at the source reduces the load on both the Cisco ISE system and the Elastic Agent.
-   **Elastic Agent Scaling:** For environments with high log volumes, a single Elastic Agent might reach its capacity limits. In such scenarios, consider deploying multiple Elastic Agents, each configured to receive logs from different Cisco ISE logging targets or specific log categories. Place Elastic Agents strategically, ideally close to the Cisco ISE instances, to minimize network latency. Ensure the Elastic Agent host has adequate CPU, memory, and disk I/O resources to handle the anticipated log ingestion rate.

# Set Up Instructions

## Vendor prerequisites

-   **Administrative Access:** You must have administrative access to the Cisco ISE Administrator Portal to configure remote logging targets and logging categories.
-   **Network Connectivity:** Ensure network connectivity between your Cisco ISE deployment and the server hosting the Elastic Agent. Specifically, the Elastic Agent's listening port (e.g., TCP 9025, UDP 9026) must be reachable from the ISE appliance, and any firewalls in between must allow the specified protocol and port.
-   **Maximum Message Length:** Configure the Cisco ISE remote logging target with a Maximum Message Length of **8192** bytes. This is crucial to prevent log segmentation, which can lead to incorrect field mappings and parsing errors in Elasticsearch.
-   **Understanding Log Categories:** Familiarity with Cisco ISE's logging categories (e.g., Passed Authentications, Failed Attempts, RADIUS Accounting) is necessary to select and forward relevant log types.

## Elastic prerequisites

-   **Elastic Agent Deployment:** An Elastic Agent must be deployed and enrolled in Fleet.
-   **Input Configuration:** The Elastic Agent must have the TCP or UDP input enabled and configured with a listening port that matches the remote logging target settings in Cisco ISE (e.g., TCP: 9025, UDP: 9026).

## Vendor set up steps

### For Syslog (TCP/UDP) Collection:

Cisco ISE sends logs to external syslog servers by defining a "Remote Logging Target". This target specifies the destination server (Elastic Agent) and the protocol. After creating the target, you must assign it to the relevant log categories to start the log flow.

1.  Log in to your Cisco ISE Administration Interface.
2.  Navigate to **Administration > System > Logging > Remote Logging Targets**.
3.  Click **Add** to create a new logging destination.
4.  Configure the remote logging target with the following parameters:
    *   **Name**: Provide a descriptive name, for example, `elastic-agent-syslog`.
    *   **Target Type**: Select `TCP Syslog` or `UDP Syslog`. This protocol must match the input configuration of your Elastic Agent.
    *   **Status**: Ensure this is set to `Enabled`.
    *   **Host / IP Address**: Enter the IP address of the server where the Elastic Agent is running.
    *   **Port**: Enter the port number the Elastic Agent is configured to listen on. The recommended defaults are `9025` for TCP or `9026` for UDP.
    *   **Facility Code**: Choose a syslog facility code, such as `Local6` or `Local7`.
    *   **Maximum Length**: **CRITICAL** - Set this value to `8192` bytes to prevent log messages from being truncated, which can lead to parsing errors.
5.  Click **Save** to create the target. Acknowledge any warning about creating an unsecure (TCP/UDP) connection if it appears.
6.  Next, assign the new target to the log categories you wish to export. Navigate to **Administration > System > Logging > Logging Categories**.
7.  For each category you want to forward, select it from the list (for example, `Passed Authentications`, `Failed Attempts`, `Radius Accounting`).
8.  In the edit view for the category, find the **Targets** section.
9.  Move your newly created target (e.g., `elastic-agent-syslog`) from the **Available** list to the **Selected** list using the arrow icon.
10. Click **Save** for that category.
11. Repeat steps 7-10 for all other log categories you wish to send to the Elastic Agent.

### For Logfile Collection:

If direct Syslog forwarding is not feasible or desired, logs can be collected from local files on the Cisco ISE system (if available for direct agent access).

1.  Identify the specific log file paths on your Cisco ISE deployment that contain the desired log events. Common paths may include `/var/log/cisco_ise*`.
2.  Ensure that the Elastic Agent has sufficient read permissions to access these log files.
3.  Configure log rotation settings on Cisco ISE to prevent excessive disk usage and ensure that new log data is always written to files monitored by the agent.

## Vendor Set up Resources

-   [Configure External Syslog Server On Ise.Html](https://www.cisco.com/c/en/us/support/docs/security/identity-services-engine/222223-configure-external-syslog-server-on-ise.html) - This document provides detailed steps on how to configure an external syslog server on Cisco ISE.
-   [B Ise Admin 31 Deployment.Html](https://www.cisco.com/c/en/us/td/docs/security/ise/3-1/admin_guide/b_ise_admin_3_1/b_ISE_admin_31_deployment.html) - This is a section from the Cisco ISE 3.1 Administration Guide covering deployment topics.

## Kibana set up steps

1. In Kibana, navigate to **Integrations**.
2. Search for "Cisco ISE" and click on the integration.
3. Click **Add Cisco ISE**.
4. Follow the prompts to add the integration to an existing Elastic Agent policy or create a new one.
5. Choose your desired input type based on how Cisco ISE is configured to send logs, and configure the following fields:

### Collecting Cisco ISE logs by TCP input
To collect logs by TCP, configure the following:
-   **Listen Address** (`listen_address`): The bind address to listen for TCP connections. Set to `0.0.0.0` to bind to all available interfaces. Default: `localhost`.
-   **Listen Port** (`listen_port`): The TCP port number to listen on. Default: `9025`.
-   **Preserve original event** (`preserve_original_event`): Preserves a raw copy of the original event, added to the field `event.original`. Default: `False`.
-   **Timezone Offset** (`tz_offset`): When interpreting syslog timestamps without a time zone, use this timezone offset. Datetimes recorded in logs are by default interpreted in relation to the timezone set up on the host where the agent is operating. Use this parameter to adjust the timezone offset when importing logs from a host in a different timezone so that datetimes are appropriately interpreted. Both a canonical ID (such as "Europe/Amsterdam") and an HH:mm differential (such as "-05:00") are acceptable timezone formats.
-   **Tags** (`tags`): Default: `['forwarded', 'cisco_ise-log']`.
-   **Processors** (`processors`): Processors are used to reduce the number of fields in the exported event or to enhance the event with metadata. This executes in the agent before the logs are parsed. See [Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details.

### Collecting Cisco ISE logs by UDP input
To collect logs by UDP, configure the following:
-   **Listen Address** (`listen_address`): The bind address to listen for UDP connections. Set to `0.0.0.0` to bind to all available interfaces. Default: `localhost`.
-   **Listen Port** (`listen_port`): The UDP port number to listen on. Default: `9026`.
-   **Preserve original event** (`preserve_original_event`): Preserves a raw copy of the original event, added to the field `event.original`. Default: `False`.
-   **Timezone Offset** (`tz_offset`): When interpreting syslog timestamps without a time zone, use this timezone offset. Datetimes recorded in logs are by default interpreted in relation to the timezone set up on the host where the agent is operating. Use this parameter to adjust the timezone offset when importing logs from a host in a different timezone so that datetimes are appropriately interpreted. Both a canonical ID (such as "Europe/Amsterdam") and an HH:mm differential (such as "-05:00") are acceptable timezone formats.
-   **Tags** (`tags`): Default: `['forwarded', 'cisco_ise-log']`.
-   **Custom UDP Options** (`udp_options`): Specify custom configuration options for the UDP input. Default: `#read_buffer: 100MiB
#max_message_size: 50KiB
#timeout: 300s
`.
-   **Processors** (`processors`): Processors are used to reduce the number of fields in the exported event or to enhance the event with metadata. This executes in the agent before the logs are parsed. See [Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details.

### Collecting Cisco ISE logs using filestream input
To collect logs from local files, configure the following:
-   **Paths** (`paths`): Default: `['/var/log/cisco_ise*']`.
-   **Preserve original event** (`preserve_original_event`): Preserves a raw copy of the original event, added to the field `event.original`. Default: `False`.
-   **Timezone Offset** (`tz_offset`): When interpreting syslog timestamps without a time zone, use this timezone offset. Datetimes recorded in logs are by default interpreted in relation to the timezone set up on the host where the agent is operating. Use this parameter to adjust the timezone offset when importing logs from a host in a different timezone so that datetimes are appropriately interpreted. Both a canonical ID (such as "Europe/Amsterdam") and an HH:mm differential (such as "-05:00") are acceptable timezone formats.
-   **Tags** (`tags`): Default: `['forwarded', 'cisco_ise-log']`.
-   **Processors** (`processors`): Processors are used to reduce the number of fields in the exported event or to enhance the event with metadata. This executes in the agent before the logs are parsed. See [Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details.

6. Save the integration. The Elastic Agent will automatically update its configuration.

# Validation Steps

After configuration is complete, follow these steps to verify data is flowing correctly from Cisco ISE to the Elastic Stack.

### 1. Trigger Data Flow on Cisco ISE:
1.  **Generate a successful authentication event:** Authenticate a test user or device against Cisco ISE. For example, log in to a network device or wireless network controlled by ISE.
2.  **Generate a failed authentication event:** Attempt to log in with incorrect credentials for a test user or device.
3.  **Perform an administrative action:** Log in to the Cisco ISE Administrator Portal and make a minor configuration change, then save it (e.g., enable/disable a logging category, then revert the change).
4.  **Initiate a RADIUS accounting session:** If applicable, connect a device that generates RADIUS accounting start/stop messages using ISE.

### 2. Check Data in Kibana:
1.  Navigate to **Analytics > Discover**.
2.  Select the `logs-*` data view.
3.  Enter the following KQL filter: `data_stream.dataset : "cisco_ise.log"`
4.  Verify logs appear in the results. Expand a log entry and confirm these fields are populated:
    -   `event.dataset` (should be `cisco_ise.log`)
    -   `source.ip` and `destination.ip`
    -   `event.action` or `event.outcome`
    -   `cisco_ise.event_id` or `cisco_ise.message_code` (for specific ISE event identification)
    -   `message` (containing the raw log payload)
    -   `user.name` (for authentication events)
5.  Navigate to **Analytics > Dashboards** and search for "Cisco ISE" to view pre-built visualizations.

# Troubleshooting

## Common Configuration Issues

-   **Maximum Message Length Not Set to 8192**:
    -   **Cause**: If the Maximum Length is not set to `8192` in the Cisco ISE remote logging target configuration, syslog messages may be truncated before being sent to the Elastic Agent. This can lead to incomplete log entries and parsing failures, resulting in missing fields or malformed events in Kibana.
    -   **Solution**: Log in to the Cisco ISE Administrator Portal, navigate to **Administration > System > Logging > Remote Logging Targets**, edit the target configured for Elastic Agent, and ensure the **Maximum Length** field is set to `8192`.
-   **Port or Protocol Mismatch**:
    -   **Cause**: The Elastic Agent might be configured to listen on a different port or protocol (TCP/UDP) than what Cisco ISE is sending logs to. This will prevent any logs from being received by the Agent.
    -   **Solution**: Verify the **Target Type** (TCP/UDP Syslog) and **Port** configured in the Cisco ISE remote logging target (under **Administration > System > Logging > Remote Logging Targets**) matches the input type and port configured for the Cisco ISE integration in Kibana. For example, if Cisco ISE is sending to UDP port 9026, the Elastic Agent integration must be configured for UDP input on port 9026.
-   **Network Connectivity Issues**:
    -   **Cause**: Firewalls (host-based or network), routing issues, or incorrect IP address/hostname configuration can prevent Cisco ISE from reaching the Elastic Agent's listening port.
    -   **Solution**:
        -   Verify the **IP Address / Hostname** of the Elastic Agent host is correctly entered in the Cisco ISE remote logging target.
        -   Check firewall rules on both the Cisco ISE server and the Elastic Agent host to ensure the configured syslog port (for example, 9025 TCP, 9026 UDP) is open and accessible.
        -   Perform network tests (for example, `ping`, `telnet` to the syslog port from Cisco ISE CLI) to confirm connectivity.
-   **Logging Categories Not Enabled**:
    -   **Cause**: Even if a remote logging target is configured, Cisco ISE will not send logs unless specific logging categories (e.g., `Passed Authentications`, `Failed Attempts`) are explicitly assigned to that target.
    -   **Solution**: Navigate to **Administration > System > Logging > Logging Categories** in the Cisco ISE Administrator Portal. For each desired log category, ensure your `elastic-agent-syslog` target is selected in the "Remote Logging Targets" list for that category.

## Ingestion Errors

-   **Parsing Failures Due to Malformed Logs**:
    -   **Cause**: Cisco ISE logs that are segmented (due to incorrect `Maximum Length` setting) or contain unexpected characters/formats can lead to parsing errors within the Elastic Agent, causing fields to be unpopulated or events to be dropped.
    -   **Solution**: Review the raw logs in Kibana (check the `event.original` field if `preserve_original_event` is enabled, or the `message` field). Look for `_grokparsefailure` tags or errors in the `error.message` field. Ensure the `Maximum Length` in Cisco ISE is set to `8192`. If issues persist, refer to the Cisco ISE Syslog documentation for expected log formats and compare them against the ingested data.

## Vendor Resources

- [Official Cisco ISE Syslog Documentation](https://www.cisco.com/c/en/us/td/docs/security/ise/syslog/Cisco_ISE_Syslogs/m_SyslogsList.html) - This page provides detailed information about Cisco ISE syslog messages.

# Documentation sites

-   [Cisco ISE Syslogs Reference Guide](https://www.cisco.com/c/en/us/td/docs/security/ise/syslog/Cisco_ISE_Syslogs/m_SyslogsList.html)
-   [Official Cisco ISE Product Page](https://www.cisco.com/site/us/en/products/security/identity-services-engine/index.html)
