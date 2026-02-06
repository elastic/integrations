# Service Info

## Common use cases

The QNAP NAS integration facilitates the collection and analysis of Event and Access logs from QNAP NAS devices, enhancing security posture and operational visibility.
- **Security Monitoring:** Monitor for unauthorized access attempts, failed logins, successful user authentications, and changes to user permissions, aiding in the detection of malicious activity and insider threats.
- **Operational Insight:** Track critical system events such as device reboots, firmware updates, service starts/stops, and storage volume health, providing administrators with a clear view of device operational status and potential issues.
- **Compliance Auditing:** Maintain a comprehensive and immutable record of system and user activities on the QNAP NAS, crucial for meeting regulatory compliance requirements and internal auditing processes.
- **Troubleshooting and Diagnostics:** Utilize detailed event and access logs to diagnose system problems, identify performance bottlenecks, and resolve configuration issues affecting the NAS device and its users.

## Data types collected

This integration can collect the following types of data:
- **QNAP NAS logs (TCP)**: This data stream collects QNAP NAS Event and Access logs using the TCP protocol. It processes logs formatted according to RFC-3164, providing detailed records of system events and user activities.
- **QNAP NAS logs (UDP)**: This data stream collects QNAP NAS Event and Access logs using the UDP protocol. It also processes RFC-3164 formatted logs, offering an alternative for collecting event and access data.

## Compatibility

This integration has been tested against **QNAP NAS** QTS 4.5.4 and is expected to work with versions later than QTS 4.5.4. It is only compatible with logs sent using the "Send to Syslog Server" option, which uses the RFC-3164 syslog format.

## Scaling and Performance

-   **Transport/Collection Considerations**: For QNAP NAS syslog collection, consider the trade-offs between UDP and TCP. UDP offers faster, connectionless transmission, which can be suitable for high-volume, less critical logs where occasional packet loss is acceptable. TCP provides reliable, ordered delivery, ensuring all logs are received, which is preferred for critical security and audit events, though it introduces more overhead. TLS can be used with TCP for encrypted transport, adding security but increasing processing load.
-   **Data Volume Management**: To optimize performance and reduce data volume, configure the QNAP NAS device in the QuLog Center to send only the necessary log types (Event Log and Access Log). Avoid sending unnecessary log categories if available. High log volumes at the source could impact the NAS device's performance, so careful selection of forwarded logs is recommended.
-   **Elastic Agent Scaling**: A single Elastic Agent can handle a significant volume of syslog traffic, but for very high-throughput QNAP NAS environments or multiple NAS devices, consider deploying multiple Elastic Agents. Distribute the log forwarding across several Agents, each listening on a unique port or IP, to balance the load. Ensure the host running the Elastic Agent has sufficient CPU, memory, and disk I/O resources to process and forward the logs efficiently.

# Set Up Instructions

## Vendor prerequisites

-   **Administrative Access:** Full administrator access to the QNAP QTS web administration interface is required to configure log forwarding using the QuLog Center.
-   **QuLog Center Application:** The QuLog Center application must be installed on your QNAP NAS. If not present, it can be installed from the App Center.
-   **Network Connectivity:** The QNAP NAS must have network connectivity to the Elastic Agent host on the chosen protocol (TCP, UDP, or TLS) and port (for example, `9301`). Ensure no firewalls are blocking communication between the NAS and the Agent.
-   **Elastic Agent Host IP Address:** You will need the IP address of the server where the Elastic Agent is running to configure it as the syslog server destination on the QNAP NAS.
-   **Protocol and Port Selection:** Decide whether to use TCP, UDP, or TLS for syslog communication and the specific port number the Elastic Agent will listen on. This choice must match the configuration on both the QNAP NAS and the Elastic Agent.

## Elastic prerequisites

-   **Elastic Agent Installation and Enrollment:** An Elastic Agent must be installed and successfully enrolled in Fleet, connected to your Elastic Stack instance.
-   **Network Connectivity:** The Elastic Agent host must be reachable from the QNAP NAS on the configured syslog port (for example, `9301`) and protocol (TCP, UDP, or TLS). Ensure that any host-based firewalls on the Elastic Agent server or network firewalls allow inbound connections on the specified port.
-   **Elastic Stack Version:** Your Elastic Stack (Elasticsearch and Kibana) should be compatible with the version of the Elastic Agent you are using.

## Vendor set up steps

### For Syslog Collection:
1.  Log in to your QNAP QTS web administration interface using an administrator account.
2.  Open the **QuLog Center** application. If it's not installed, navigate to the **App Center** and install it.
3.  In QuLog Center, navigate to **QuLog Service** using the left-hand menu.
4.  Click on the **Log Sender** tab to manage log forwarding settings.
5.  Select the checkbox next to **Send logs to a syslog server** to enable the log forwarding service.
6.  Click **Add a log sending rule** to initiate the configuration of a new syslog destination for the Elastic Agent.
7.  In the rule creation window, configure the following settings:
    *   **Server**: Enter the IP address of the server where your Elastic Agent is running.
    *   **Protocol**: Choose the protocol (`UDP`, `TCP`, or `TLS`) that precisely matches the syslog input configuration of your Elastic Agent.
    *   **Port**: Specify the port number (for example, `9301`) that your Elastic Agent is configured to listen on for syslog messages.
    *   **Log Format**: Select `RFC-3164` as the log format. This is critical for the integration to correctly parse the logs.
8.  Under "Log Type", choose the types of logs you wish to send. It is recommended to select both **Event Log** and **Access Log** for comprehensive monitoring.
9.  Click the **Test** button to send a test message from the QNAP NAS to the configured Elastic Agent. Verify that the connection is successful.
10. If the test is successful, click **Apply** to save the log sending rule.

Your QNAP NAS will now begin forwarding the selected Event and Access logs to the Elastic Agent.

### Vendor Set up Resources

-   [QNAP QTS 5.0.x User Manual](https://docs.qnap.com/operating-system/qts/5.0.x/en-us/configuring-samba-microsoft-networking-settings-7447174D.html) - Provides a general user manual for QNAP QTS 5.0.x, which includes information on system configuration.

## Kibana set up steps

1.  In Kibana, navigate to **Integrations**.
2.  Search for "QNAP NAS" and click on the integration.
3.  Click **Add QNAP NAS**.
4.  Follow the prompts to add the integration to an existing Elastic Agent policy or create a new one.
5.  Based on your QNAP NAS syslog configuration, select the appropriate input type.

### Collecting logs from QNAP NAS using TCP
1. Select the **Collecting logs from QNAP NAS using TCP** input type.
2. Configure the following fields:
   - **Syslog Host**: The host address to listen on for syslog messages. Default: `localhost`.
   - **Syslog Port**: The port number to listen on for syslog messages. Default: `9301`.
   - **Timezone Offset**: By default, datetimes in the logs will be interpreted as relative to the timezone configured in the host where the agent is running. If ingesting logs from a host on a different timezone, use this field to set the timezone offset so that datetimes are correctly parsed. Acceptable timezone formats are: a canonical ID (for example "Europe/Amsterdam"), abbreviated (for example "EST") or an HH:mm differential (for example "-05:00") from UCT. Default: `local`.
   - **SSL Configuration**: SSL configuration options. See [documentation](https://www.elastic.co/guide/en/beats/filebeat/current/configuration-ssl.html#ssl-common-config) for details.
   - **Preserve original event**: Preserves a raw copy of the original event, added to the field `event.original`. Default: `False`.
   - **Tags**: Default: `['qnap-nas', 'forwarded']`.
   - **Processors**: Processors are used to reduce the number of fields in the exported event or to enhance the event with metadata. This executes in the agent before the logs are parsed. See [Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details.
3. Review any additional settings if needed.

### Collecting logs from QNAP NAS using UDP
1. Select the **Collecting logs from QNAP NAS using UDP** input type.
2. Configure the following fields:
   - **Syslog Host**: The host address to listen on for syslog messages. Default: `localhost`.
   - **Syslog Port**: The port number to listen on for syslog messages. Default: `9301`.
   - **Timezone Offset**: By default, datetimes in the logs will be interpreted as relative to the timezone configured in the host where the agent is running. If ingesting logs from a host on a different timezone, use this field to set the timezone offset so that datetimes are correctly parsed. Acceptable timezone formats are: a canonical ID (for example "Europe/Amsterdam"), abbreviated (for example "EST") or an HH:mm differential (for example "-05:00") from UCT. Default: `local`.
   - **Preserve original event**: Preserves a raw copy of the original event, added to the field `event.original`. Default: `False`.
   - **Tags**: Default: `['qnap-nas', 'forwarded']`.
   - **Custom UDP Options**: Specify custom configuration options for the UDP input. Default: `#read_buffer: 100MiB
#max_message_size: 50KiB
#timeout: 300s`.
   - **Processors**: Processors are used to reduce the number of fields in the exported event or to enhance the event with metadata. This executes in the agent before the logs are parsed. See [Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details.
3. Review any additional settings if needed.
4. Click **Save and Deploy**. The Elastic Agent will automatically update its configuration.

# Validation Steps

After configuration is complete, follow these steps to verify data is flowing correctly from QNAP NAS to the Elastic Stack.

### 1. Trigger Data Flow on QNAP NAS:
To generate test events, perform a few common administrative or user actions on your QNAP NAS:
-   **Log In/Out:** Log out of the QNAP QTS web administration interface and then log back in. This will generate authentication-related event logs.
-   **Create/Delete a File:** Access a shared folder on your QNAP NAS and create a new file or delete an existing one. This will generate access logs.
-   **Change a System Setting:** Navigate to a system setting (for example, Date & Time, Network settings) and make a minor change, then apply it. This should trigger an event log related to configuration changes.
-   **Access a Shared Folder:** Access a shared folder from a client device (for example, using SMB/CIFS or NFS) to generate additional access logs.

### 2. Check Data in Kibana:
1.  Navigate to **Analytics > Discover**.
2.  Select the `logs-*` data view.
3.  Enter the following KQL filter: `data_stream.dataset : "qnap_nas.log"`
4.  Verify logs appear in the results. Expand a log entry and confirm these fields are populated:
    -   `event.dataset` (should be `qnap_nas.log`)
    -   `source.ip` (IP address of the QNAP NAS)
    -   `event.action` or `event.outcome` (for example, login success/failure, file access)
    -   `qnap_nas.mnemonic` (a short code representing the event type)
    -   `message` (containing the raw log payload from the QNAP NAS)
5.  Navigate to **Analytics > Dashboards** and search for "QNAP NAS" to view pre-built visualizations.

# Troubleshooting

## Common Configuration Issues

-   **No logs appearing in Kibana**:
    -   **Cause**: This is often due to incorrect IP address, port, or protocol configuration between the QNAP NAS and the Elastic Agent.
    -   **Solution**:
        1.  Verify the **Server IP address** configured in the QNAP QuLog Center's "Send to Syslog Server" tab matches the IP address of the Elastic Agent host.
        2.  Ensure the **Port** number in the QNAP configuration matches the `syslog_port` configured in your Elastic Agent's QNAP NAS integration input (default is 9301).
        3.  Confirm the **Protocol** (UDP, TCP, or TLS) configured on the QNAP NAS matches the input type (TCP or UDP) selected in the Elastic Agent integration.
        4.  Check firewall rules on both the QNAP NAS and the Elastic Agent host to ensure the configured port is open for inbound traffic to the Agent.
        5.  Use a network utility like `netcat` or `tcpdump` on the Elastic Agent host to verify it is receiving traffic on the specified port. For example, `tcpdump -i any port 9301` to check for incoming packets.

-   **Logs are present but unparsed or missing fields**:
    -   **Cause**: This usually indicates that the logs are not in the expected RFC-3164 syslog format, or there's an issue with the parsing rules.
    -   **Solution**:
        1.  In the QNAP QuLog Center, verify that the **Format** option under "Send to Syslog Server" is set to **RFC 3164**. Other formats are not supported by this integration.
        2.  Check the `error.message` field in Kibana's Discover for relevant parsing errors if `preserve_original_event` is enabled.
        3.  Ensure the `Timezone Offset` setting in the Elastic Agent's integration configuration is correct if the QNAP NAS is in a different timezone than the Elastic Agent host. An incorrect offset can lead to timestamp parsing issues.

## Ingestion Errors

-   **Parsing Failures or Missing Fields**:
    -   **Cause**: Logs are being received by the Elastic Agent, but the integration is failing to parse them correctly, leading to missing or malformed fields in Kibana. This can occur if the log format deviates unexpectedly from RFC-3164 or contains non-standard elements.
    -   **Solution**:
        1.  In Kibana Discover, filter for logs from `qnap_nas.log` and inspect documents that have an `error.message` field or where expected fields are missing.
        2.  If you enabled `preserve_original_event`, check the `event.original` field to view the raw log received by the agent. Compare it against the expected RFC-3164 format.
        3.  Ensure the `Timezone Offset` setting in the Elastic Agent input configuration is correct if the QNAP NAS is in a different timezone than the Agent. Incorrect timezone settings can lead to parsing issues for timestamps.

## Vendor Resources

-   [QNAP NAS Official Website](https://qnap.com) - General information about QNAP NAS products and solutions.

# Documentation sites

-   [QNAP NAS Official Website](https://qnap.com) - Official website for QNAP NAS products.
