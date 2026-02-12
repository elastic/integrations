# Service Info

## Common use cases
The Custom UDP Logs integration acts as a generic network data collector, allowing the Elastic Agent to serve as a high-performance UDP server. This integration is designed for environments where data sources do not support TCP or where the overhead of a connection-oriented protocol is undesirable.
- **Legacy Network Gear Ingestion:** Capture logs from older switches, routers, and firewalls that only support standard UDP syslog (RFC 3164) exports.
- **Custom Application Telemetry:** Collect real-time metrics and event data from bespoke applications that broadcast performance statistics via UDP packets to minimize application latency.
- **High-Volume Log Centralization:** Efficiently aggregate large volumes of unstructured or semi-structured data across the network before routing them to Elasticsearch for analysis.
- **Security Monitoring:** Ingest CEF or JSON formatted security events from third-party appliances that utilize UDP for rapid data transmission.

## Data types collected
This integration can collect the following types of data by listening on a specified network port and ingesting the payload of each received packet:
- **Syslog Data:** Automatic parsing is available for logs following RFC 3164 and RFC 5424 standards, commonly used by Linux systems and network appliances.
- **Generic Log Events:** Any raw text-based or binary data sent over UDP is captured and stored in the `message` field.
- **Security Events:** Formats such as Common Event Format (CEF) or JSON-encoded security logs can be ingested and processed via custom pipelines.
- **Network Traffic Metadata:** Information regarding the source IP and port of the incoming traffic is automatically appended to each event.

The following data stream is available:
- **udp.generic (logs):** This is the default data stream used to collect and index all incoming UDP traffic as log documents.

## Compatibility
The **Custom UDP Logs** integration is a protocol-based listener and is compatible with any third-party vendor, hardware appliance, or software application capable of transmitting data via the **User Datagram Protocol (UDP)**. This includes but is not limited to:
- **Network Appliances:** Cisco IOS/NX-OS, Juniper Junos, Fortinet FortiOS, and Check Point Gaia.
- **Operating Systems:** Linux (via rsyslog or syslog-ng), Windows (via event-to-syslog agents), and macOS.
- **Standard Protocols:** Support for RFC 3164 (BSD Syslog) and RFC 5424 (IETF Syslog) message formats.

## Scaling and Performance
- **Transport/Collection Considerations:** UDP is a connectionless protocol, which offers lower latency and less overhead than TCP, making it ideal for high-throughput logging. However, because it lacks delivery guarantees, packets may be dropped during periods of extreme network congestion or if the Elastic Agent's read buffer is overwhelmed. Users should consider increasing the **Read Buffer Size** in the integration settings to mitigate packet loss during traffic bursts.
- **Data Volume Management:** To prevent overwhelming the Elastic Stack, it is recommended to filter logs at the source device whenever possible. Limit exports to specific severity levels (e.g., Warning and above) or specific facilities. If high volumes are unavoidable, use the **Processors** configuration within the integration to drop irrelevant events at the Agent level before they are transmitted to Elasticsearch.
- **Elastic Agent Scaling:** For high-traffic environments (e.g., >10,000 events per second), a single Elastic Agent may become a bottleneck. In such cases, deploy multiple Elastic Agents across different hosts and use a network load balancer to distribute the incoming UDP traffic. Ensure the host machine has sufficient CPU resources to handle the context switching required for high-speed packet processing.

# Set Up Instructions

## Vendor prerequisites
Before configuring the integration, ensure the following requirements are met on the source device or application:
- **Administrative Access:** You must have permission to modify the logging or telemetry export configuration on the device sending the logs.
- **Network Connectivity:** Unrestricted UDP traffic flow must be allowed from the source device's IP address to the Elastic Agent's IP address on the chosen port (e.g., 8080 or 514).
- **Protocol Knowledge:** Determine if the source device sends data in a specific format like RFC 5424, as this will impact whether you enable the Syslog Parsing toggle.
- **Firewall Rules:** Any intermediate firewalls or host-based firewalls (like iptables or Windows Firewall) must be configured to allow inbound UDP traffic on the listener port.

## Elastic prerequisites
- **Elastic Agent Enrollment:** The Elastic Agent must be installed and successfully enrolled in a Fleet policy.
- **Privileged Access:** If you intend to use a privileged port below 1024 (such as UDP 514), the Elastic Agent service must be running with root or administrative privileges.

## Vendor set up steps
To begin ingesting data, you must configure your external devices to target the Elastic Agent.

### For Generic Network Devices (Syslog/UDP):
1. Log in to the management interface (CLI or Web UI) of your network appliance or server.
2. Navigate to the **System Logging**, **Remote Logging**, or **Telemetry** configuration section.
3. Add a new remote log destination or "syslog server" entry.
4. Set the **Destination IP Address** to the IP address of the host running the Elastic Agent.
5. Set the **Destination Port** to the port you plan to configure in Kibana (default is `8080`).
6. Set the **Protocol** to **UDP**.
7. If the device allows, select the log format. **RFC 5424** is preferred for better structured data, though **RFC 3164** is widely supported.
8. Specify the facility and severity levels you wish to export (e.g., `Local0`, `Notice`).
9. Save the configuration and, if necessary, restart the logging service on the device to initiate the stream.

### For Custom Applications:
1. Access the application's configuration file or environment variables.
2. Locate the logging output settings.
3. Configure the application to use a UDP appender or socket logger.
4. Point the appender to the Elastic Agent's host IP and the configured UDP port.
5. Ensure the message payload is sent as a single packet per log line to ensure correct indexing.

### Vendor Set up Resources
- Refer to the official vendor documentation for detailed configuration guides.

## Kibana set up steps

### Custom UDP Logs
1. Navigate to **Management > Integrations** in Kibana and search for **Custom UDP Logs**.
2. Click **Add Custom UDP Logs** to begin the configuration.
3. Configure the following fields:
   - **Listen Address**: The bind address for the UDP listener. Use `0.0.0.0` to listen on all network interfaces or `localhost` for local traffic only. Default: `localhost`.
   - **Listen Port**: The UDP port the agent will bind to. Default: `8080`.
   - **Syslog Parsing**: Toggle this to **On** to automatically parse RFC3164 and RFC5424 formatted messages.
   - **Max Message Size**: Define the maximum allowed size for a single UDP packet. Large packets exceeding this value will be truncated. Default: `10KiB`.
   - **Ingest Pipeline**: (Optional) Enter the ID of a custom ingest pipeline to process logs on the server side.
   - **Dataset Name**: Specify the dataset name, which determines the target index. Default: `udp.generic`.
   - **Read Buffer Size**: Configure the size of the operating system's UDP receive buffer (uses OS default if not specified).
   - **Preserve Original Event**: Enable this to store the raw, unmodified log in the `event.original` field.
   - **Timeout**: (Advanced) Set the read and write timeout for socket operations. Valid time units are ns, us, ms, s, m, h.
   - **Keep Null Values**: (Advanced) If enabled, fields with null values will be published in the output document. Default: disabled.
4. (Optional) In the **Processors** field, add YAML-formatted processors to drop, rename, or add fields at the Agent level.
5. Click **Save and Continue**, select the appropriate **Agent Policy**, and click **Save and deploy changes**.

# Validation Steps

### 1. Trigger Data Flow on [Vendor]:
To verify the integration is working, generate test traffic from a source device or a terminal:
- **Using Netcat (Linux/macOS):** Run the following command from a remote machine to send a test syslog message: `echo "<34>1 2023-10-11T10:30:00Z myhost.example.com test-app - - [test@1234 message=\"Hello Elastic\"] This is a test message" | nc -u -w1 <AGENT_IP> 8080`.
- **Using Logger (Linux):** Execute `logger -n <AGENT_IP> -P 8080 -d "Test UDP Log Entry"` to send a standard system log.
- **Generate Device Event:** Log out and log back into the web interface of your configured network switch to trigger an authentication event.

### 2. Check Data in Kibana:
1. Navigate to **Analytics > Discover**.
2. Select the `logs-*` data view.
3. Enter the following KQL filter: `data_stream.dataset : "udp.generic"`
4. Verify logs appear in the results table. Expand a recent log entry and confirm the following fields are populated:
   - `event.dataset`: This should be exactly `udp.generic`.
   - `source.ip`: This should contain the IP address of the device that sent the test message.
   - `message`: This should contain the raw text of your test log (e.g., "This is a test message").
   - `log.syslog.priority`: (If Syslog Parsing is enabled) Should show the numerical priority extracted from the header.
   - `event.original`: (If enabled) Should contain the full raw packet including syslog headers.
5. Navigate to **Analytics > Dashboards** and search for **UDP** to see any available generic dashboards or visualizations.

# Troubleshooting

## Common Configuration Issues
- **Permission Denied for Low Ports**: If you configure the integration to listen on a port below 1024 (e.g., 514) and the Agent fails to start, it is likely due to insufficient privileges. Resolve this by using a port above 1024 or running the Elastic Agent as a privileged user (root/administrator).
- **Address Already in Use**: If another service (like an existing rsyslog daemon) is already listening on the configured port, the Elastic Agent will fail to bind to the socket. Use `netstat -tuln | grep <PORT>` to identify conflicting services and stop them or change the port in the integration settings.
- **Firewall Blocking Traffic**: If the Agent is running but no data appears in Kibana, check the host firewall. Ensure that inbound UDP traffic is allowed on the listener port using `iptables -L` or `Get-NetFirewallRule`.
- **Listen Address Mismatch**: If **Listen Address** is set to `localhost`, the Agent will only accept traffic from its own machine. Ensure this is set to `0.0.0.0` to receive logs from external network devices.

## Ingestion Errors
- **Parsing Failures**: If logs appear in Kibana but are not correctly split into fields, ensure the **Syslog Parsing** toggle matches the format sent by the source. If the source uses a non-standard format, you may need to disable automatic parsing and use a custom **Ingest Pipeline** with a Grok processor.
- **Message Truncation**: If long log messages are being cut off, check the **Max Message Size** setting. Increase this value (e.g., to `64KiB`) if your source sends large jumbo frames or high-entropy JSON blobs.
- **Timestamp Mismatches**: If logs appear with the wrong time, check if the source device is using a different timezone than the Elastic Stack. Use an ingest pipeline to correct timezone offsets if the source does not provide UTC timestamps.

## Vendor Resources
Refer to the official vendor website for additional resources.

# Documentation sites
- Refer to the official vendor website for general documentation.
- Refer to the Elastic integration documentation for specific package details and field mappings.
