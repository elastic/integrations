# Service Info

The Custom TCP Logs integration allows the Elastic Agent to act as a dedicated listener on a network interface, capturing raw log data or structured syslog messages sent over the TCP protocol. This integration is highly flexible, serving as a generic entry point for any application, script, or hardware appliance that can output text-based data over a TCP socket, ensuring that even legacy or proprietary systems can be integrated into the Elastic Stack for centralized observability and security analysis.

## Common use cases
The Custom TCP Logs integration is designed to provide a versatile and robust mechanism for ingesting log data from any source capable of transmitting information over a TCP socket. This integration is particularly useful for legacy systems, custom applications, and network devices that do not have dedicated integrations but support standard TCP or Syslog delivery.
- **Custom Application Logging:** Directly stream application events from internal software to the Elastic Agent by configuring a TCP appender in the application's logging framework.
- **Legacy Syslog Ingestion:** Collect logs from older network hardware or Unix-based systems that use TCP-based syslog (RFC 3164 or RFC 5424) to ensure centralized visibility.
- **Centralized Log Aggregation:** Act as a middle-tier listener for log forwarders or custom scripts that aggregate data before sending it to the Elastic Stack for analysis.
- **Encrypted Data Ingestion:** Secure sensitive log transmissions from remote sites using the built-in SSL/TLS support, ensuring data integrity and confidentiality during transit.

## Data types collected

This integration can collect the following types of data:
- **Raw TCP Streams:** Any text-based data stream sent over a TCP connection, typically separated by newline characters or other delimiters.
- **Syslog Messages:** Structured messages following RFC 3164 or RFC 5424, which include metadata such as facility, severity, and timestamps.

The following data stream is available:
- **tcp.generic (logs):** This is the default data stream. It captures the raw message payload in the `message` field along with connection metadata such as `source.ip` and `source.port`. If Syslog parsing is enabled, additional ECS fields are populated from the syslog header.

## Compatibility

The **Custom TCP Logs** integration is compatible with any third-party software or hardware capable of establishing a TCP connection and transmitting text-based data.
- **Syslog Standards:** Supports devices compliant with **RFC 3164** (BSD syslog) and **RFC 5424** (The Syslog Protocol).
- **Framing Standards:** Supports **RFC 6587** for octet-counted framing, commonly used in high-reliability log transmission.
- **Encryption:** Compatible with clients supporting **TLS/SSL** for secure transport.

## Scaling and Performance

- **Data Volume Management:** To prevent overwhelming the Elastic Agent, it is recommended to filter logs at the source whenever possible. Adjusting the **Max Message Size** (default 20MiB) is critical for performance; excessively large limits can lead to high memory usage per connection, while limits that are too small will truncate legitimate log entries.
- **Elastic Agent Scaling:** For high-throughput environments receiving data from hundreds of sources, deploy multiple Elastic Agents behind a network load balancer. This allows for horizontal scaling and ensures high availability. Resource sizing should account for the number of concurrent TCP connections, as each open socket consumes system file descriptors and memory.

# Set Up Instructions

## Vendor prerequisites
To successfully integrate a third-party source with the Custom TCP Logs listener, the following prerequisites must be met:
- **Firewall Rules:** Local and network firewalls (for example, iptables, firewalld, or cloud security groups) must be configured to allow inbound traffic on the selected TCP port.
- **Source Configuration Knowledge:** Access to the configuration interface or configuration files of the source device/application to specify the destination IP address and port.
- **SSL Certificates:** If enabling TLS, you must have a valid CA-signed or self-signed certificate and private key accessible by the Elastic Agent.

## Elastic prerequisites

- **Elastic Agent:** A running Elastic Agent enrolled in a Fleet policy.
- **Network Access:** Connectivity between the Elastic Agent and the Elasticsearch/Kibana endpoint for data delivery.

## Vendor set up steps

The "Vendor" in this context refers to any external system or application you wish to monitor. Follow these steps to point your data source to the Elastic Agent.

### For Generic Linux/Unix Log Forwarding:
1. Log in to the source server that will be sending the logs.
2. If using `rsyslog`, locate the configuration file (typically `/etc/rsyslog.conf` or `/etc/rsyslog.d/50-default.conf`).
3. Add a forwarding rule to point to your Elastic Agent's IP and port. For example:
   `*.* @@<ELASTIC_AGENT_IP>:8080`
   *(Note: The `@@` symbol denotes TCP transport in rsyslog).*
4. Restart the rsyslog service:
   `sudo systemctl restart rsyslog`
5. Verify that the server can establish a connection to the Agent using a tool like `telnet` or `nc -zv <ELASTIC_AGENT_IP> 8080`.

### For Custom Application Loggers:
1. Open your application's logging configuration file (for example, `log4j2.xml`, `logback.xml`, or a Python logging dictionary).
2. Configure a Socket Appender or TCP Handler.
3. Set the **Remote Host** or **Destination** to the IP address of the host running the Elastic Agent.
4. Set the **Port** to match the port configured in the Elastic integration (for example, `8080`).
5. Ensure the application is configured to send logs in a newline-delimited format unless you have configured a custom framing method in Kibana.
6. Restart the application to apply the changes and begin the data stream.


## Kibana set up steps

### Custom TCP Logs
1. Navigate to **Management > Integrations** in Kibana.
2. Search for **Custom TCP Logs** and select it.
3. Click **Add Custom TCP Logs**.
4. Configure the following fields:
   - **Listen Address**: The interface address to listen on. Use `0.0.0.0` to accept connections from any network interface. Default: `localhost`.
   - **Listen Port**: The TCP port the Agent will open to listen for incoming logs. Default: `8080`.
   - **Dataset Name**: The name of the dataset to which logs will be written. Default: `tcp.generic`.
   - **Framing**: Specify how the Agent identifies the end of a log message. Options include `delimiter` (default) or `rfc6587`.
   - **Line Delimiter**: The character used to split incoming data into separate log events. Default: `\n`.
   - **Max Message Size**: The maximum allowed size for a single log message. Default: `20MiB`.
   - **Syslog Parsing**: Enable this boolean if the incoming data is in standard Syslog format (RFC3164/5424).
5. If using SSL, expand the **Advanced options** or **SSL Configuration** section and provide:
   - **Certificate**: Path to the SSL certificate file.
   - **Key**: Path to the SSL private key file.
6. (Optional) Provide a **Custom Ingest Pipeline** name if you have pre-defined processing logic in Elasticsearch.
7. Click **Save and Continue** to deploy the configuration to your Agents.

# Validation Steps

After configuration is complete, follow these steps to verify data is flowing correctly from your source to the Elastic Stack.

### 1. Trigger Data Flow on Source:
- **Manual Test Event:** From the source machine (or any machine with network access to the Agent), run the following command to send a manual test message:
  `echo "Integration Validation Test Message $(date)" | nc <AGENT_IP_ADDRESS> <PORT>`
- **Syslog Generation:** If the source is a Linux server, use the `logger` command to generate a syslog event:
  `logger -n <AGENT_IP_ADDRESS> -P <PORT> -T "This is a test syslog message"`
- **Application Activity:** Perform an action in your custom application that is known to trigger a log entry, such as a failed login attempt or a service restart.

### 2. Check Data in Kibana:
1. Navigate to **Analytics > Discover**.
2. Select the `logs-*` data view.
3. Enter the following KQL filter: `data_stream.dataset : "tcp.generic"`
4. Verify logs appear in the results. Expand a log entry and confirm these fields are populated:
   - `event.dataset` (should be `tcp.generic`)
   - `log.syslog.priority` (if syslog parsing is enabled)
   - `source.address` or `source.ip` (showing the sender's IP)
   - `message` (containing the "Integration Validation Test Message")
   - `input.type` (should indicate `tcp`)
5. Navigate to **Analytics > Dashboards** and search for "TCP" to view any available visualizations for generic log traffic.

# Troubleshooting

## Common Configuration Issues

- **Port Binding Failure**: If the Elastic Agent fails to start the listener, check if another process is using the configured port with `netstat -tulpn | grep <PORT>`. If using a port below 1024, ensure the Agent has root/administrator privileges.
- **Firewall Blocking**: If the source device shows connection timeouts, verify that the host firewall (for example, firewalld, iptables, or Windows Firewall) on the Agent machine allows inbound traffic on the configured TCP port.
- **Incorrect Listen Address**: Setting the **Listen Address** to `localhost` or `127.0.0.1` prevents remote devices from connecting. Ensure it is set to `0.0.0.0` or the specific internal IP of the Agent host.
- **Dataset Naming Restriction**: If data is not appearing, check the integration configuration for hyphens in the **Dataset Name**. Hyphens are not supported in this field and will cause ingestion issues.

## Ingestion Errors

- **Parsing Failures**: If data appears in Kibana but is not parsed correctly, check the `error.message` field. This often happens if **Syslog Parsing** is enabled but the incoming logs do not strictly adhere to RFC 3164 or RFC 5424.
- **Framing Issues**: If multiple log lines appear as a single event or if events are cut off, verify that the **Framing** method matches the sender. For example, if the sender uses octet counting, but the integration is set to `delimiter`, messages will be malformed.
- **Message Truncation**: If logs are incomplete, check if they exceed the **Max Message Size**. Increase this value in the integration settings if your application sends large payloads (for example, large JSON blobs).


# Documentation sites
- [Filebeat SSL Configuration](https://www.elastic.co/docs/reference/beats/filebeat/configuration-ssl#ssl-common-config)
