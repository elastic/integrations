# Custom TCP Logs Integration for Elastic

> **Note**: This documentation was generated using AI and should be reviewed for accuracy.

## Overview

The Custom TCP Logs integration for Elastic enables you to collect raw TCP data from any source that can establish a TCP connection and transmit text-based data. It's a flexible solution for ingesting logs from various third-party software or hardware devices into the Elastic Stack. By using this integration, you can centralize your log data, making it easier to monitor, search, and analyze your environment's activity.

### Compatibility

The Custom TCP Logs integration is compatible with any third-party software or hardware capable of establishing a TCP connection and transmitting text-based data.

This integration supports the following standards:
- Syslog standards: Supports devices compliant with `RFC 3164` (BSD syslog) and `RFC 5424` (The Syslog Protocol).
- Framing standards: Supports `RFC 6587` for octet-counted framing, which is commonly used in high-reliability log transmission.
- Encryption: Compatible with clients supporting `TLS/SSL` for secure transport.

### How it works

This integration collects data by having an Elastic Agent listen on a specified TCP port. You'll configure the agent to act as a receiver for incoming TCP traffic. When your external systems or devices send text-based data to this port, the Elastic Agent receives it.

Once received, the data is processed according to your configuration—whether it's raw text, syslog formatted, or uses specific framing like octet counting. The Elastic Agent then forwards the logs to your Elastic deployment, where you can analyze them using Kibana.

## What data does this integration collect?

The Custom TCP Logs integration collects log messages of the following types:
- Raw TCP streams: Any text-based data stream sent over a TCP connection, typically separated by newline characters or other delimiters.
- Syslog messages: Structured messages following RFC 3164 or RFC 5424, which include metadata such as facility, severity, and timestamps.

This integration includes the following data stream:
- `tcp.generic`: This is the default data stream. It captures the raw message payload in the `message` field along with connection metadata such as `source.ip` and `source.port`. If you enable Syslog parsing, additional ECS fields are populated from the syslog header.

### Supported use cases

The Custom TCP Logs integration provides a versatile and robust mechanism for ingesting log data from any source capable of transmitting information over a TCP socket. You can use this integration for the following use cases:
- Custom application logging: Directly stream application events from internal software to the Elastic Agent by configuring a TCP appender in your application's logging framework.
- Legacy syslog ingestion: Collect logs from older network hardware or Unix-based systems that use TCP-based syslog (RFC 3164 or RFC 5424) to ensure centralized visibility.
- Centralized log aggregation: Act as a middle-tier listener for log forwarders or custom scripts that aggregate data before sending it to the Elastic Stack for analysis.
- Encrypted data ingestion: Secure sensitive log transmissions from remote sites using the built-in SSL/TLS support, ensuring data integrity and confidentiality during transit.

## What do I need to use this integration?

To use the Custom TCP Logs integration, you'll need to meet several requirements.

### Vendor prerequisites

To successfully integrate a third-party source with the Custom TCP Logs listener, you must meet these prerequisites:
- Firewall rules: You'll need to configure local and network firewalls (for example, `iptables`, `firewalld`, or cloud security groups) to allow inbound traffic on the selected TCP port.
- Source configuration knowledge: You'll need access to the configuration interface or configuration files of the source device or application to specify the destination IP address and port.
- SSL certificates: If you're enabling TLS, you must have a valid CA-signed or self-signed certificate and private key that's accessible by the Elastic Agent.

### Elastic prerequisites

You'll also need the following Elastic components:
- Elastic Agent: A running Elastic Agent that's enrolled in a Fleet policy.
- Network access: Connectivity between the Elastic Agent and the Elasticsearch or Kibana endpoint for data delivery.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the TCP receiver and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Set up steps in Custom TCP Logs

To send data to the Elastic Agent, you'll need to configure your external system or application to point its output to the Agent's IP and port.

For generic Linux/Unix log forwarding using rsyslog, you'll need to:

1. Log in to the source server that'll be sending the logs.
2. Locate the configuration file, which is typically `/etc/rsyslog.conf` or found within `/etc/rsyslog.d/50-default.conf`.
3. Add a forwarding rule to point to your Elastic Agent's IP and port (replace `<ELASTIC_AGENT_IP>` and `8080` with your actual values):
   ```bash
   *.* @@<ELASTIC_AGENT_IP>:8080
   ```
   Note: The `@@` symbol denotes TCP transport in rsyslog.
4. Restart the rsyslog service:
   ```bash
   sudo systemctl restart rsyslog
   ```
5. Verify that the server can establish a connection to the Agent using a tool like `telnet` or `nc -zv <ELASTIC_AGENT_IP> 8080`.

For custom application loggers, you'll need to:

1. Open your application's logging configuration file, such as `log4j2.xml`, `logback.xml`, or a Python logging dictionary.
2. Configure a Socket Appender or TCP Handler.
3. Set the remote host or destination to the IP address of the host running the Elastic Agent.
4. Set the port to match the port you've configured in the Elastic integration (for example, `8080`).
5. Ensure the application is configured to send logs in a newline-delimited format unless you've configured a custom framing method in Kibana.
6. Restart the application to apply the changes and begin the data stream.

### Set up steps in Kibana

You'll follow these steps to add and configure the integration in Kibana:

1. Navigate to **Management > Integrations** in Kibana.
2. Search for **Custom TCP Logs** and select it.
3. Click **Add Custom TCP Logs**.
4. Configure the integration settings:
    - **Listen Address**: The interface address to listen on. Use `0.0.0.0` to accept connections from any network interface. The default is `localhost`.
    - **Listen Port**: The TCP port the Agent will open to listen for incoming logs. The default is `8080`.
    - **Dataset Name**: The name of the dataset where logs will be written. The default is `tcp.generic`.
    - **Framing**: Specify how the Agent identifies the end of a log message. Options include `delimiter` (default) or `rfc6587`.
    - **Line Delimiter**: The character used to split incoming data into separate log events. The default is `\n`.
    - **Max Message Size**: The maximum allowed size for a single log message. The default is `20MiB`.
    - **Syslog Parsing**: Enable this boolean if the incoming data is in standard Syslog format (RFC3164/5424).
5. If you're using SSL, expand the **Advanced options** or **SSL Configuration** section and provide:
    - **Certificate**: The path to the SSL certificate file.
    - **Key**: The path to the SSL private key file.
6. (Optional) Provide a **Custom Ingest Pipeline** name if you've already defined processing logic in Elasticsearch.
7. Click **Save and Continue** to deploy the configuration to your Agents.

### Validation

After you've finished the configuration, you'll need to verify that data is flowing correctly from your source to the Elastic Stack.

You can trigger a data flow on the source using one of these methods:

- To send a manual test message from the source machine (or any machine with network access to the Agent), run this command:
  ```bash
  echo "Integration Validation Test Message $(date)" | nc <AGENT_IP_ADDRESS> <PORT>
  ```
- If the source is a Linux server, you can use the `logger` command to generate a syslog event:
  ```bash
  logger -n <AGENT_IP_ADDRESS> -P <PORT> -T "This is a test syslog message"
  ```
- You can also perform an action in your custom application that's known to trigger a log entry, such as a failed login attempt.

To check for the data in Kibana, you'll need to:

1. Navigate to **Analytics > Discover**.
2. Select the `logs-*` data view.
3. Enter this KQL filter: `data_stream.dataset : "tcp.generic"`
4. Verify that logs appear in the results. You'll want to expand a log entry and confirm these fields are populated:
    - `event.dataset` (should be `tcp.generic`)
    - `log.syslog.priority` (if you've enabled syslog parsing)
    - `source.address` or `source.ip` (showing the sender's IP)
    - `message` (containing the test message)
    - `input.type` (should indicate `tcp`)
5. Navigate to **Analytics > Dashboards** and search for "TCP" to view any available visualizations for generic log traffic.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Common configuration issues

You might encounter the following common configuration issues when setting up or using this integration:

-   Port binding failure:
    -   If the Elastic Agent fails to start the listener, check if another process is using the configured port with `netstat -tulpn | grep <PORT>`. 
    -   If you're using a port below 1024, ensure the Agent has root or administrator privileges.
-   Firewall blocking:
    -   If your source device shows connection timeouts, verify that the host firewall (such as `firewalld`, `iptables`, or Windows Firewall) on the Elastic Agent machine allows inbound traffic on the configured TCP port.
-   Incorrect listen address:
    -   If you set the `Listen Address` to `localhost` or `127.0.0.1`, remote devices won't be able to connect. Ensure it's set to `0.0.0.0` or the specific internal IP of your Elastic Agent host.
-   Dataset naming restriction:
    -   If data isn't appearing, check your integration configuration for hyphens in the `Dataset Name`. Hyphens aren't supported in this field and will cause ingestion issues.
-   Parsing failures:
    -   If data appears in Kibana but doesn't parse correctly, check the `error.message` field. This often happens if you've enabled `Syslog Parsing` but the incoming logs don't strictly adhere to RFC 3164 or RFC 5424.
-   Framing issues:
    -   If multiple log lines appear as a single event or if events are cut off, verify that the `Framing` method matches the sender. For example, if the sender uses octet counting but the integration is set to `delimiter`, messages will be malformed.
-   Message truncation:
    -   If logs are incomplete, check if they exceed the `Max Message Size`. You'll need to increase this value in the integration settings if your application sends large payloads like large JSON blobs.

### Vendor resources

For more information about configuring your data sources or underlying transport settings, refer to these resources:
- [Filebeat SSL Configuration](https://www.elastic.co/docs/reference/beats/filebeat/configuration-ssl#ssl-common-config)

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

When you're managing high-volume data streams, consider the following factors to optimize performance and ensure successful scaling:

- Data volume management: To prevent overwhelming your Elastic Agent, you should filter logs at the source whenever possible.
- Message size: Adjusting the `Max Message Size` (default `20MiB`) is critical for performance. Excessively large limits can lead to high memory usage per connection, while limits that are too small will truncate your log entries.
- Elastic Agent scaling: For high-throughput environments receiving data from hundreds of sources, you can deploy multiple Elastic Agents behind a network load balancer. This approach allows for horizontal scaling and ensures high availability for your log collection.
- Resource sizing: You should account for the number of concurrent TCP connections when sizing your system resources, as each open socket consumes system file descriptors and memory.

## Reference

### Inputs used



### Vendor documentation links

The following links provide additional information about the protocols and configurations supported by this integration:
- [RFC 3164: The BSD Syslog Protocol](https://datatracker.ietf.org/doc/html/rfc3164)
- [RFC 5424: The Syslog Protocol](https://datatracker.ietf.org/doc/html/rfc5424)
- [RFC 6587: Transmission of Syslog Messages over TCP](https://datatracker.ietf.org/doc/html/rfc6587)

### Data streams

#### generic

The `generic` data stream provides events from any source sending text-based data over TCP. It's the default destination for ingested logs and captures the raw message payload alongside connection metadata like `source.ip` and `source.port`.

The `generic` data stream supports the following types of data:
- Raw TCP streams: Any text-based data stream sent over a TCP connection, typically separated by newline characters or other delimiters.
- Syslog messages: Structured messages following RFC 3164 or RFC 5424, which include metadata such as facility, severity, and timestamps.

##### generic fields

**Exported fields**

(no fields available)

