# Custom UDP Logs Integration for Elastic

> **Note**: This documentation was generated using AI and should be reviewed for accuracy.

## Overview

The Custom UDP Logs integration for Elastic enables you to collect raw UDP data by listening on a specified UDP port using an Elastic Agent. This integration acts as a generic network data collector, allowing the Elastic Agent to serve as a high-performance UDP server. It's designed for environments where data sources don't support TCP or where the overhead of a connection-oriented protocol is undesirable.

This integration facilitates:
- Legacy network gear ingestion: Capture logs from older switches, routers, and firewalls that only support standard UDP syslog (RFC 3164) exports.
- Custom application telemetry: Collect real-time metrics and event data from bespoke applications that broadcast performance statistics using UDP packets to minimize application latency.
- High-volume log centralization: Efficiently aggregate large volumes of unstructured or semi-structured data across the network before routing them to Elasticsearch for analysis.
- Security monitoring: Ingest CEF or JSON formatted security events from third-party appliances that use UDP for rapid data transmission.

### Compatibility

This integration is a protocol-based listener and is compatible with any third-party vendor, hardware appliance, or software application capable of transmitting data using the User Datagram Protocol (UDP).

This integration is compatible with the following:
- Network appliances: Cisco IOS/NX-OS, Juniper Junos, Fortinet FortiOS, and Check Point Gaia.
- Operating systems: Linux (using rsyslog or syslog-ng), Windows (using event-to-syslog agents), and macOS.
- Standard protocols: Support for RFC 3164 (BSD Syslog) and RFC 5424 (IETF Syslog) message formats.

### How it works

This integration works by opening a listening UDP port on the host where the Elastic Agent is running. When the agent receives a UDP packet, it ingests the payload and automatically appends metadata about the source.

The data collection process involves several steps:
- Listening: The agent waits for incoming packets on the port you configure.
- Payload capture: The raw text-based or binary data sent over UDP is captured and stored in the `message` field.
- Metadata attachment: Information regarding the source IP and port of the incoming traffic is automatically appended to each event.
- Parsing and processing: Automatic parsing is available for syslog data following RFC 3164 and RFC 5424 standards. Other formats like Common Event Format (CEF) or JSON can be processed through custom ingest pipelines.
- Data indexing: All incoming UDP traffic is collected and indexed into the `udp.generic` data stream as log documents.

## What data does this integration collect?

The Custom UDP Logs integration collects several types of data by listening on a specified network port and ingesting the payload of each received packet:
* Syslog data: Automatic parsing is available for logs following RFC 3164 and RFC 5424 standards, which are commonly used by Linux systems and network appliances.
* Generic log events: Any raw text-based or binary data sent over UDP is captured and stored in the `message` field.
* Security events: Formats such as Common Event Format (CEF) or JSON-encoded security logs can be ingested and processed through custom pipelines.
* Network traffic metadata: Information about the source IP and port of the incoming traffic is automatically appended to each event.

The integration provides the following data stream:
* `udp.generic`: This is the default data stream used to collect and index all incoming UDP traffic as log documents.

### Supported use cases

You can use this integration to enable several operational and security scenarios:
* Log centralization: Collect logs from legacy hardware and network appliances that only support UDP transport for log transmission.
* Custom application monitoring: Ingest raw text or binary telemetry from internal applications that use UDP for performance or low-latency reasons.
* Security monitoring: Bring in security events from third-party tools that output CEF or JSON over the network for analysis in Elastic Security.
* Operational visibility: Gain insights into network activity by capturing the metadata from incoming packets.

## What do I need to use this integration?

Before you can collect data, you'll need to satisfy a few requirements on your source device and within your Elastic Stack.

### Vendor prerequisites

To prepare your source device or application, make sure you meet these requirements:
- You have administrative access to modify the logging or telemetry export configuration on the device sending the logs.
- Your network allows unrestricted UDP traffic flow from the source device's IP address to the Elastic Agent's IP address on the chosen port, like `8080` or `514` (replace with your actual port).
- You know if the source device sends data in a specific format like `RFC 5424`, which helps you decide whether to enable the syslog parsing toggle.
- You've configured any intermediate or host-based firewalls, such as `iptables` or Windows Firewall, to allow inbound UDP traffic on the listener port.

### Elastic prerequisites

You'll also need to satisfy these Elastic prerequisites:
- You've installed the Elastic Agent and successfully enrolled it in a Fleet policy.
- You're running the Elastic Agent service with root or administrative privileges if you intend to use a privileged port below `1024`, such as `UDP 514`.

## How do I deploy this integration?

### Agent-based deployment

You must install Elastic Agent. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

You use Elastic Agent to stream data from the syslog or log file receiver and ship the data to Elastic, where the system processes the events through the integration's ingest pipelines.

### Set up steps in Custom UDP Logs

To begin ingesting data, you must configure your external devices to target the Elastic Agent using these instructions.

#### For generic network devices (Syslog/UDP)

You can configure your network appliance or server using the following steps:

1. Log in to the management interface (CLI or Web UI) of your network appliance or server.
2. Navigate to the **System Logging**, **Remote Logging**, or **Telemetry** configuration section.
3. Add a new remote log destination or syslog server entry.
4. Set the **Destination IP Address** to the IP address of the host running the Elastic Agent.
5. Set the **Destination Port** to the port you plan to configure in Kibana (default is `8080`).
6. Set the **Protocol** to `UDP`.
7. If the device allows, select the log format. RFC 5424 is preferred for better structured data, though RFC 3164 is widely supported.
8. Specify the facility and severity levels you wish to export (for example, `Local0`, `Notice`).
9. Save the configuration and, if necessary, restart the logging service on the device to initiate the stream.

#### For custom applications

If you use a custom application, you can configure it with these steps:

1. Access the application's configuration file or environment variables.
2. Locate the logging output settings.
3. Configure the application to use a `UDP` appender or socket logger.
4. Point the appender to the Elastic Agent's host IP and the configured `UDP` port.
5. Ensure you send the message payload as a single packet per log line to ensure correct indexing.

### Set up steps in Kibana

You can configure the integration in Kibana using these steps:

1. Navigate to **Management > Integrations** in Kibana and search for **Custom UDP Logs**.
2. Click **Add Custom UDP Logs** to begin the configuration.
3. Provide the configuration settings for the following fields:
   - **Listen Address**: The bind address for the `UDP` listener. Use `0.0.0.0` to listen on all network interfaces or `localhost` for local traffic only. Default: `localhost`.
   - **Listen Port**: The `UDP` port the agent will bind to. Default: `8080`.
   - **Syslog Parsing**: Toggle this to **On** to automatically parse RFC 3164 and RFC 5424 formatted messages.
   - **Max Message Size**: Define the maximum allowed size for a single `UDP` packet. The system truncates large packets exceeding this value. Default: `10KiB`.
   - **Ingest Pipeline**: (Optional) Enter the ID of a custom ingest pipeline to process logs on the server side.
   - **Dataset Name**: Specify the dataset name, which determines the target index. Default: `udp.generic`.
   - **Read Buffer Size**: Configure the size of the operating system's `UDP` receive buffer (uses OS default if not specified).
   - **Preserve Original Event**: Enable this to store the raw, unmodified log in the `event.original` field.
   - **Timeout**: (Advanced) Set the read and write timeout for socket operations. Valid time units are `ns`, `us`, `ms`, `s`, `m`, `h`.
   - **Keep Null Values**: (Advanced) If you enable this setting, the system publishes fields with null values in the output document. Default: disabled.
   - **Use the "logs" data stream**: (Advanced) Enable this to send all ingested data to the "logs" data stream. Requires Elasticsearch 9.2.0 or later. When enabled, the Dataset name option is ignored. Note: "Write to logs streams" must also be enabled in the output settings. Default: disabled.
   - **Syslog Options**: (Advanced) Configure syslog parsing options in YAML format, including format type and timezone settings.
   - **Custom configurations**: (Advanced) Add custom YAML configuration options. Use with caution as incorrect settings might break your configuration.
4. (Optional) In the **Processors** field, add `YAML`-formatted processors to drop, rename, or add fields at the Agent level.
5. Click **Save and Continue**, select the appropriate **Agent Policy**, and click **Save and deploy changes**.

### Validation

To verify the integration is working, you can generate test traffic and check for the results in Kibana.

#### Trigger data flow

You can generate test traffic from a source device or a terminal using these methods:

- **Using Netcat (Linux/macOS)**: Run the following command from a remote machine to send a test syslog message:
  ```bash
  echo "<34>1 2023-10-11T10:30:00Z myhost.example.com test-app - - [test@1234 message=\"Hello Elastic\"] This is a test message" | nc -u -w1 <AGENT_IP> 8080
  ```
- **Using Logger (Linux)**: Execute the following command to send a standard system log:
  ```bash
  logger -n <AGENT_IP> -P 8080 -d "Test UDP Log Entry"
  ```
- **Generate Device Event**: Log out and log back into the web interface of your configured network switch to trigger an authentication event.

#### Check data in Kibana

You can verify that data is flowing into Elasticsearch with these steps:

1. Navigate to **Analytics > Discover**.
2. Select the `logs-*` data view.
3. Enter the following KQL filter: `data_stream.dataset : "udp.generic"`
4. Verify logs appear in the results table. You can expand a recent log entry and confirm the system populated these fields:
   - `event.dataset`: This should be exactly `udp.generic`.
   - `source.ip`: This contains the IP address of the device that sent the test message.
   - `message`: This contains the raw text of your test log (for example, "This is a test message").
   - `log.syslog.priority`: (If you enabled Syslog Parsing) This shows the numerical priority extracted from the header.
   - `event.original`: (If you enabled this setting) This contains the full raw packet including syslog headers.

## Troubleshooting

> **Note**: This documentation was generated using AI and should be reviewed for accuracy.

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Common configuration issues

The following issues are common when setting up the Custom UDP Logs integration:
- Permission denied for low ports:
    * If you configure a port below 1024 (like UDP `514`), the Elastic Agent may fail to start because it doesn't have sufficient privileges.
    * You'll need to use a port above 1024 or run the Elastic Agent service as a privileged user like root or administrator.
- Address already in use:
    * The Elastic Agent can't bind to the port if another service, such as a local `rsyslog` or `syslog-ng` daemon, is already using it.
    * You can check for conflicting services using a command like `netstat -tuln | grep <your-port>`.
- Firewall blocking incoming traffic:
    * If the agent is running but you don't see data in Kibana, the host's firewall might be blocking the UDP packets.
    * Check your firewall settings using `iptables -L` on Linux or `Get-NetFirewallRule` on Windows to ensure the configured port is open.
- Listen address mismatch:
    * If you set the **Listen Address** to `localhost`, the agent only accepts traffic from its own host.
    * To receive logs from external network devices, ensure the **Listen Address** is set to `0.0.0.0`.
- Parsing failures:
    * If logs appear in Kibana but fields aren't correctly extracted, verify that the **Syslog Parsing** toggle matches the format (RFC 3164 or RFC 5424) being sent by your source.
    * If your device uses a non-standard format, you might need to disable automatic parsing and use a custom ingest pipeline with a Grok processor.
- Message truncation:
    * Long log messages or jumbo frames might be cut off if they exceed the **Max Message Size** limit.
    * You can increase this value in the integration settings (for example, to `64KiB`) to accommodate larger payloads.
- Timestamp mismatches:
    * If your logs show an incorrect time in Kibana, the source device might be using a different timezone than the Elastic Stack.
    * You can use an ingest pipeline to correct timezone offsets if the source device doesn't provide UTC timestamps.
- Packet loss during traffic bursts:
    * UDP doesn't guarantee delivery, so packets can be dropped if the network is congested or the agent's buffer is overwhelmed.
    * You can mitigate this by increasing the **Read Buffer Size** in the integration settings to allow the operating system to buffer more incoming packets.

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

You should consider several factors when scaling the Custom UDP Logs integration to ensure reliable data collection and optimal performance.

### Transport and collection considerations

UDP is a connectionless protocol that offers lower latency and less overhead than TCP, which makes it ideal for high-throughput logging. However, because it lacks delivery guarantees, packets can be dropped during periods of extreme network congestion or if the Elastic Agent's read buffer is overwhelmed. You should consider the following to improve reliability:

*   **Increase read buffer size**: Adjust the `read_buffer_size` setting in the integration configuration to help the agent handle traffic bursts without dropping packets. Note that increasing this value will consume more memory on the host machine.
*   **Monitor packet loss**: Use host-level network monitoring tools to track UDP packet drops at the operating system level, which can indicate that the agent's buffer or the system's network stack needs tuning.

### Data volume management

To prevent overwhelming your Elastic Stack and to control costs, you can manage the volume of data being ingested using these strategies:

*   **Filter at the source**: Whenever possible, configure your source devices or applications to limit exports to specific severity levels (for example, Warning and above) or specific facilities.
*   **Use processors**: If you can't reduce volume at the source, use the `processors` setting within the integration configuration to drop irrelevant events at the agent level before they're transmitted to Elasticsearch. This reduces network bandwidth and storage usage.

### Elastic Agent scaling

In high-traffic environments, such as those exceeding 10,000 events per second, a single Elastic Agent might become a performance bottleneck. You can scale your deployment using the following methods:

*   **Deploy multiple agents**: Distribute the incoming UDP traffic across multiple Elastic Agents deployed on different hosts to increase total processing capacity.
*   **Use a network load balancer**: Place a network load balancer in front of your Elastic Agents to distribute the incoming UDP traffic evenly across the agent pool.
*   **Ensure sufficient CPU resources**: Make sure the host machines have enough CPU cores to handle the intensive context switching required for high-speed packet processing.

## Reference

The Reference section for the Custom UDP Logs integration provides detailed information about the inputs and data streams used to collect and process your UDP data.

### Data streams

The Custom UDP Logs integration produces a single data stream that handles the ingested data.

#### generic

The `generic` data stream provides events from UDP listeners of the following types:
- Raw UDP messages ingested as plain text.
- Syslog formatted data adhering to RFC3164 or RFC5424 standards.

By default, the integration sends all collected data to the `udp.generic` dataset. You can customize the dataset name in the integration settings to categorize your logs differently.

### Documentation links

For more information about configuring UDP logging and optimizing your data collection, refer to these resources:
- [Elastic Agent troubleshooting guide](https://www.elastic.co/guide/en/fleet/current/fleet-troubleshooting.html)
- [Elastic integration documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for processors and field mappings
- [Elasticsearch index names documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-index_.html) for index naming conventions
- [RFC 3164 - The BSD Syslog Protocol](https://datatracker.ietf.org/doc/html/rfc3164)
- [RFC 5424 - The Syslog Protocol](https://datatracker.ietf.org/doc/html/rfc5424)
