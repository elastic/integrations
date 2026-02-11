# Squid Proxy Integration for Elastic

> **Note**: This documentation was generated using AI and should be reviewed for accuracy.

## Overview

The Squid Proxy integration for Elastic enables you to collect and parse logs from Squid devices using Elastic Agent. This allows you to monitor web traffic, optimize cache performance, and perform security auditing within the Elastic Stack. By ingesting these logs, you'll gain visibility into bandwidth consumption, user behavior, and potential security threats.

This integration facilitates:
- Web traffic analysis: Monitor the volume and destination of web requests flowing through your proxy to understand user behavior and bandwidth consumption.
- Cache performance optimization: Track cache hits and misses to tune Squid configuration for better response times and reduced outbound traffic.
- Security auditing: Identify unauthorized access attempts, unusual request patterns, or connections to malicious domains by auditing detailed access logs.
- Troubleshooting connectivity: Diagnose client connection issues by analyzing response codes and proxy-specific error messages in the `log` data stream.

### Compatibility

This integration is compatible with the following:
- Squid Proxy versions that support the native log format and log modules such as Standard I/O, TCP Receiver, or UDP Receiver.
- Linux distributions including Ubuntu, Debian, CentOS, and RHEL.
- Other Unix-like operating systems capable of running Squid.

### How it works

The Squid Proxy integration collects logs through several input methods, allowing you to choose the best approach for your architecture. You can configure the integration to receive data over the network using the `UDP` or `TCP` inputs, or you can use the `filestream` input to read logs directly from local files on the host where the agent is running.

Once the data is received, the integration parses the native Squid log format into the Elastic Common Schema (ECS). This standardization allows you to analyze your proxy logs alongside other data sources in your Elastic environment, using pre-built dashboards and search capabilities.

## What data does this integration collect?

The Squid Proxy integration collects log messages of the following types:
*   Access logs: Details about client requests, including the source IP, requested URL, and the HTTP method used.
*   Request metadata: Information about the time taken to process requests, HTTP status codes, and the volume of data transferred.
*   Cache result codes: Specific information that identifies how the request was satisfied, such as a cache hit or miss.

This integration is designed to parse the native Squid log format and map it to the Elastic Common Schema (ECS). You can ingest data into the `log` data stream using the following input methods:
*   `UDP` input: Use this for high-speed transmission where low-latency delivery is the priority.
*   `TCP` input: Use this for reliable, connection-oriented transmission of your proxy events.
*   `filestream` input: Use this to read logs directly from local files on the host where the Elastic Agent is running.

### Supported use cases

Integrating Squid Proxy logs with the Elastic Stack helps you enhance your network visibility and security:
*   Visualize traffic patterns: You can use Kibana dashboards to analyze web usage and identify bandwidth bottlenecks.
*   Detect security incidents: You'll be able to identify access to malicious or unauthorized websites by correlating logs with threat intelligence.
*   Troubleshoot proxy performance: You can investigate latency issues and request failures to ensure your proxy is running efficiently.
*   Ensure compliance: You can maintain a searchable audit trail of web activity to meet regulatory requirements and support forensic investigations.

## What do I need to use this integration?

You'll need to meet the following Elastic prerequisites:
- Install and enroll an Elastic Agent in Fleet, or configure it as a standalone agent.
- Ensure the Elastic Agent can reach Elasticsearch for data ingestion and Kibana for management.

You'll also need to meet these vendor-specific prerequisites:
- Use `sudo` or `root` privileges on the Squid server to modify `squid.conf` and restart the service.
- Maintain a functional Squid installation with support for the native log format and standard log modules.
- Ensure the Squid server can reach the Elastic Agent host on the configured port (default `9537`) if you use network-based logging (TCP/UDP).
- Locate your access logs (typically at `/var/log/squid/`) and understand the `squid.conf` configuration file.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the syslog or log file receiver and ship the data to Elastic, where the events will then be processed using the integration's ingest pipelines.

### Set up steps in Squid Proxy

You can configure Squid Proxy to send logs to Elastic using local log files, UDP, or TCP. Follow the steps below for your preferred method:

#### Configure local log file (filestream)

1. Open the Squid configuration file using `sudo nano /etc/squid/squid.conf` (replace with your actual configuration path).
2. Locate or add the `access_log` directive to write to a local file: `access_log stdio:/var/log/squid/access.log squid`.
3. Verify the native format is defined to ensure compatibility: `logformat squid %ts.%03tu %6tr %>a %Ss/%03>Hs %<st %rm %ru %[un %Sh/%<a %mt`.
4. Save the file and restart the Squid service: `sudo systemctl restart squid`.
5. Check that data is being written to the file: `tail -f /var/log/squid/access.log`.

#### Configure UDP network export

1. Open `squid.conf` and add the network target: `access_log udp://<AGENT_IP>:9537 squid`. Replace `<AGENT_IP>` with the IP address of your Elastic Agent host (replace with your actual value).
2. Restart Squid to begin streaming: `sudo systemctl restart squid`.
3. (Optional) Verify that packets are leaving the host: `sudo tcpdump -i any udp port 9537`.

#### Configure TCP network export

1. Open `squid.conf` and add the network target: `access_log tcp://<AGENT_IP>:9537 squid`. Replace `<AGENT_IP>` with the IP address of your Elastic Agent host (replace with your actual value).
2. Restart the service: `sudo systemctl restart squid`.
3. Check the connection status: `ss -ant | grep 9537`.

### Set up steps in Kibana

To set up the integration in Kibana:

1. In Kibana, navigate to **Management** > **Integrations**.
2. Search for **Squid Proxy** and select the integration.
3. Click **Add Squid Proxy**.
4. Configure the integration by selecting the input type that matches your Squid Proxy setup.

Choose the configuration steps below that match your preferred input method:

#### Collecting syslog from Squid via UDP

This input collects logs sent over the network using the UDP protocol.

- UDP host to listen on (`udp_host`): The interface the agent should listen on. Default: `localhost`.
- UDP port to listen on (`udp_port`): The port to listen for incoming Squid logs. Default: `9537`.
- Preserve original event (`preserve_original_event`): Preserves a raw copy of the original event in the `event.original` field. Default: `false`.
- Tags (`tags`): Custom tags to add to the events. Default: `['squid-log', 'forwarded']`.
- Custom UDP options (`udp_options`): Specify custom configuration options such as `read_buffer`, `max_message_size`, or `timeout`.
- Processors (`processors`): Define processors to reduce fields or enhance events with metadata before parsing.

#### Collecting syslog from Squid via TCP

This input collects logs sent over the network using the TCP protocol.

- TCP host to listen on (`tcp_host`): The interface the agent should listen on. Default: `localhost`.
- TCP port to listen on (`tcp_port`): The port to listen for incoming Squid logs. Default: `9537`.
- Preserve original event (`preserve_original_event`): Preserves a raw copy of the original event in the `event.original` field. Default: `false`.
- Tags (`tags`): Custom tags to add to the events. Default: `['squid-log', 'forwarded']`.
- SSL configuration (`ssl`): Configure SSL options including `certificate` and `key` paths for encrypted transport.
- Custom TCP options (`tcp_options`): Specify custom configuration options such as `max_message_size`.
- Processors (`processors`): Define processors for data enhancement or filtering in the agent.

#### Collecting syslog from Squid via filestream

This input collects logs directly from log files on the host where Elastic Agent is running.

- Paths (`paths`): The list of paths to look for Squid log files, such as `/var/log/squid/access.log`.
- Preserve original event (`preserve_original_event`): Preserves a raw copy of the original event in the `event.original` field. Default: `false`.
- Tags (`tags`): Custom tags to identify logs from this input. Default: `['squid-log', 'forwarded']`.
- Processors (`processors`): Define optional processors for data enhancement or filtering.

After configuring the settings, click **Save and continue** to deploy the integration to your agent policy.

### Validation

To verify the integration is working and data is flowing:

1. Verify the Elastic Agent status:
   - Navigate to **Management** > **Fleet** > **Agents**.
   - Ensure the agent assigned to the Squid policy is `Healthy` and connected.

2. Trigger data flow on the Squid Proxy:
   - Generate web traffic: From a client machine configured to use the Squid proxy, browse to several websites to generate access log entries.
   - Test using command line: Use `curl` on a client to make a request through the proxy: `curl -x http://<SQUID_IP>:<SQUID_PORT> http://www.elastic.co` (replace with your actual Squid IP and port).
   - Authentication event: If proxy authentication is enabled, attempt to log in with both valid and invalid credentials.

3. Check data in Kibana:
   - Navigate to **Analytics** > **Discover**.
   - Select the `logs-*` data view.
   - Enter the KQL filter: `data_stream.dataset : "squid.log"`.
   - Verify that logs appear with the expected fields such as `event.dataset`, `source.ip`, `event.outcome`, and `message`.
   - Navigate to **Analytics** > **Dashboards** and search for "Squid Proxy" to view pre-built visualizations populated with your data.

## Troubleshooting

For help with Elastic ingest tools, refer to the [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems) documentation.

### Common configuration issues

If you encounter issues with the Squid Proxy integration, check the following scenarios:
- Logs are not parsed correctly: Ensure the `access_log` directive in `squid.conf` includes the `squid` keyword at the end. This integration is specifically designed to parse the native Squid log format.
- Port is already in use: When using TCP or UDP collection, verify that no other service is using port `9537` on the Elastic Agent host. You can check for existing listeners by running `sudo lsof -i :9537`.
- Permission denied errors: If you're using the filestream input, check that the Elastic Agent user has read permissions for the Squid log files, typically located in `/var/log/squid/`.
- Logs are not appearing in Kibana: Verify that firewalls on both the Squid server and the Elastic Agent host allow traffic on the configured port. By default, this integration uses port `9537`.
- Grok parsing failures: Look for `_grokparsefailure` tags in Discover. These usually occur if the `logformat` in your Squid configuration has been customized or modified from the standard native format.
- Event timestamps are incorrect: Synchronize the system clocks on both the Squid server and the Elastic Agent host using NTP to prevent events from appearing with future timestamps or arriving late.

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

To ensure your Squid Proxy integration performs optimally in high-volume environments, consider the following:

### Transport and collection considerations
The choice of protocol and input type affects both performance and reliability:
- While `UDP` is faster for log transmission with lower overhead, you should use `TCP` in environments where you require delivery guarantees.
- For local collection, use the `filestream` input because it's highly reliable, maintains state, and handles log rotation natively.

### Data volume management
Squid Proxy can generate significant log volumes. You can manage this load using the following methods:
- Use Squid ACLs to filter traffic at the source.
- Configure the `access_log` directive to only log specific event types.
- Ensure that the `logformat` remains in the "native" style, as the parser for this integration depends on this specific structure for accurate processing.

### Elastic Agent scaling
For high-throughput environments, you can scale your deployment using these strategies:
- Deploy an Elastic Agent on each Squid node for local file collection.
- If you're using centralized network-based collection, deploy multiple Elastic Agents behind a network load balancer to distribute the ingest load evenly across multiple CPU cores.

## Reference

### Vendor documentation

For more details on Squid logging and configuration, refer to the official documentation:
- [Squid Log Modules - Official Wiki](https://wiki.squid-cache.org/Features/LogModules)
- [Squid Access Log FAQ - Official Wiki](https://wiki.squid-cache.org/SquidFaq/SquidLogs)
- [Squid Native Log Format Details](https://wiki.squid-cache.org/Features/LogFormat#squid-native-accesslog-format-in-detail)

### Inputs used

These inputs can be used with this integration:
<details>
<summary>filestream</summary>

## Setup

For more details about the Filestream input settings, check the [Filebeat documentation](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-filestream).


### Collecting logs from Filestream

To collect logs via Filestream, select **Collect logs via Filestream** and configure the following parameters:

- Filestream paths: The full path to the related log file.
</details>
<details>
<summary>tcp</summary>

## Setup

For more details about the TCP input settings, check the [Filebeat documentation](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-tcp).

### Collecting logs from TCP

To collect logs via TCP, select **Collect logs via TCP** and configure the following parameters:

**Required Settings:**
- Host
- Port

**Common Optional Settings:**
- Max Message Size - Maximum size of incoming messages
- Max Connections - Maximum number of concurrent connections
- Timeout - How long to wait for data before closing idle connections
- Line Delimiter - Character(s) that separate log messages

## SSL/TLS Configuration

To enable encrypted connections, configure the following SSL settings:

**SSL Settings:**
- Enable SSL*- Toggle to enable SSL/TLS encryption
- Certificate - Path to the SSL certificate file (`.crt` or `.pem`)
- Certificate Key - Path to the private key file (`.key`)
- Certificate Authorities - Path to CA certificate file for client certificate validation (optional)
- Client Authentication - Require client certificates (`none`, `optional`, or `required`)
- Supported Protocols - TLS versions to support (e.g., `TLSv1.2`, `TLSv1.3`)

**Example SSL Configuration:**
```yaml
ssl.enabled: true
ssl.certificate: "/path/to/server.crt"
ssl.key: "/path/to/server.key"
ssl.certificate_authorities: ["/path/to/ca.crt"]
ssl.client_authentication: "optional"
```
</details>
<details>
<summary>udp</summary>

## Setup

For more details about the UDP input settings, check the [Filebeat documentation](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-udp).

### Collecting logs from UDP

To collect logs via UDP, select **Collect logs via UDP** and configure the following parameters:

**Required Settings:**
- Host
- Port

**Common Optional Settings:**
- Max Message Size - Maximum size of UDP packets to accept (default: 10KB, max: 64KB)
- Read Buffer - UDP socket read buffer size for handling bursts of messages
- Read Timeout - How long to wait for incoming packets before checking for shutdown
</details>


### Data streams

#### log

The `log` data stream provides events from Squid Proxy of the following types: access logs in both native and common log formats.

##### log fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| container.id | Unique container id. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.device_id | ID of the device containing the filesystem where the file resides. | keyword |
| log.file.fingerprint | The sha256 fingerprint identity of the file when fingerprinting is enabled. | keyword |
| log.file.idxhi | The high-order part of a unique identifier that is associated with a file. (Windows-only) | keyword |
| log.file.idxlo | The low-order part of a unique identifier that is associated with a file. (Windows-only) | keyword |
| log.file.inode | Inode number of the log file. | keyword |
| log.file.path | Full path to the log file this event came from. | keyword |
| log.file.vol | The serial number of the volume that contains a file. (Windows-only) | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| squid.content_type | The content type as seen in the HTTP reply header. | keyword |
| squid.peer_status | A code explaining how the request was handled, by forwarding it to a peer or going straight to the source. | keyword |
| squid.result_code | The outcome of the request. | keyword |
| squid.status_code | The status of the result. | long |


##### log sample event

An example event for `log` looks as following:

```json
{
    "@timestamp": "2006-09-08T04:21:52.049Z",
    "agent": {
        "ephemeral_id": "703e0801-aef8-4d26-aa48-12c7673f6df0",
        "id": "29b8ade0-b4ef-4ce2-ab55-0acc99bbb914",
        "name": "elastic-agent-52603",
        "type": "filebeat",
        "version": "8.15.0"
    },
    "data_stream": {
        "dataset": "squid.log",
        "namespace": "63238",
        "type": "logs"
    },
    "destination": {
        "address": "175.16.199.115",
        "bytes": 19763,
        "geo": {
            "city_name": "Changchun",
            "continent_name": "Asia",
            "country_iso_code": "CN",
            "country_name": "China",
            "location": {
                "lat": 43.88,
                "lon": 125.3228
            },
            "region_iso_code": "CN-22",
            "region_name": "Jilin Sheng"
        },
        "ip": "175.16.199.115"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "29b8ade0-b4ef-4ce2-ab55-0acc99bbb914",
        "snapshot": false,
        "version": "8.15.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "dataset": "squid.log",
        "duration": 5006000000,
        "ingested": "2024-09-03T18:27:38Z",
        "kind": "event",
        "original": "1157689312.049   5006 10.105.21.199 TCP_MISS/200 19763 CONNECT login.yahoo.com:443 badeyek DIRECT/175.16.199.115 -",
        "outcome": "success",
        "type": [
            "access"
        ]
    },
    "http": {
        "request": {
            "method": "CONNECT"
        }
    },
    "input": {
        "type": "filestream"
    },
    "log": {
        "file": {
            "device_id": "35",
            "inode": "442644",
            "path": "/tmp/service_logs/squid-log-access.log"
        },
        "offset": 0
    },
    "observer": {
        "product": "Squid",
        "type": "proxy",
        "vendor": "Squid"
    },
    "related": {
        "ip": [
            "10.105.21.199",
            "175.16.199.115"
        ],
        "user": [
            "badeyek"
        ]
    },
    "source": {
        "address": "10.105.21.199",
        "ip": "10.105.21.199",
        "user": {
            "name": "badeyek"
        }
    },
    "squid": {
        "peer_status": "DIRECT",
        "result_code": "TCP_MISS",
        "status_code": 200
    },
    "tags": [
        "preserve_original_event",
        "squid-log",
        "forwarded"
    ],
    "url": {
        "original": "login.yahoo.com:443"
    }
}
```

