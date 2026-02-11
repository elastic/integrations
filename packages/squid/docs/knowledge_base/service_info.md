# Service Info

The Squid Proxy integration allows for the comprehensive monitoring of Squid access logs, providing visibility into web traffic, caching efficiency, and proxy performance. It enables administrators to ingest logs from Squid instances into the Elastic Stack for real-time analysis and visualization.

## Common use cases
- **Web Traffic Analysis:** Monitor the volume and destination of web requests flowing through your proxy to understand user behavior and bandwidth consumption.
- **Cache Performance Optimization:** Track cache hits and misses to tune Squid configuration for better response times and reduced outbound traffic.
- **Security Auditing:** Identify unauthorized access attempts, unusual request patterns, or connections to malicious domains by auditing detailed access logs.
- **Troubleshooting Connectivity:** Diagnose client connection issues by analyzing response codes and proxy-specific error messages in the access log stream.

## Data types collected

This integration collects log data via a single data stream with multiple input options:

- **Squid logs (logs):** Collect Squid logs using the **UDP** input. This is designed for high-speed network transmission where low-latency delivery is prioritized.
- **Squid logs (logs):** Collect Squid logs using the **TCP** input. This ensures reliable, connection-oriented network transmission of proxy events.
- **Squid logs (filestream):** Collect Squid logs using the **filestream** input. This method reads logs directly from local files on the host where the agent is running.

All streams are designed to parse the **Native log file** format (the "squid" format) to ensure accurate field mapping to the Elastic Common Schema (ECS).

## Compatibility

The Squid Proxy integration is compatible with:
- **Squid Proxy** versions that support the native log format and log modules (Standard I/O, TCP Receiver, or UDP Receiver).
- Systems capable of running **Squid** such as Linux (Ubuntu, Debian, CentOS, RHEL) and other Unix-like operating systems.

## Scaling and Performance

To ensure optimal performance in high-volume environments, consider the following:
- **Transport/Collection Considerations:** While UDP is faster for log transmission with lower overhead, TCP is recommended for environments where delivery guarantees are required. For local collection, the `filestream` input is highly reliable as it maintains state and handles log rotation natively.
- **Data Volume Management:** Squid can generate significant log volumes. Use Squid ACLs to filter traffic at the source or configure the `access_log` directive to only log specific event types. Ensure that the `logformat` remains in the "native" style, as the integration's parser depends on this specific structure for accurate processing.
- **Elastic Agent Scaling:** For high-throughput environments, deploy an Elastic Agent on each Squid node for local file collection. If using centralized network-based collection, deploy multiple Elastic Agents behind a network load balancer to distribute the ingest load evenly across multiple CPU cores.

# Set Up Instructions

## Vendor prerequisites

- **Administrative Access:** Sudo or root privileges on the Squid server are required to modify `squid.conf` and restart the service.
- **Network Connectivity:** If using network-based logging (TCP/UDP), ensure the Squid server can reach the Elastic Agent host on the configured port (default `9537`).
- **Log Format Knowledge:** Familiarity with the `squid.conf` configuration file and the location of access logs (typically `/var/log/squid/`).
- **Standard Squid Installation:** A functional Squid installation with support for the native log format and standard log modules.

## Elastic prerequisites

- **Elastic Agent:** An Agent must be installed and enrolled in Fleet, or configured as a standalone agent.
- **Network Access:** The Elastic Agent must be able to reach Elasticsearch for data ingestion and Kibana for management.

## Vendor set up steps

### 1. Configure Local Log File (Filestream)
1. Open the Squid configuration file: `sudo nano /etc/squid/squid.conf`.
2. Locate or add the `access_log` directive to write to a local file: `access_log stdio:/var/log/squid/access.log squid`.
3. Verify the native format is defined: `logformat squid %ts.%03tu %6tr %>a %Ss/%03>Hs %<st %rm %ru %[un %Sh/%<a %mt`.
4. Save the file and restart Squid: `sudo systemctl restart squid`.
5. Check that data is being written: `tail -f /var/log/squid/access.log`.

### 2. Configure UDP Network Export
1. Open `squid.conf` and add the network target: `access_log udp://<AGENT_IP>:9537 squid`.
2. Replace `<AGENT_IP>` with the IP of your Elastic Agent host.
3. Restart Squid to begin streaming: `sudo systemctl restart squid`.
4. (Optional) Verify packets are leaving the host: `sudo tcpdump -i any udp port 9537`.

### 3. Configure TCP Network Export
1. Open `squid.conf` and add the network target: `access_log tcp://<AGENT_IP>:9537 squid`.
2. Restart the service: `sudo systemctl restart squid`.
3. Check the connection status: `ss -ant | grep 9537`.

### Vendor Set up Resources

- [Squid Log Modules - Official Wiki](https://wiki.squid-cache.org/Features/LogModules)
- [Squid Access Log FAQ - Official Wiki](https://wiki.squid-cache.org/SquidFaq/SquidLogs)

## Kibana set up steps

### Collecting syslog from Squid via UDP
1. In Kibana, navigate to **Integrations** and search for **Squid**.
2. Click **Add Squid** and select the **Collecting syslog from Squid via UDP** input.
3. Configure the following variables:
   - **UDP host to listen on** (`udp_host`): The interface the agent should listen on. Default: `localhost`.
   - **UDP port to listen on** (`udp_port`): The port to listen for incoming Squid logs. Default: `9537`.
   - **Preserve original event** (`preserve_original_event`): Preserves a raw copy of the original event, added to the field `event.original`. Default: `False`.
   - **Tags** (`tags`): Custom tags to add to the events. Default: `['squid-log', 'forwarded']`.
   - **Custom UDP Options** (`udp_options`): Specify custom configuration options for the UDP input such as `read_buffer`, `max_message_size`, or `timeout`.
   - **Processors** (`processors`): Processors are used to reduce the number of fields in the exported event or to enhance the event with metadata. This executes in the agent before the logs are parsed.
4. Save and deploy the integration.

### Collecting syslog from Squid via TCP
1. In Kibana, navigate to **Integrations** and search for **Squid**.
2. Click **Add Squid** and select the **Collecting syslog from Squid via TCP** input.
3. Configure the following variables:
   - **TCP host to listen on** (`tcp_host`): The interface the agent should listen on. Default: `localhost`.
   - **TCP port to listen on** (`tcp_port`): The port to listen for incoming Squid logs. Default: `9537`.
   - **Preserve original event** (`preserve_original_event`): Preserves a raw copy of the original event, added to the field `event.original`. Default: `False`.
   - **Tags** (`tags`): Custom tags to add to the events. Default: `['squid-log', 'forwarded']`.
   - **SSL Configuration** (`ssl`): SSL configuration options including `certificate` and `key` paths for encrypted transport.
   - **Custom TCP Options** (`tcp_options`): Specify custom configuration options for the TCP input, such as `max_message_size`.
   - **Processors** (`processors`): Define processors to enhance or filter data in the agent before parsing.
4. Save and deploy the integration.

### Collecting syslog from Squid via filestream
1. In Kibana, navigate to **Integrations** and search for **Squid**.
2. Click **Add Squid** and select the **Collecting syslog from Squid via filestream** input.
3. Configure the following variables:
   - **Paths** (`paths`): The list of paths to look for Squid log files. Default: `['/var/log/squid-log.log']`.
   - **Preserve original event** (`preserve_original_event`): Preserves a raw copy of the original event, added to the field `event.original`. Default: `False`.
   - **Tags** (`tags`): Custom tags to identify logs from this input. Default: `['squid-log', 'forwarded']`.
   - **Processors** (`processors`): Define optional processors for data enhancement or filtering.
4. Save and deploy the integration.

# Validation Steps

After configuration is complete, verify that data is flowing correctly.

### 1. Trigger Data Flow on Squid:
- **Generate web traffic:** From a client machine configured to use the Squid proxy, browse to several different websites (e.g., `http://example.com`) to generate access log entries.
- **Test via command line:** Use `curl` on a client to make a request through the proxy: `curl -x http://<SQUID_IP>:<SQUID_PORT> http://www.elastic.co`.
- **Authentication event:** If proxy authentication is enabled, attempt to log in with both valid and invalid credentials to generate authentication-related log entries.

### 2. Check Data in Kibana:
1. Navigate to **Analytics > Discover**.
2. Select the `logs-*` data view.
3. Enter the KQL filter: `data_stream.dataset : "squid.log"`
4. Verify logs appear. Expand a log entry and confirm these fields:
   - `event.dataset` (should be `squid.log`)
   - `source.ip` (the IP of the client making the request)
   - `event.outcome` (the result of the proxy request)
   - `message` (the raw log payload)
5. Navigate to **Analytics > Dashboards** and search for "Squid Proxy" to view pre-built visualizations.

# Troubleshooting

## Common Configuration Issues

- **Incorrect Log Format**: If logs are appearing in Kibana but are not being parsed correctly, ensure the `access_log` directive in `squid.conf` includes the `squid` keyword at the end. This integration specifically expects the Native log format.
- **Port Conflicts**: If using TCP or UDP collection, ensure no other service is using port `9537` on the Agent host. Use `sudo lsof -i :9537` to check for existing listeners.
- **File Permissions**: When using the filestream input, ensure the Elastic Agent user has read permissions for the Squid log directory and the `access.log` file itself (e.g., `chmod 644 /var/log/squid/access.log`).
- **Firewall Obstructions**: If logs are sent via network but not appearing, check the firewall settings on both the Squid server (egress) and the Agent host (ingress) to allow traffic on the configured port.

## Ingestion Errors

- **Parsing Failures**: Look for the `error.message` or `tags` field in Discover containing `_grokparsefailure`. This usually indicates that the log format in Squid has been customized away from the standard Native format.
- **Timestamp Mismatches**: Squid logs use Unix timestamps with milliseconds. Ensure the system clock on both the Squid server and the Elastic Agent host are synchronized via NTP to avoid "event in the future" or "late arrival" issues.
- **Field Mapping Issues**: If specific fields like `source.ip` are missing, verify that the `logformat` directive has not been modified to remove those specific tokens.

## Vendor Resources

- [Squid Access Log Wiki](https://wiki.squid-cache.org/SquidFaq/SquidLogs#accesslog)
- [Squid Native Log Format Details](https://wiki.squid-cache.org/Features/LogFormat#squid-native-accesslog-format-in-detail)
- [Squid Log Modules Configuration](https://wiki.squid-cache.org/Features/LogModules#Module:_System_Log)

# Documentation sites

- [Squid Access Log FAQ - Official Wiki](https://wiki.squid-cache.org/SquidFaq/SquidLogs)
