# Service Info

## Common use cases
The Cisco IOS integration allows for the centralized collection and analysis of system logs from Cisco routers and switches, providing deep visibility into network health and security events. By ingesting these logs into the Elastic Stack, administrators can monitor infrastructure stability and respond to critical events in real-time.
- **Security Monitoring and Auditing:** Track unauthorized access attempts, configuration changes, and privilege escalations across the entire network fabric by analyzing system message logs.
- **Network Troubleshooting:** Rapidly identify and diagnose hardware failures, interface flapping, or routing protocol changes (such as EIGRP or OSPF state changes) using centralized log data.
- **Compliance and Reporting:** Maintain long-term historical records of system events to meet regulatory requirements for network logging and audit trails.
- **Performance Visibility:** Monitor system-level notifications regarding resource exhaustion, such as high CPU or memory utilization alerts, to proactively manage device health.

## Data types collected
This integration can collect the following types of data:
- **System Message Logs:** Standard Cisco IOS logging messages including facility, severity, mnemonic, and descriptive text.
- **Authentication Logs:** Events related to user logins, logouts, and command execution (when AAA logging is enabled).
- **Interface Logs:** Status updates regarding physical and logical interfaces, including "up/down" state transitions.
- **Protocol Events:** Log entries from routing protocols and network services like DHCP, VPN, and Spanning Tree.
- **Data Streams:**
  - **Cisco IOS logs (log):** Collect Cisco IOS logs. This stream supports standard Cisco syslog formats and includes fields for sequencing and millisecond timestamps.
  - **Cisco IOS logs (log):** Collect Cisco IOS logs via UDP or TCP inputs.
  - **Cisco IOS logs (log):** Collect Cisco IOS logs from file for environments where logs are written to a local disk or intermediate log aggregator.

## Compatibility
This integration is compatible with **Cisco IOS** and **Cisco IOS-XE** network devices that support standard syslog output over TCP, UDP, or local file logging.
- **Versions:** Generally applicable to all modern Cisco IOS versions that support the `logging host` command and `service timestamps` configuration.
- **Protocol Support:** Older versions of IOS may not support TCP transport for syslog; UDP is the most universally compatible method.

## Scaling and Performance
To ensure optimal performance in high-volume networking environments, consider the following:
- **Transport/Collection Considerations:** While UDP provides lower overhead for high-volume log streams, TCP is recommended for environments requiring guaranteed delivery to prevent data loss during network congestion. If the Elastic Agent is co-located on a management server with access to device logs, using the **logfile** input is the most reliable collection method.
- **Data Volume Management:** Use the `logging trap <level>` command on Cisco devices to filter logs by severity at the source. It is recommended to collect levels 0 (emergencies) through 5 (notifications) for standard monitoring. Avoid level 7 (debugging) in production unless troubleshooting, as it can generate excessive volume that impacts both device performance and ingest pipelines.
- **Elastic Agent Scaling:** For high-throughput environments receiving logs from thousands of interfaces, deploy multiple Elastic Agents behind a network load balancer (e.g., F5, HAProxy) to distribute UDP/TCP traffic. Ensure the Agent host has sufficient CPU resources for the parsing overhead associated with `grok` patterns and `tz_map` translations.

# Set Up Instructions

## Vendor prerequisites
1. **Administrative Access:** Privileged EXEC mode (`enable`) access to the Cisco device CLI is required for configuration.
2. **Network Connectivity:** The device must have a clear network path to the Elastic Agent. Ensure firewall rules allow traffic on the configured port (default is **9002**).
3. **Service Configuration:** The `service timestamps` feature must be enabled to ensure logs are parsable by the integration.
4. **Identity Information:** The device must be configured with a hostname, as the integration expects this field to be present in the syslog header.
5. **Interface Selection:** A stable source interface, such as a Loopback address, should be available to ensure logs are sent from a consistent IP address.

## Elastic prerequisites
- **Elastic Agent:** An active Elastic Agent must be installed and enrolled in Fleet.
- **Elastic Stack Version:** It is recommended to use Elastic Stack version 8.0 or later for full support of this integration's data streams.
- **Connectivity:** The Elastic Agent must be reachable by the Cisco devices over the network via the specified TCP or UDP ports.
- **Permissions:** The user configuring the integration in Kibana must have the necessary roles to manage Integrations and Fleet policies.

## Vendor set up steps

### For UDP/TCP (Syslog) Collection:
1. **Access the Device CLI:** Log in to your Cisco IOS device via SSH, Telnet, or a Console cable and enter privileged EXEC mode using the `enable` command.
2. **Enter Configuration Mode:** Access global configuration mode by typing `configure terminal`.
3. **Enable Timestamps:** This is a critical step. Enable timestamps for log messages to ensure the Elastic Agent can parse the events:
   ```bash
   service timestamps log datetime
   ```
   *Note: For higher precision, use `service timestamps log datetime msec show-timezone`.*
4. **Configure the Remote Logging Host:** Direct the device to the IP address of the Elastic Agent. Replace `<ELASTIC_AGENT_IP>` with your Agent's IP and use the default port **9002**:
   ```bash
   logging <ELASTIC_AGENT_IP>
   logging trap <ELASTIC_AGENT_IP> transport udp port 9002
   ```
   *Note: Change `udp` to `tcp` and update the port if you have customized the Kibana input settings.*
5. **Set Logging Severity:** Define which logs should be sent to the Agent. Level 6 (informational) is a common starting point:
   ```bash
   logging trap informational
   ```
6. **Set Source Interface:** Ensure all logs originate from a consistent IP address (e.g., Loopback0):
   ```bash
   logging source-interface Loopback0
   ```
7. **Exit and Save:** Exit configuration mode and save the changes to the startup configuration:
   ```bash
   end
   write memory
   ```
8. **Verify Logging:** Run the `show logging` command to confirm that the remote host is configured and logs are being generated.

### For Logfile Collection:
1. **Access the Device CLI:** Log in to your device and enter global configuration mode.
2. **Configure Local Logging:** Ensure logs are being written to a local buffer or a file that can be accessed by the Elastic Agent:
   ```bash
   logging buffered 16384
   ```
3. **Ensure File Access:** If the Elastic Agent is running on a host that mounts a filesystem from the Cisco device or receives files via SCP/FTP, ensure the Agent service has read permissions for the target log file path (default: `/var/log/cisco-ios.log`).

### Vendor Set up Resources
- [Configuring System Message Logs - Cisco IOS XE 17.17.x](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-17/configuration_guide/sys_mgmt/b_1717_sys_mgmt_9300_cg/configuring_system_message_logs.html) - Official guide for configuring logging on modern Cisco platforms.
- [How to configure logging in Cisco IOS - Cisco Community](https://community.cisco.com/t5/networking-knowledge-base/how-to-configure-logging-in-cisco-ios/ta-p/3132434) - Community-driven guide for standard IOS logging configuration.
- [Cisco Syslog Configuration Step-by-Step | Auvik](https://www.auvik.com/franklyit/blog/configure-syslog-cisco/) - Detailed walkthrough for configuring syslog on Cisco hardware.

## Kibana set up steps

### Collecting logs from Cisco IOS via TCP
1. In Kibana, navigate to **Management > Integrations** and search for **Cisco IOS**.
2. Click **Add Cisco IOS**.
3. Select the **Collecting logs from Cisco IOS via TCP** input type.
4. Configure the following variables:
   - **Host to listen on** (`syslog_host`): The interface address the agent should bind to. Default: `localhost`.
   - **Syslog Port** (`syslog_port`): The TCP port to listen for Cisco logs. Default: `9002`.
   - **Preserve original event** (`preserve_original_event`): Preserves a raw copy of the original event, added to the field `event.original`. Default: `False`.
   - **Tags** (`tags`): List of tags to add to the events. Default: `['cisco-ios', 'forwarded']`.
   - **Timezone** (`tz_offset`): IANA time zone or time offset (e.g. `+0200`) to use when interpreting syslog timestamps without a time zone. Default: `UTC`.
   - **Timezone Map** (`tz_map`): A combination of timezones as they appear in the Cisco IOS log, in combination with a proper IANA Timezone format. 
   - **Processors** (`processors`): Processors are used to reduce the number of fields in the exported event or to enhance the event with metadata. See [Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details.
   - **SSL Configuration** (`ssl`): SSL configuration options. See [documentation](https://www.elastic.co/guide/en/beats/filebeat/current/configuration-ssl.html#ssl-common-config) for details.
   - **Custom TCP Options** (`tcp_options`): Specify custom configuration options for the TCP input. See [TCP](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-tcp.html) for details.
5. Click **Save and continue**.

### Collecting logs from Cisco IOS via UDP
1. In Kibana, navigate to **Management > Integrations** and search for **Cisco IOS**.
2. Click **Add Cisco IOS**.
3. Select the **Collecting logs from Cisco IOS via UDP** input type.
4. Configure the following variables:
   - **Host to listen on** (`syslog_host`): The interface address for the UDP listener. Default: `localhost`.
   - **Syslog Port** (`syslog_port`): The UDP port to listen for Cisco logs. Default: `9002`.
   - **Preserve original event** (`preserve_original_event`): Preserves a raw copy of the original event, added to the field `event.original`. Default: `False`.
   - **Tags** (`tags`): Custom tags for event identification. Default: `['cisco-ios', 'forwarded']`.
   - **Timezone** (`tz_offset`): IANA time zone or time offset (e.g. `+0200`) for interpreting timestamps without a time zone. Default: `UTC`.
   - **Timezone Map** (`tz_map`): A combination of timezones as they appear in the Cisco IOS log, in combination with a proper IANA Timezone format.
   - **Custom UDP Options** (`udp_options`): Specify custom configuration options for the UDP input. See [UDP](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-udp.html) for details.
   - **Processors** (`processors`): Processors are used to reduce the number of fields in the exported event or to enhance the event with metadata.
5. Click **Save and continue**.

### Collecting logs from Cisco IOS via file
1. In Kibana, navigate to **Management > Integrations** and search for **Cisco IOS**.
2. Click **Add Cisco IOS**.
3. Select the **Collecting logs from Cisco IOS via file** input type.
4. Configure the following variables:
   - **Paths** (`paths`): List of file paths to monitor. Default: `['/var/log/cisco-ios.log']`.
   - **Preserve original event** (`preserve_original_event`): Preserves the raw log in `event.original`. Default: `False`.
   - **Tags** (`tags`): Identification tags. Default: `['cisco-ios', 'forwarded']`.
   - **Timezone** (`tz_offset`): Timezone to use when interpreting syslog timestamps without a time zone. Default: `UTC`.
   - **Timezone Map** (`tz_map`): Mapping for short-form Cisco timezones to IANA formats.
   - **Processors** (`processors`): Optional processors for pre-ingestion logic.
5. Click **Save and continue**.

# Validation Steps

After configuration is complete, verify that data is flowing correctly.

### 1. Trigger Data Flow on Cisco IOS:
- **Generate configuration event:** Enter global configuration mode and exit to trigger a "Configured from console" log message.
  ```bash
  configure terminal
  exit
  ```
- **Trigger interface event:** Safely toggle a non-critical or administrative interface to generate link status logs.
  ```bash
  interface Loopback99
  shutdown
  no shutdown
  ```
- **Generate authentication event:** Log out of the current SSH or Console session and log back in to trigger login/logout events.

### 2. Check Data in Kibana:
1. Navigate to **Analytics > Discover**.
2. Select the `logs-*` data view.
3. Enter the KQL filter: `data_stream.dataset : "cisco_ios.log"`
4. Verify logs appear. Expand a log entry and confirm these fields:
   - `event.dataset` (should be `cisco_ios.log`)
   - `event.severity` or `event.sequence`
   - `observer.vendor` (should be `Cisco`)
   - `message` (containing the raw Cisco log payload)
5. Navigate to **Analytics > Dashboards** and search for "Cisco IOS" to view pre-built visualizations.

# Troubleshooting

## Common Configuration Issues
- **Log Format Requirements**: The Cisco appliance may be [configured in a variety of ways](https://www.cisco.com/c/en/us/td/docs/routers/access/wireless/software/guide/SysMsgLogging.html) to include or exclude fields. The integration expects the host name and timestamp to be present. If `sequence-number` is configured it will populate `event.sequence`, otherwise `message-count` will be used if available.
- **Missing Timestamps**: Timestamps and timezones are by default not enabled for Cisco IOS logging. To enable them, use `service timestamps log datetime`. For more information, see the [Timestamp documentation](https://www.cisco.com/c/en/us/td/docs/routers/access/wireless/software/guide/SysMsgLogging.html#wp1054710). Without this, the integration cannot determine the event time.
- **Timezone Configuration**: The format of timezones in Cisco IOS logs may not match standard formats. Use the `Timezone` option to specify a single timezone (default: `UTC`) for all logs, or use `Timezone Map` for advanced scenarios with multiple timezones. Unmapped timezones fall back to the `Timezone` setting.
- **Port Conflict**: If the Elastic Agent fails to start the input, check if another service is already using port 9002. Use `netstat -ano | grep 9002` to verify.
- **Firewall Blockage**: If the `show logging` command on the Cisco device shows increments in "Messages logged" but no data reaches Kibana, ensure UDP/TCP port 9002 is open on any intermediate firewalls and the Agent host's local firewall.
- **Relayed Log Headers**: If logs are sent to a central syslog server before the Elastic Agent or are relayed resulting in additional syslog header prefixes, that server may add its own headers. Use a Beats processor in the Kibana configuration to strip these extra prefixes before ingestion.

## Ingestion Errors
- **Syslog Relay Headers**: If logs are forwarded through a central syslog-ng or rsyslog server, they may have extra headers. Use a "drop" or "replace" processor in the Elastic Agent configuration to strip these before parsing.
- **Timezone Mapping Failures**: If logs show an incorrect time (offset by several hours), ensure the `Timezone Map` is configured to translate Cisco's non-standard timezone strings (like `AEST`) to IANA formats.
- **Incomplete Log Parsing**: Check the `error.message` field in Kibana Discover. If it contains "pattern not found", verify that the Cisco device is not using a custom log format that deviates from the standard `facility-severity-mnemonic` structure.

## Vendor Resources
- [Cisco System Message Logging Guide](https://www.cisco.com/c/en/us/td/docs/routers/access/wireless/software/guide/SysMsgLogging.html)

# Documentation sites
- [Cisco IOS Integration Reference](https://www.elastic.co/docs/reference/integrations/cisco_ios)
- [Cisco System Message Logging Documentation](https://www.cisco.com/c/en/us/td/docs/routers/access/wireless/software/guide/SysMsgLogging.html)
