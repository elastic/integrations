# Cisco IOS Integration for Elastic

> **Note**: This documentation was generated using AI and should be reviewed for accuracy.

## Overview

The Cisco IOS integration for Elastic enables you to collect system logs from Cisco routers and switches, providing centralized visibility into network health and security events. By ingesting these logs into the Elastic Stack, you can monitor infrastructure stability, respond to critical events in real-time, and maintain historical records of system activity for your network environment.

This integration facilitates:
- Security monitoring and auditing: Track unauthorized access attempts, configuration changes, and privilege escalations across the entire network fabric by analyzing system message logs.
- Network troubleshooting: Rapidly identify and diagnose hardware failures, interface flapping, or routing protocol changes such as EIGRP or OSPF state transitions using centralized log data.
- Compliance and reporting: Maintain long-term historical records of system events to meet regulatory requirements for network logging and audit trails.
- Performance visibility: Monitor system-level notifications regarding resource exhaustion, such as high CPU or memory utilization alerts, to proactively manage device health.

### Compatibility

This integration is compatible with Cisco IOS and Cisco IOS-XE network devices that support standard syslog output over TCP, UDP, or local file logging. It's generally applicable to all modern Cisco IOS versions that support the `logging host` command and `service timestamps` configuration. Note that older versions of IOS might not support TCP transport for syslog; UDP is the most universally compatible method.

### How it works

This integration collects logs from Cisco IOS devices by receiving syslog data over TCP or UDP, or by reading directly from log files. You'll deploy an Elastic Agent on a host that's configured as a syslog receiver or has access to the log files. The agent collects the `log` data stream, parses the messages, and forwards them to your Elastic deployment where they're mapped to the Elastic Common Schema (ECS) for analysis.

## What data does this integration collect?

The Cisco IOS integration collects log messages of the following types:
* System message logs: Standard Cisco IOS logging messages including facility, severity, mnemonic, and descriptive text.
* Authentication logs: Events related to user logins, logouts, and command execution when you've enabled AAA logging on your devices.
* Interface logs: Status updates regarding physical and logical interfaces, including up/down state transitions.
* Protocol events: Log entries from routing protocols and network services like DHCP, VPN, and Spanning Tree.

This integration uses the `log` data stream to organize the collected information. This stream supports standard Cisco syslog formats and includes fields for sequencing and millisecond timestamps. You can collect these logs using the following methods:
* Network inputs: Collect logs directly via `UDP` or `TCP` inputs.
* File inputs: Collect logs from files for environments where logs are written to a local disk or an intermediate log aggregator.

### Supported use cases

Integrating your Cisco IOS logs with the Elastic Stack provides several benefits:
* Real-time security monitoring: You'll detect and respond to potential threats by monitoring authentication events and command execution across your network.
* Network performance analysis: You can use Kibana dashboards to visualize and analyze network traffic patterns, which helps you identify anomalies and optimize performance.
* Rapid incident response: When issues occur, you'll have a centralized location to correlate Cisco IOS data with other security and observability sources.
* Compliance and auditing: You'll maintain a searchable, long-term archive of logs to meet regulatory requirements and conduct thorough security audits.

## What do I need to use this integration?

Before you start collecting logs from your Cisco IOS devices, you'll need to ensure your environment meets these requirements.

### Vendor prerequisites

To configure your Cisco hardware, you must meet these prerequisites:
- You'll need privileged EXEC mode (`enable`) access to the Cisco device CLI to perform the necessary configuration.
- Your device needs a clear network path to the Elastic Agent. You'll also need to ensure firewall rules allow traffic on the configured port (the default is `9002`).
- You must enable the `service timestamps` feature on the device to ensure that logs are formatted correctly for the integration to parse.
- You'll need to configure a hostname on the device because the integration expects this field to be present in the syslog header.
- You'll need a stable source interface, such as a Loopback address, to ensure that logs are sent from a consistent IP address.

### Elastic prerequisites

To prepare your Elastic Stack environment, you'll need the following:
- You'll need an active Elastic Agent installed and enrolled in Fleet.
- It's recommended that you use Elastic Stack version `8.11.0` or later for full support of this integration's data streams.
- Ensure the Cisco devices can reach the Elastic Agent over the network via the specified TCP or UDP ports.
- You'll need the necessary roles and permissions in Kibana to manage integrations and Fleet policies.

## How do I deploy this integration?

### Agent-based deployment

You must install Elastic Agent on a host that can receive syslog data or access the log files from your Cisco IOS devices. For detailed instructions, see the Elastic Agent [installation guide](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You only need one Elastic Agent per host.

You'll need Elastic Agent to stream data from the syslog or log file receiver and ship it to Elastic, where the integration's ingest pipelines process the events.

### Set up steps in Cisco IOS

To set up **UDP** or **TCP** syslog collection, follow these steps:

1.  Log in to your Cisco IOS device via SSH, Telnet, or a Console cable and enter privileged EXEC mode using the `enable` command.

2.  Access global configuration mode by typing `configure terminal`.

3.  Enable timestamps for log messages to ensure Elastic Agent can parse the events:

    ```bash
    service timestamps log datetime
    ```
    For higher precision, you can use `service timestamps log datetime msec show-timezone`.

4.  Direct the device to the IP address of the Elastic Agent. Replace `<ELASTIC_AGENT_IP>` (replace with your actual value) with your Agent's IP and use the default port `9002`:
    ```bash
    logging <ELASTIC_AGENT_IP>
    logging trap <ELASTIC_AGENT_IP> transport udp port 9002
    ```
    *Note: Change `udp` to `tcp` and update the port if you've customized the Kibana input settings.*

5.  Define which logs to send to the Agent. Level 6 (informational) is a common starting point:
    ```bash
    logging trap informational
    ```

6.  Ensure all logs originate from a consistent IP address, such as `Loopback0`:
    ```bash
    logging source-interface Loopback0
    ```

7.  Exit configuration mode and save the changes to the startup configuration:
    ```bash
    end
    write memory
    ```

8.  Run the `show logging` command to confirm the remote host is configured and logs are being generated.

To set up **log file** collection, follow these steps:

1.  Log in to your device and enter global configuration mode.

2.  Ensure logs are being written to a local buffer or a file that the Elastic Agent can access:

    ```bash
    logging buffered 16384
    ```

3.  If the Elastic Agent is running on a host that mounts a filesystem from the Cisco device or receives files via SCP/FTP, ensure the Agent service has read permissions for the target log file path. The default path is `/var/log/cisco-ios.log`.

#### Vendor resources

For more information, refer to the following Cisco documentation:
- [Configuring System Message Logs - Cisco IOS XE 17.17.x](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-17/configuration_guide/sys_mgmt/b_1717_sys_mgmt_9300_cg/configuring_system_message_logs.html)
- [How to configure logging in Cisco IOS - Cisco Community](https://community.cisco.com/t5/networking-knowledge-base/how-to-configure-logging-in-cisco-ios/ta-p/3132434)
- [Cisco Syslog Configuration Step-by-Step](https://www.auvik.com/franklyit/blog/configure-syslog-cisco/)

### Set up steps in Kibana

1.  In Kibana, navigate to **Management > Integrations**.
2.  Search for **Cisco IOS** and select the integration.
3.  Click **Add Cisco IOS**.
4.  Configure the integration by selecting an input type and providing the necessary settings. This integration supports `TCP`, `UDP`, and `Log file` inputs.

Choose the configuration steps below that match your environment.

#### Collecting logs from Cisco IOS via TCP

This input collects logs over a TCP socket. Configure the following variables:

| Setting                 | Description                                                                                    |
| ----------------------- | ---------------------------------------------------------------------------------------------- |
| Host to listen on       | The interface address the agent should bind to (e.g., `0.0.0.0`).                              |
| Syslog Port             | The TCP port to listen for Cisco logs (e.g., `9002`).                                          |
| Preserve original event | If you check this, a raw copy of the original event is added to the `event.original` field.    |
| Tags                    | List of tags to add to the events (e.g., `cisco-ios`, `forwarded`).                            |
| Timezone                | IANA time zone or offset (e.g., `+0200`) to use when syslog timestamps don't have a time zone. |
| Timezone Map            | A mapping of timezones as they appear in Cisco IOS logs to standard IANA formats.              |
| Processors              | Add custom processors to reduce or enhance event fields.                                       |
| SSL Configuration       | Configure SSL options for encrypted communication.                                             |
| Custom TCP Options      | Specify custom configuration options for the TCP input.                                        |

#### Collecting logs from Cisco IOS via UDP

This input collects logs over a UDP socket. Configure the following variables:

| Setting                 | Description                                                                                    |
| ----------------------- | ---------------------------------------------------------------------------------------------- |
| Host to listen on       | The interface address the agent should bind to (e.g., `0.0.0.0`).                              |
| Syslog Port             | The UDP port to listen for Cisco logs (e.g., `9002`).                                          |
| Preserve original event | If you check this, a raw copy of the original event is added to the `event.original` field.    |
| Tags                    | List of tags to add to the events (e.g., `cisco-ios`, `forwarded`).                            |
| Timezone                | IANA time zone or offset (e.g., `+0200`) to use when syslog timestamps don't have a time zone. |
| Timezone Map            | A mapping of timezones as they appear in Cisco IOS logs to standard IANA formats.              |
| Custom UDP Options      | Specify custom configuration options for the UDP input.                                        |
| Processors              | Add custom processors to reduce or enhance event fields.                                       |

#### Collecting logs from Cisco IOS via file

This input collects logs directly from log files on the host where the Elastic Agent is running. Configure the following variables:

| Setting                 | Description                                                                                    |
| ----------------------- | ---------------------------------------------------------------------------------------------- |
| Paths                   | List of file paths to monitor (e.g., `/var/log/cisco-ios.log`).                                |
| Preserve original event | If you check this, a raw copy of the original event is added to the `event.original` field.    |
| Tags                    | List of tags to add to the events (e.g., `cisco-ios`, `forwarded`).                            |
| Timezone                | IANA time zone or offset (e.g., `+0200`) to use when syslog timestamps don't have a time zone. |
| Timezone Map            | A mapping of timezones as they appear in Cisco IOS logs to standard IANA formats.              |
| Processors              | Add custom processors to reduce or enhance event fields.                                       |

After you finish configuring the input, assign the integration to an agent policy and click **Save and continue**.

### Validation

To ensure your integration works correctly, you can trigger specific events on your Cisco IOS device using these commands:

- Trigger a configuration event by entering and exiting global configuration mode:
  ```bash
  configure terminal
  exit
  ```
- Trigger an interface event by toggling a non-critical interface:
  ```bash
  interface Loopback99
  shutdown
  no shutdown
  ```
- Trigger an authentication event by logging out and logging back in to your SSH or Console session.

Next, verify the data in Kibana:

1.  Navigate to **Analytics > Discover**.
2.  Select the `logs-*` data view.
3.  Enter the following KQL filter in the search bar: `data_stream.dataset : "cisco_ios.log"`.
4.  Confirm that logs appear with recent timestamps.
5.  Check for the following fields to confirm data is mapped correctly:
    - `event.dataset` should be `cisco_ios.log`.
       - `event.severity` or `event.sequence` should be populated.
       - `observer.vendor` should be `Cisco`.
       - `message` should contain the raw Cisco log payload.
6.  Navigate to **Analytics > Dashboards** and search for **Cisco IOS** to view the pre-built dashboards populated with your data.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Common configuration issues

You might encounter the following issues when configuring or using the Cisco IOS integration:

- **No data is being collected**: Verify network connectivity between the Cisco device and the Elastic Agent host. Ensure there are no firewalls or network ACLs blocking the syslog port. Confirm that the listening port configured in the Elastic integration matches the destination port configured on the device.
- **Log format requirements**: Your Cisco appliance might be configured to include or exclude various fields. This integration expects the hostname and timestamp to be present in the logs. If `sequence-number` is configured, it populates the `event.sequence` field; otherwise, `message-count` is used if available.
- **Missing timestamps**: Timestamps and timezones aren't enabled by default for Cisco IOS logging. You can enable them by using the `service timestamps log datetime` command on your device. Without this, the integration can't accurately determine the event time.
- **Timezone configuration**: Cisco IOS logs often use non-standard timezone formats. You can use the `Timezone` option to specify a single offset for all logs or use the `Timezone Map` setting for more complex environments with multiple timezones.
- **Port conflict**: If the Elastic Agent fails to start the input, check if another service is already using port `9002`. You can verify this on the host using a command like `netstat -ano | grep 9002`.
- **Firewall blockage**: If you see that messages are being logged on the Cisco device but no data reaches Kibana, ensure that the UDP or TCP port `9002` is open on any intermediate firewalls and the Elastic Agent host's local firewall.
- **Relayed log headers**: If you send logs to a central syslog server (like `syslog-ng` or `rsyslog`) before they reach the Elastic Agent, that server might add its own headers. You can use a processor in your configuration to strip these extra prefixes before ingestion.
- **Timezone mapping failures**: If your logs show an incorrect time that's offset by several hours, ensure your `Timezone Map` is configured to correctly translate Cisco's short-form timezone strings (like `AEST`) to standard IANA formats.
- **Incomplete log parsing**: Check the `error.message` field in Kibana Discover. If it contains `pattern not found`, verify that your Cisco device isn't using a custom log format that deviates from the standard `facility-severity-mnemonic` structure.

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

To ensure you get the best performance from Cisco IOS in high-volume networking environments, consider these recommendations for the `log` data stream:
- Use `UDP` for low overhead in high-volume log streams, or use `TCP` in environments that require guaranteed delivery to prevent data loss during network congestion.
- Use the `logfile` input for the most reliable collection method if you co-locate the Elastic Agent on a management server that has access to device logs.
- Manage data volume by using the `logging trap <level>` (replace `<level>` with your actual value) command on your Cisco devices to filter logs by severity at the source.
- Collect levels 0 (emergencies) through 5 (notifications) for standard monitoring.
- Avoid using level 7 (debugging) in production unless you're troubleshooting, as it can generate excessive volume that impacts both device performance and ingest pipelines.
- Deploy multiple Elastic Agents behind a network load balancer like F5 or HAProxy to distribute `UDP` or `TCP` traffic in high-throughput environments receiving logs from thousands of interfaces.
- Ensure your Elastic Agent host has enough CPU resources for the parsing overhead associated with `grok` patterns and `tz_map` translations.

## Reference

### Inputs used

{{ inputDocs }}

### Data streams

#### log

The `log` data stream provides events from Cisco IOS devices of the following types:
- System messages
- Configuration changes
- Interface status updates

##### log fields

{{ fields "log" }}

##### log sample event

{{ event "log" }}

### Vendor documentation links

For more information about Cisco IOS logging and troubleshooting, refer to these resources:
- [Cisco System Message Logging Guide](https://www.cisco.com/c/en/us/td/docs/routers/access/wireless/software/guide/SysMsgLogging.html)
- [Configuring System Message Logs - Cisco IOS XE 17.17.x](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-17/configuration_guide/sys_mgmt/b_1717_sys_mgmt_9300_cg/configuring_system_message_logs.html)
- [How to configure logging in Cisco IOS - Cisco Community](https://community.cisco.com/t5/networking-knowledge-base/how-to-configure-logging-in-cisco-ios/ta-p/3132434)
- [Cisco Syslog Configuration Step-by-Step | Auvik](https://www.auvik.com/franklyit/blog/configure-syslog-cisco/)
