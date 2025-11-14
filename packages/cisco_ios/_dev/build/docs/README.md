# Cisco IOS Integration for Elastic

## Overview

The Cisco IOS integration for Elastic collects logs from Cisco IOS devices, enabling real-time visibility into network activity, security events, and operational health. This integration facilitates network security monitoring, compliance reporting, and troubleshooting by parsing and visualizing syslog messages from Cisco routers and switches.

### How it works

This integration receives syslog messages from Cisco IOS devices through the Elastic Agent. It can be configured to listen for logs over TCP or UDP, or to read them directly from a log file. The Elastic Agent processes these logs, parsing them into structured fields, and securely sends them to your Elastic deployment for analysis and visualization.

### Compatibility

This integration is compatible with a wide range of Cisco devices running Cisco IOS software, including routers and switches.

**Elastic Stack Requirements:**
- Elastic Stack version 8.11.0 or higher

## What data does this integration collect?

The Cisco IOS integration collects various types of log messages, including:

*   **System Messages**: Captures administrative actions, configuration changes, and system restarts.
*   **Security Events**: Monitors for access control list (ACL) violations, authentication failures, and other security-related events.
*   **Network Events**: Tracks interface status changes (up/down), routing protocol updates, and other network-related messages.
*   **Traffic Logs**: Collects data on IPv4 and IPv6 traffic, including source/destination IP addresses and ports.
*   **Protocol-specific Messages**: Logs events related to protocols like ICMP, TCP, UDP, and IGMP.

### Supported use cases

*   **Network Security Monitoring**: Actively monitor network device logs for security threats like unauthorized access attempts and ACL violations.
*   **Compliance Reporting**: Collect and archive logs to meet regulatory compliance requirements (e.g., PCI DSS, SOX).
*   **Network Operations Management**: Gain visibility into the health and status of network devices, track configuration changes, and monitor system events.
*   **Troubleshooting**: Quickly diagnose and resolve network issues, hardware failures, and configuration problems by analyzing detailed device logs.

## What do I need to use this integration?

### Vendor Prerequisites

*   A Cisco IOS device with network connectivity to the host running the Elastic Agent.
*   Administrative access to the Cisco device to configure syslog settings.
*   **Important**: Timestamps must be enabled on the Cisco IOS device, as they are not on by default. Use the command `service timestamps log datetime`.

### Elastic Prerequisites

*   Elastic Agent must be installed on a host that can receive syslog messages from your Cisco devices.
*   The host running the Elastic Agent must have the specified listening port (e.g., 9002) open and accessible from the Cisco devices.
*   Firewall rules must be configured to allow syslog traffic from your network devices to the Elastic Agent host.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent is required to stream data from the syslog receiver or log file and ship it to Elastic, where the events will be processed by the integration's ingest pipelines. You can install only one Elastic Agent per host. For detailed instructions, see the Elastic Agent [installation guide](docs-content://reference/fleet/install-elastic-agents.md).

### Onboard / configure

#### 1. Configure Syslog on Cisco IOS Devices

Log into your Cisco IOS device to perform the following steps.

1.  **Enable Timestamp Logging (Required)**:
    This ensures that logs have the correct timestamp.
    ```shell
    configure terminal
    service timestamps log datetime
    exit
    ```

2.  **Enable Sequence Numbers (Optional)**:
    This adds a sequence number to each log message, which populates the `event.sequence` field.
    ```shell
    configure terminal
    service sequence-numbers
    exit
    ```

3.  **Configure Syslog Destination**:
    Point your Cisco device to the Elastic Agent's IP address and port. Replace `<ELASTIC_AGENT_IP>` with the actual IP address of your agent host.

    *   **For UDP**:
        ```shell
        configure terminal
        logging host <ELASTIC_AGENT_IP> transport udp port 9002
        exit
        ```
    *   **For TCP**:
        ```shell
        configure terminal
        logging host <ELASTIC_AGENT_IP> transport tcp port 9002
        exit
        ```

4.  **Set Logging Severity Level (Optional)**:
    Adjust the logging level to control the verbosity of the logs. `informational` (level 6) is a common choice.
    ```shell
    configure terminal
    logging trap informational
    exit
    ```

5.  **Save Configuration**:
    ```shell
    write memory
    ```

For more details, refer to [Cisco's System Message Logging documentation](https://www.cisco.com/c/en/us/td/docs/routers/access/wireless/software/guide/SysMsgLogging.html).

#### 2. Add and Configure the Integration in Kibana

1.  In Kibana, navigate to **Management → Integrations**.
2.  Search for "Cisco IOS" and click on it.
3.  Click **Add Cisco IOS**.
4.  Provide a descriptive **Integration name**.
5.  Choose your desired **Input Type** (TCP, UDP, or Log file) and configure its settings.

##### TCP Input Configuration

Collect logs via a TCP syslog listener.

**Basic Options**

| Setting | Description | Default Value |
|---|---|---|
| **Host to listen on** | The IP address or hostname for the Elastic Agent to listen on. Use `0.0.0.0` to listen on all interfaces or `localhost` for local-only. | `localhost` |
| **Syslog Port** | The port for the Elastic Agent to listen on for syslog messages. Must match the port configured on the Cisco device. | `9002` |
| **Preserve original event** | If enabled, the original, raw log message is stored in the `event.original` field. | `false` |

**Advanced Options**

| Setting | Description | Default Value |
|---|---|---|
| **Timezone** | The IANA time zone or time offset (e.g., `+0200`) to use when parsing timestamps that do not include a timezone. | `UTC` |
| **Timezone Map** | A map of timezone abbreviations (e.g., AEST) to their corresponding IANA timezone names (e.g., Australia/Sydney). | (empty) |
| **SSL Configuration** | Configuration for SSL/TLS settings. See [SSL documentation](https://www.elastic.co/guide/en/beats/filebeat/current/configuration-ssl.html) for details. | (empty) |
| **Custom TCP Options** | Advanced TCP settings such as `max_connections`, `framing`, and `line_delimiter`. See the [Filebeat TCP input documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-tcp.html) for details. | (empty) |
| **Processors** | Processors to apply to the data before it is sent to Elasticsearch. See the [Processors documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details. | (empty) |

##### UDP Input Configuration

Collect logs via a UDP syslog listener.

**Basic Options**

| Setting | Description | Default Value |
|---|---|---|
| **Host to listen on** | The IP address or hostname for the Elastic Agent to listen on. Use `0.0.0.0` to listen on all interfaces or `localhost` for local-only. | `localhost` |
| **Syslog Port** | The port for the Elastic Agent to listen on for syslog messages. Must match the port configured on the Cisco device. | `9002` |
| **Preserve original event** | If enabled, the original, raw log message is stored in the `event.original` field. | `false` |

**Advanced Options**

| Setting | Description | Default Value |
|---|---|---|
| **Timezone** | The IANA time zone or time offset (e.g., `+0200`) to use when parsing timestamps that do not include a timezone. | `UTC` |
| **Timezone Map** | A map of timezone abbreviations (e.g., AEST) to their corresponding IANA timezone names (e.g., Australia/Sydney). | (empty) |
| **Custom UDP Options** | Advanced UDP settings such as `read_buffer`, `max_message_size`, and `timeout`. See the [Filebeat UDP input documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-udp.html) for details. | (empty) |
| **Processors** | Processors to apply to the data before it is sent to Elasticsearch. See the [Processors documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details. | (empty) |

##### Log File Input Configuration

Collect logs from one or more log files.

**Basic Options**

| Setting | Description | Default Value |
|---|---|---|
| **Paths** | A list of file paths to monitor for logs. Wildcards are supported (e.g., `/var/log/cisco-*.log`). | `/var/log/cisco-ios.log` |
| **Preserve original event** | If enabled, the original, raw log message is stored in the `event.original` field. | `false` |

**Advanced Options**

| Setting | Description | Default Value |
|---|---|---|
| **Timezone** | The IANA time zone or time offset (e.g., `+0200`) to use when parsing timestamps that do not include a timezone. | `UTC` |
| **Timezone Map** | A map of timezone abbreviations (e.g., AEST) to their corresponding IANA timezone names (e.g., Australia/Sydney). | (empty) |
| **Processors** | Processors to apply to the data before it is sent to Elasticsearch. See the [Processors documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details. | (empty) |

6.  Select an **Agent policy**. The Elastic Agent must be running on a host that is accessible to your Cisco devices.
7.  Click **Save and continue** to save your configuration and deploy the changes to the specified agent policy.

### Validation

1.  **Verify Logs on Cisco Device**:
    *   Trigger a log event, for example, by entering and exiting configuration mode.
    *   Run `show logging` on the Cisco device to confirm that logs are being generated and sent.

2.  **Check Data in Kibana**:
    *   Navigate to **Analytics → Discover**.
    *   Select the `logs-cisco_ios.log-*` data view.
    *   Verify that log events from your device are appearing. Check that key fields like `@timestamp`, `observer.vendor`, `cisco.ios.facility`, and `message` are correctly populated.

## Troubleshooting

For help with Elastic ingest tools, see [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

**Issue: No data in Kibana**
*   Verify network connectivity between the Cisco device and the Elastic Agent host.
*   Check that firewall rules on the agent host and any network firewalls allow traffic on the configured syslog port.
*   Confirm the Elastic Agent is running (`elastic-agent status`) and check its logs for errors.
*   Ensure the listening port in the integration settings matches the destination port configured on the Cisco device.

**Issue: Incorrect timestamps**
*   Confirm that `service timestamps log datetime` is configured on the Cisco IOS device.
*   In the integration's advanced settings, ensure the correct **Timezone** is configured (default is UTC).

## Performance and scaling

The performance and scaling of the Cisco IOS integration depend on several factors, including the volume of logs generated by your network devices, the resources allocated to the Elastic Agent, and the network protocol used for syslog collection.

### Scaling for High-Volume Environments

For environments with a large number of devices or high log throughput, consider the following strategies:

*   **Load Balancing**: Place a load balancer (e.g., F5, Nginx) between your Cisco devices and a pool of Elastic Agents. This distributes the syslog traffic evenly, preventing any single agent from becoming a bottleneck.
*   **Dedicated Hosts**: Run the Elastic Agent on a dedicated host or a group of hosts to ensure it has sufficient resources and is not competing with other applications.
*   **Multiple Integration Instances**: If you have geographically distributed datacenters or logically separated networks, you can configure multiple instances of the Cisco IOS integration, each with its own agent policy and dedicated agent(s). This can help isolate traffic and improve manageability.

## Reference

### log

The `log` data stream provides logs from Cisco IOS.

#### log fields

{{ fields "log" }}

{{ event "log" }}

### Inputs used
{{ inputDocs }}
