# Cisco IOS Integration for Elastic

## Overview

The Cisco IOS integration for Elastic collects logs from your Cisco IOS devices, enabling you to gain real-time visibility into network activity, security events, and the operational health of your network infrastructure. By parsing and visualizing syslog messages from your Cisco routers and switches, this integration helps with network security monitoring, compliance reporting, and troubleshooting.

### How it works

This integration works by receiving syslog messages from your Cisco IOS devices via the Elastic Agent. You can configure the integration to listen for these logs over TCP or UDP, or to read them directly from a log file. After receiving the logs, the Elastic Agent processes and parses them into structured fields, then securely sends them to your Elastic deployment for analysis, visualization, and alerting.

### Compatibility

This integration is designed for a wide range of Cisco devices running Cisco IOS software, including routers and switches.

**Elastic Stack Requirements:**
*   Elastic Stack version 8.11.0 or higher
*   Kibana version 8.11.0 or higher

## What data does this integration collect?

The Cisco IOS integration collects various types of log messages, which are parsed into detailed, structured fields. The data collected includes:

*   **System Messages**: Captures key administrative actions, configuration changes, and system restarts.
*   **Security Events**: Monitors for access control list (ACL) denials and permits, authentication failures, and other critical security-related events.
*   **Network Events**: Tracks important network state changes, such as interface status (up/down), routing protocol updates, and other network messages.
*   **Traffic Logs**: Collects data on IPv4 and IPv6 traffic, including source and destination IP addresses and ports.
*   **Protocol-specific Messages**: Logs events related to protocols like ICMP, TCP, UDP, and IGMP.

### Supported use cases

By collecting and analyzing this data, you can support several key operational and security use cases:

*   **Network Security Monitoring**: Actively monitor your network device logs for security threats like unauthorized access attempts and ACL violations.
*   **Compliance Reporting**: Collect and archive logs to help you meet regulatory compliance requirements such as PCI DSS or SOX.
*   **Network Operations Management**: Gain deep visibility into the health and status of your network devices, track configuration changes, and monitor system events to ensure stability.
*   **Troubleshooting**: Quickly diagnose and resolve network issues, hardware failures, and configuration problems by analyzing detailed device logs.

## What do I need to use this integration?

### Vendor Prerequisites

*   A Cisco IOS device that has network connectivity to the host running the Elastic Agent.
*   Administrative access to the Cisco device to configure its syslog settings.
*   **Important**: You must enable timestamps on your Cisco IOS device, as they are not enabled by default. Use the command `service timestamps log datetime`.

### Elastic Prerequisites

*   The Elastic Agent must be installed on a host that can receive syslog messages from your Cisco devices.
*   The host running the Elastic Agent must have the specified listening port (the default is 9002) open and accessible from the Cisco devices.
*   Your firewall rules must be configured to allow syslog traffic from your network devices to the Elastic Agent host.

## How do I deploy this integration?

### Agent-based deployment

The Elastic Agent is required to stream data from the syslog receiver or log file and send it to Elastic, where the events will be processed by the integration's ingest pipelines. You only need to install one Elastic Agent per host. For detailed instructions, refer to the Elastic Agent [installation guide](docs-content://reference/fleet/install-elastic-agents.md).

### Set up steps in Cisco IOS

Log into your Cisco IOS device to perform the following steps.

1.  **Enable Timestamp Logging (Required)**
    This step is critical to ensure that all logs are correctly time-stamped.
    ```shell
    configure terminal
    service timestamps log datetime
    exit
    ```

2.  **Enable Sequence Numbers (Optional)**
    This adds a sequence number to each log message, which populates the `event.sequence` field in Elastic.
    ```shell
    configure terminal
    service sequence-numbers
    exit
    ```

3.  **Configure Syslog Destination**
    Configure your Cisco device to send logs to the Elastic Agent's IP address and port. Replace `<ELASTIC_AGENT_IP>` with the actual IP address of your agent host.

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

4.  **Set Logging Severity Level (Optional)**
    You can adjust the logging level to control the verbosity of the logs. `informational` (level 6) is a common choice for comprehensive visibility.
    ```shell
    configure terminal
    logging trap informational
    exit
    ```

5.  **Save Your Configuration**
    ```shell
    write memory
    ```

For more detailed information, you can refer to [Cisco's System Message Logging documentation](https://www.cisco.com/c/en/us/td/docs/routers/access/wireless/software/guide/SysMsgLogging.html).

### Set up steps in Kibana

1.  In Kibana, navigate to **Management → Integrations**.
2.  In the search bar, type "Cisco IOS" and select the integration.
3.  Click **Add Cisco IOS**.
4.  Configure the integration by providing a name and selecting your desired input type (TCP, UDP, or Log file).

#### TCP Input Configuration
Collect logs using a TCP syslog listener.

| Setting | Description | Default |
|---|---|---|
| **Host to listen on** | The IP address or hostname for the Elastic Agent to listen on. Use `0.0.0.0` to listen on all available network interfaces. | `localhost` |
| **Syslog Port** | The port for the Elastic Agent to listen on. This must match the port you configured on your Cisco device. | `9002` |
| **Preserve original event** | If enabled, the original raw log message is stored in the `event.original` field. | `false` |

#### UDP Input Configuration
Collect logs using a UDP syslog listener.

| Setting | Description | Default |
|---|---|---|
| **Host to listen on** | The IP address or hostname for the Elastic Agent to listen on. Use `0.0.0.0` to listen on all available network interfaces. | `localhost` |
| **Syslog Port** | The port for the Elastic Agent to listen on. This must match the port you configured on your Cisco device. | `9002` |
| **Preserve original event** | If enabled, the original raw log message is stored in the `event.original` field. | `false` |

#### Log File Input Configuration
Collect logs directly from one or more log files.

| Setting | Description | Default |
|---|---|---|
| **Paths** | A list of file paths to monitor for new logs. Wildcards are supported (for example, `/var/log/cisco-*.log`). | `/var/log/cisco-ios.log` |
| **Preserve original event** | If enabled, the original raw log message is stored in the `event.original` field. | `false` |

After configuring the input, select an **Agent policy**. The Elastic Agent must be running on a host that is accessible to your Cisco devices. Click **Save and continue** to save your configuration and deploy the changes.

## Validation

1.  **Verify on the Cisco Device**
    *   Trigger a log event on your Cisco device, for example, by entering and exiting configuration mode.
    *   Run the `show logging` command to confirm that logs are being generated and sent to the correct destination.

2.  **Check Data in Kibana**
    *   In Kibana, navigate to the **Discover** tab.
    *   Select the `logs-cisco_ios.log-*` data view.
    *   Verify that log events from your device are appearing. Check that key fields like `@timestamp`, `observer.vendor`, `cisco.ios.facility`, and `message` are correctly populated.

## Troubleshooting

For help with Elastic ingest tools, refer to the [common problems documentation](https://www.elastic.com/docs/troubleshoot/ingest/fleet/common-problems).

**Issue: No data is appearing in Kibana**
*   **Solutions**:
    *   Verify the network connectivity between your Cisco device and the Elastic Agent host.
    *   Check that any firewall rules on the agent host or network firewalls allow traffic on the configured syslog port.
    *   Confirm that the Elastic Agent is running by executing `elastic-agent status` on its host, and check its logs for any errors.
    *   Ensure the listening port in the integration settings in Kibana perfectly matches the destination port configured on your Cisco device.

**Issue: Timestamps are not parsing correctly**
*   **Solutions**:
    *   Confirm that `service timestamps log datetime` is configured on your Cisco IOS device. This is a required step.
    *   In the integration's advanced settings in Kibana, ensure the correct **Timezone** is configured (the default is UTC).

## Performance and scaling

The performance and scaling of this integration depend on the volume of logs your network devices generate, the resources allocated to the Elastic Agent, and the network protocol you use. For high-volume environments, consider these strategies:

*   **Load Balancing**: Place a load balancer (such as Nginx or F5) between your Cisco devices and a pool of Elastic Agents to distribute the syslog traffic evenly. This prevents any single agent from becoming a performance bottleneck.
*   **Dedicated Hosts**: Run the Elastic Agent on dedicated hosts to ensure it has sufficient CPU and memory resources.

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.com/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### log

The `log` data stream collects logs from Cisco IOS.

#### log fields

{{ fields "log" }}

{{ event "log" }}

### Inputs used
{{ inputDocs }}
