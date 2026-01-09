# Fortinet FortiGate Firewall Logs Integration for Elastic

## Overview

The Fortinet FortiGate Firewall Logs integration for Elastic enables the collection of logs from Fortinet FortiGate firewalls. This allows for comprehensive security monitoring, threat detection, and network traffic analysis within the Elastic Stack. By ingesting FortiGate logs, users can gain visibility into firewall activity, monitor for security threats, audit policy compliance, and troubleshoot network issues.

This integration facilitates:
- Security monitoring and threat detection
- Network traffic analysis and monitoring
- Firewall policy compliance and auditing
- Intrusion detection and prevention system (IPS) event monitoring
- VPN connection monitoring and troubleshooting
- Web filtering and application control monitoring

### Compatibility

This integration has been tested against FortiOS versions 6.x and 7.x up to 7.4.1. Newer versions are expected to work but have not been tested.

This integration is compatible with Elastic Stack version 8.11.0 or higher.

### How it works

This integration collects logs from FortiGate firewalls by receiving syslog data over TCP or UDP, or by reading directly from log files. An Elastic Agent is deployed on a host that is configured as a syslog receiver or has access to the log files. The agent forwards the logs to your Elastic deployment, where they can be monitored or analyzed.

## What data does this integration collect?

The Fortinet FortiGate Firewall Logs integration collects the following types of logs:
*   **Traffic logs**: Records of firewall decisions to allow or deny traffic.
*   **UTM (Unified Threat Management) logs**: Includes events from antivirus, web filter, application control, IPS, and DNS filter modules.
*   **Event logs**: System-level events, high-availability (HA) events, and configuration changes.
*   **Authentication logs**: Records of VPN, administrator, and user authentication events.

### Supported use cases

Integrating Fortinet FortiGate logs with Elastic provides a powerful solution for enhancing security posture and operational visibility. Key use cases include:
- **Real-time Threat Detection**: Leverage Elastic SIEM to detect and respond to threats identified in firewall logs.
- **Network Traffic Analysis**: Use Kibana dashboards to visualize and analyze network traffic patterns, helping to identify anomalies and optimize network performance.
- **Compliance and Auditing**: Maintain a searchable, long-term archive of firewall logs to meet compliance requirements and conduct security audits.
- **Incident Response**: Accelerate incident investigation by correlating firewall data with other security and observability data sources within Elastic.

## What do I need to use this integration?

- A FortiGate firewall with administrative access to configure syslog settings.
- Network connectivity between the FortiGate firewall and the Elastic Agent host.
- Elastic Stack version 8.11.0 or higher.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed on a host that will receive the syslog data or has access to the log files from the FortiGate firewall. For detailed installation instructions, refer to the Elastic Agent [installation guide](docs-content://reference/fleet/install-elastic-agents.md). Only one Elastic Agent is needed per host.

### Vendor set up steps

#### Syslog Configuration

You can configure FortiGate to send logs to the Elastic Agent using either the GUI or the CLI.

**GUI Configuration:**

1.  Log in to the FortiGate web-based manager (GUI).
2.  Navigate to **Log & Report -> Log Settings**.
3.  Enable **Send Logs to Syslog**.
4.  In the IP address field, enter the IP address of the host where the Elastic Agent is installed.
5.  Click **Apply**.
6.  Under **Log Settings**, ensure that **Event Logging** and all desired log subtypes are enabled to generate and send the necessary logs.

**CLI Configuration:**

1.  Log in to the FortiGate CLI.
2.  Use the following commands to configure the syslog server settings:

    ```sh
    config log syslogd setting
        set status enable
        set server "<elastic_agent_ip>"
        set port <port>  // Default syslog ports are 514 for UDP and TCP
        // For TCP with reliable syslog mode, ensure framing is set to rfc6587
        set mode reliable
        set format rfc6587
    end
    ```

3.  Configure the appropriate log types and severity levels to be sent to the syslog server. For example:

    ```sh
    config log syslogd filter
        set severity information
        set forward-traffic enable
        set local-traffic enable
        set web enable
        set antivirus enable
        // Enable other UTM and event logs as needed
    end
    ```

For more detailed information, refer to the [FortiGate CLI reference](https://docs.fortinet.com/document/fortigate/7.4.0/cli-reference/405620/config-log-syslogd-setting).

### Onboard / configure in Kibana

1.  In Kibana, navigate to **Management > Integrations**.
2.  Search for "Fortinet FortiGate Firewall Logs" and select the integration.
3.  Click **Add Fortinet FortiGate Firewall Logs**.
4.  Configure the integration by selecting an input type and providing the necessary settings. This integration supports `TCP`, `UDP`, and `Log file` inputs.

#### TCP Input Configuration

This input collects logs over a TCP socket.

| Setting | Description |
|---|---|
| **Listen Address** | The bind address for the TCP listener (e.g., `localhost`, `0.0.0.0`). |
| **Listen Port** | The TCP port number to listen on (e.g., `9004`). |
| **Preserve original event** | If checked, a raw copy of the original log is stored in the `event.original` field. |

Under **Advanced Options**, you can configure the following optional parameters:

| Setting | Description |
|---|---|
| **Internal/External interfaces** | Define your network interfaces to correctly map network direction. |
| **Internal networks** | Specify your internal network ranges (defaults to private address spaces). Supports CIDR notation and named ranges like `private`. |
| **SSL Configuration** | Configure SSL options for encrypted communication. See the [SSL documentation](https://www.elastic.co/guide/en/beats/filebeat/current/configuration-ssl.html#ssl-common-config) for details. |
| **Custom TCP Options** | `framing`: Specifies how messages are framed. Defaults to `rfc6587`, which is required for FortiGate's reliable syslog mode. <br> `max_message_size`: The maximum size of a log message (e.g., `50KiB`). <br> `max_connections`: The maximum number of simultaneous connections. |
| **Timezone** | Specify an IANA timezone or offset (e.g., `+0200`) for logs with no timezone information. |
| **Timezone Map** | A mapping of timezone strings from logs to standard IANA timezone formats. |
| **Processors** | Add custom processors to enhance or reduce event fields before parsing. |

#### UDP Input Configuration

This input collects logs over a UDP socket.

| Setting | Description |
|---|---|
| **Listen Address** | The bind address for the UDP listener (e.g., `localhost`, `0.0.0.0`). |
| **Listen Port** | The UDP port number to listen on (e.g., `9004`). |
| **Preserve original event** | If checked, a raw copy of the original log is stored in the `event.original` field. |

Under **Advanced Options**, you can configure the following optional parameters:

| Setting | Description |
|---|---|
| **Internal/External interfaces** | Define your network interfaces to correctly map network direction. |
| **Internal networks** | Specify your internal network ranges (defaults to private address spaces). |
| **Custom UDP Options** | `read_buffer`: The size of the read buffer for the UDP socket (e.g., `100MiB`). <br> `max_message_size`: The maximum size of a log message (e.g., `50KiB`). <br> `timeout`: The read timeout for the UDP socket (e.g., `300s`). |
| **Timezone** | Specify an IANA timezone or offset (e.g., `+0200`) for logs with no timezone information. |
| **Timezone Map** | A mapping of timezone strings from logs to standard IANA timezone formats. |
| **Processors** | Add custom processors to enhance or reduce event fields before parsing. |

#### Log file Input Configuration

This input collects logs directly from log files on the host where the Elastic Agent is running.

| Setting | Description |
|---|---|
| **Paths** | A list of file paths to monitor (e.g., `/var/log/fortinet-firewall.log`). |
| **Preserve original event** | If checked, a raw copy of the original log is stored in the `event.original` field. |

Under **Advanced Options**, you can configure the following optional parameters:

| Setting | Description |
|---|---|
| **Internal/External interfaces** | Define your network interfaces to correctly map network direction. |
| **Internal networks** | Specify your internal network ranges (defaults to private address spaces). |
| **Timezone** | Specify an IANA timezone or offset (e.g., `+0200`) for logs with no timezone information. |
| **Timezone Map** | A mapping of timezone strings from logs to standard IANA timezone formats. |
| **Processors** | Add custom processors to enhance or reduce event fields before parsing. |

After configuring the input, assign the integration to an agent policy and click **Save and continue**.

### Validation

1.  First, verify on the FortiGate device that logs are being actively sent to the configured Elastic Agent host.
2.  In Kibana, navigate to **Discover**.
3.  In the search bar, enter `data_stream.dataset: "fortinet_fortigate.log"` and check for incoming documents.
4.  Verify that events are appearing with recent timestamps.
5.  Navigate to **Management > Dashboards** and search for "Fortinet FortiGate Overview" to see if the visualizations are populated with data.
6.  Generate some test traffic that would be logged by the firewall and confirm that the corresponding logs appear in Kibana.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Common Configuration Issues

-   **No data is being collected**:
    *   Verify network connectivity (e.g., using `ping` or `netcat`) between the FortiGate firewall and the Elastic Agent host.
    *   Ensure there are no firewalls or network ACLs blocking the syslog port.
    *   Confirm that the listening port configured in the Elastic integration matches the destination port configured on the FortiGate device.
-   **TCP framing issues**:
    *   When using TCP input with reliable syslog mode, both the FortiGate configuration and the integration settings must have framing set to `rfc6587`. Mismatched framing settings will result in parsing errors or lost logs.

### Vendor Resources

-   [FortiGate CLI Reference - Syslog Settings](https://docs.fortinet.com/document/fortigate/7.4.0/cli-reference/405620/config-log-syslogd-setting)
-   [Fortinet Documentation Library](https://docs.fortinet.com/)
-   [FortiGate Administration Guide](https://docs.fortinet.com/product/fortigate)

## Performance and Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation. A common approach for large-scale syslog collection is to place a load balancer or a dedicated syslog collector like Logstash between the FortiGate devices and the Elastic Agents.

## Reference

### log

The `log` data stream collects all log types from the FortiGate firewall, including traffic, UTM, event, and authentication logs.

#### log fields

{{ fields "log" }}

#### log sample event

{{ event "log" }}

### Inputs used

{{ inputDocs }}
