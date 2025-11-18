# Citrix ADC Integration for Elastic

## Overview

The Citrix ADC integration for Elastic allows you to collect logs and metrics from your Citrix ADC instances. Citrix ADC is an application delivery controller that performs application-specific traffic analysis to intelligently distribute, optimize, and secure Layer 4-Layer 7 (L4-L7) network traffic for web applications.

This integration enables you to monitor the health and performance of your Citrix ADC appliances, providing visibility into network traffic, system resources, and security events. By collecting and analyzing this data, you can troubleshoot issues, optimize performance, and enhance the security of your application delivery infrastructure.

### Compatibility

This integration has been tested with Citrix ADC versions 13.0, 13.1 and 14.1.

### How it works

This integration uses two methods to collect data:
*   **Metrics**: The integration polls the Citrix ADC NITRO REST API to collect metrics about the system, interfaces, load balancing, services, and VPN.
*   **Logs**: The integration can receive syslog messages from Citrix ADC over TCP or UDP, or read them from a log file.

## What data does this integration collect?

The Citrix ADC integration collects both logs and metrics.

**Metrics** data streams provide insights into the performance and health of the Citrix ADC appliance. The collected metrics include:
*   **Interface**: Statistics for network interfaces, including inbound/outbound packets and errors.
*   **Load Balancing Virtual Server (lbvserver)**: Metrics for load balancing virtual servers, such as client connections, requests, and responses.
*   **Service**: Data for individual services, including throughput and transactions.
*   **System**: System-level metrics like CPU utilization, memory usage, and management IP information.
*   **VPN**: VPN-related metrics, including active sessions and throughput.

**Logs** provide detailed records of events and activities on the Citrix ADC, which are essential for security monitoring and troubleshooting.

### Supported use cases

By using this integration, you can:
*   Monitor the overall health and performance of your Citrix ADC appliances.
*   Analyze traffic patterns and identify potential bottlenecks.
*   Troubleshoot application delivery issues by correlating logs and metrics.
*   Enhance security by monitoring for suspicious activity and policy violations.
*   Create custom dashboards and alerts to meet your specific monitoring needs.

## What do I need to use this integration?

*   **Elastic Agent**: An Elastic Agent must be installed on a host that can access the Citrix ADC appliance. For more details, see the [Elastic Agent installation instructions](docs-content://reference/fleet/install-elastic-agents.md).
*   **Citrix ADC Credentials**: For collecting metrics, you will need the hostname (or IP address) and administrator credentials for the Citrix ADC instance. The host configuration should be in the format `http[s]://<hostname>[:<port>]`.
*   **Network Access**: If collecting logs via syslog, the Elastic Agent host must be reachable from the Citrix ADC appliance on the configured syslog port.

## How do I deploy this integration?

### Onboard / configure

#### Configure Citrix ADC to send logs

You can configure your Citrix ADC appliance to send logs to the Elastic Agent via syslog. It is recommended to use the CEF log format for better parsing and compatibility.

1.  **Enable CEF Logging**:
    *   In the Citrix ADC GUI, navigate to **Security** > **Application Firewall**.
    *   Click on **Change Engine Settings**.
    *   Enable **CEF Logging**.

2.  **Configure a Syslog Action and Policy**:
    *   Navigate to **System** > **Auditing** > **Syslog**.
    *   On the **Servers** tab, click **Add** to create a new syslog server entry. Enter the IP address and port of your Elastic Agent. Select the desired protocol (TCP or UDP).
    *   On the **Policies** tab, click **Add** to create a new syslog policy. Define the policy to capture the desired log messages and associate it with the syslog server action you just created.
    *   For more detailed instructions, refer to the official Citrix documentation on [configuring audit logging](https://docs.netscaler.com/en-us/citrix-adc/current-release/system/audit-logging/configuring-audit-logging.html#configuring-audit-log-action). Using RFC 5424 compliant syslog messages is recommended if your NetScaler version supports it.

#### Enable the integration in Elastic

1.  In Kibana, navigate to **Management** > **Integrations**.
2.  In the search bar, type **Citrix ADC**.
3.  Select the **Citrix ADC** integration and add it.
4.  Configure the integration with the appropriate settings for collecting logs and/or metrics.
    *   For **metrics**, provide the Citrix ADC hostname, username, and password.
    *   For **logs**, configure the appropriate input (TCP, UDP, or log file) to match your Citrix ADC configuration.
5.  Save the integration to begin collecting data.

### Validation

After configuring the integration, you can validate that data is being collected by navigating to the **Assets** tab within the Citrix ADC integration in Kibana. You should see dashboards populated with data from your Citrix ADC appliance. You can also use the **Discover** app in Kibana to query the `logs-citrix_adc.*` and `metrics-citrix_adc.*` data streams.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

*   **Dummy Values**: It is possible that for some fields, Citrix ADC sets dummy values. For example, a field `cpuusagepcnt` (`citrix_adc.system.cpu.utilization.pct`) might be set to `4294967295`. If you encounter this, please reach out to the Citrix ADC support team.
*   **Type Conflicts**: If you see a type conflict for the `host.ip` field in the `logs-*` data view, you may need to reindex the `interface`, `lbvserver`, `service`, `system`, and `vpn` data stream indices.

## Reference

### Interface
This is the `interface` data stream. It collects metrics related to network interfaces on the Citrix ADC.

{{fields "interface"}}

{{event "interface"}}

### Load Balancing Virtual Server (lbvserver)
This is the `lbvserver` data stream. It collects metrics related to the performance of load balancing virtual servers.

{{fields "lbvserver"}}

{{event "lbvserver"}}

### Log
This is the `log` data stream. It collects logs sent from the Citrix ADC, typically via syslog.

{{fields "log"}}

{{event "log"}}

### Service
This is the `service` data stream. It collects metrics for individual services configured on the Citrix ADC.

{{fields "service"}}

{{event "service"}}

### System
This is the `system` data stream. It collects system-level metrics such as CPU and memory utilization.

{{fields "system"}}

{{event "system"}}

### VPN
This is the `vpn` data stream. It collects metrics related to VPN activity on the Citrix ADC.

{{fields "vpn"}}

{{event "vpn"}}

### Inputs used
{{ inputDocs }}
