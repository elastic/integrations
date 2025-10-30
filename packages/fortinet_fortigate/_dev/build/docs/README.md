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

This integration has been tested against FortiOS versions 13.x. While newer versions may work, they have not been officially tested.

This integration is compatible with Elastic Stack version 8.11.0 or higher.

### How it works

This integration collects logs from FortiGate firewalls by receiving syslog data over TCP or UDP, or by reading directly from log files. An Elastic Agent is deployed on a host that is configured as a syslog receiver or has access to the log files. The agent forwards the logs to your Elastic deployment, where they are processed and enriched by the integration's ingest pipelines.

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

1.  Log in to your FortiGate firewall's management interface.
2.  Navigate to the syslog configuration settings.
3.  Configure the FortiGate device to send syslog messages to the IP address and port of the host where the Elastic Agent is installed.
4.  If you are using TCP with reliable syslog mode, ensure that the framing is set to `rfc6587`. This is a critical step for ensuring message integrity. For more details, refer to the [FortiGate CLI reference](https://docs.fortinet.com/document/fortigate/7.4.0/cli-reference/405620/config-log-syslogd-setting).
5.  Configure the appropriate syslog facility and severity levels to match the data you wish to collect.

### Onboard / configure in Kibana

1.  In Kibana, navigate to **Management > Integrations**.
2.  Search for "Fortinet FortiGate Firewall Logs" and select the integration.
3.  Click **Add Fortinet FortiGate Firewall Logs**.
4.  Configure the integration with one of the following input types:
    *   **TCP**: Provide the listen address and port (e.g., `0.0.0.0:9004`) for the syslog receiver.
    *   **UDP**: Provide the listen address and port (e.g., `0.0.0.0:9004`) for the syslog receiver.
    *   **Log file**: Specify the path to the log files you want to monitor.
5.  Under the **Settings** tab, configure any optional settings:
    *   **Internal/External interfaces**: Define your network interfaces to correctly map network direction.
    *   **Internal networks**: Specify your internal network ranges (defaults to private address spaces).
    *   **Preserve original event**: Check this option if you want to keep the original, unprocessed log message.
6.  Assign the integration to an agent policy and click **Save and continue**.

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

## Scaling

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
