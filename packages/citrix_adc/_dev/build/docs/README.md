{{- generatedHeader }}
# Citrix NetScaler (ADC) Integration for Elastic

## Overview

The Citrix NetScaler (ADC) integration for Elastic enables you to collect and analyze logs and events from your Citrix NetScaler appliances. It provides visibility into system health, performance metrics for load balancing virtual servers, VPN user activity, and more. This integration facilitates monitoring, troubleshooting, and securing your application delivery infrastructure by parsing and visualizing critical operational data.

### Compatibility

This integration is compatible with Citrix NetScaler (ADC) versions that produce syslog data in the standard format. It has been tested with NetScaler version 13.x.

### How it works

The integration collects syslog data streamed from a configured Citrix NetScaler appliance. Elastic Agent listens for these logs on a specified port, processes them using the integration's ingest pipelines to parse and structure the data, and sends the enriched events to your Elastic cluster.

### Scaling and Performance

To maximize performance and minimize scaling concerns, you can perform the following:

* Prefer CEF logging for application firewall events; use RFC 5424-compliant syslog where supported (NetScaler 14.1+).
* Choose the appropriate log transport (file, TCP, or UDP) based on your volume and reliability needs.
* Use multiple Agent inputs or scale syslog receivers as ingestion volume increases.

## What data does this integration collect?

The Citrix NetScaler (ADC) integration collects logs and events from the following data streams:

*   **`system`**: System-level events, including hardware, configuration, and system status messages.
*   **`vpn`**: Events related to VPN user activity, such as logins, logouts, and session details.
*   **`lbvserver`**: Performance and health metrics for load balancing virtual servers.
*   **`interface`**: Network interface statistics and status events.
*   **`service`**: Backend service health, status, and performance metrics.
*   **`log`**: General log messages and events that provide insight into the appliance's operations.

## What do I need to use this integration?

*   An Elastic deployment (Elastic Cloud, Serverless, or self-managed).
*   A Citrix NetScaler (ADC) appliance configured to send syslog data to the Elastic Agent.
*   Elastic Agent installed on a host that is reachable by the NetScaler appliance over the network.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed to collect data from your NetScaler appliance. You can install only one Elastic Agent per host. Elastic Agent streams the syslog data to your Elastic cluster, where the events are processed by the integration's ingest pipelines.

For detailed installation instructions, refer to the Elastic Agent [installation guide](https://www.elastic.co/docs/reference/fleet/install-elastic-agents). Only one Elastic Agent is needed per host.

### Onboard and configure

#### Set up steps in Citrix NetScaler (ADC)

1.  Log in to your Citrix NetScaler (ADC) management interface.
2.  Navigate to **Configuration** > **System** > **Auditing** > **Syslog**.
3.  In the **Servers** tab, click **Add** to create a new syslog server entry.
4.  Configure the following settings:
    *   **Server Name / IP Address**: Enter the IP address of the host where your Elastic Agent is running.
    *   **Port**: Enter the port number that you will configure in the Elastic Agent integration policy (e.g., 9001).
    *   **Log Levels**: Select the desired log levels (e.g., ALL).
5.  Click **Create** to save the configuration.

#### Set up steps in Kibana

1.  From the Kibana main menu, go to **Management** > **Integrations**.
2.  Search for "Citrix ADC" and select it.
3.  Click **Add Citrix NetScaler (ADC)**.
4.  Configure the integration policy:
    *   **Syslog Host**: Set to `0.0.0.0` to listen on all network interfaces of the agent host.
    *   **Syslog Port**: Enter the same port number you configured in the NetScaler syslog settings.
5.  Save the integration policy and assign it to your Elastic Agent(s).

### Troubleshooting

If you are not seeing data, verify the following:
*   Ensure the NetScaler appliance can reach the Elastic Agent host over the configured port. Check for firewalls or network security groups that might be blocking the traffic.
*   Verify that the port configured in the NetScaler syslog settings matches the port in the Elastic Agent integration policy.
*   Check the Elastic Agent logs for any errors related to receiving syslog data.

## Reference

### Vendor Resources
- NetScaler Syslog Message Reference: [link](https://developer-docs.netscaler.com/en-us/netscaler-syslog-message-reference/current-release)
- How to send WAF messages to a separate syslog server: [link](https://support.citrix.com/s/article/CTX138973-how-to-send-application-firewall-messages-to-a-separate-syslog-server)
- How to send NetScaler Application Firewall logs to external syslog/NS.log: [link](https://support.citrix.com/s/article/CTX483235-send-logs-to-external-syslog-server?language=en_US)
- Configuring audit log action (RFC 5424): [link](https://docs.netscaler.com/en-us/citrix-adc/current-release/system/audit-logging/configuring-audit-logging.html#configuring-audit-log-action)
- NITRO API metrics references:
  - Interface: [link](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/network/interface/)
  - LBVserver: [link](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/lb/lbvserver/)
  - Service: [link](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/basic/service/)
  - System: [link](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/system/system/)
  - VPN: [link](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/vpn/vpn/)

### Documentation sites
- Elastic ECS Field Reference: [link](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html)

### system

The `system` data stream collects system-level events and health monitoring data from the NetScaler appliance.

{{ fields "system" }}
{{ event "system" }}

### vpn

The `vpn` data stream provides events related to VPN user activity, including session logins and logouts.

{{ fields "vpn" }}
{{ event "vpn" }}

### lbvserver

The `lbvserver` data stream contains performance and status metrics for the load balancing virtual servers.

{{ fields "lbvserver" }}
{{ event "lbvserver" }}

### interface

The `interface` data stream collects metrics and status events for the network interfaces of the appliance.

{{ fields "interface" }}
{{ event "interface" }}

### service

The `service` data stream provides health and performance data for the backend services managed by the NetScaler.

{{ fields "service" }}
{{ event "service" }}

### log

The `log` data stream collects general log messages and events from the NetScaler appliance.

{{ fields "log" }}
{{ event "log" }}

### Inputs used
{{ inputDocs }}
