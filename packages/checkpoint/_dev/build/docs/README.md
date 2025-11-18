# Check Point Integration for Elastic

## Overview

The Check Point integration for Elastic enables you to collect and monitor network security events, firewall traffic, and audit logs from Check Point Security Gateways and Management Servers. This integration facilitates centralized visibility into security policies, blocked connections, accepted connections, and VPN activity. By collecting and analyzing this data, you can enhance threat detection, incident response, and compliance auditing.

### Compatibility

This integration is compatible with Check Point Security Gateways and Management Servers running R80.x, R81, and R81.x versions. It requires Kibana version 8.11.0 or later, or 9.0.0 or later.

### How it works

This integration collects logs from Check Point devices using two primary methods:
- **Syslog (UDP/TCP)**: The Check Point Log Exporter forwards logs in Syslog format to the Elastic Agent.
- **Log file**: The Elastic Agent directly monitors and collects logs from files on the Check Point appliance, such as system logs.

## What data does this integration collect?

The Check Point integration collects the following types of data:
*   Check Point Security Gateway and Management Server logs in Syslog format (firewall connections, VPN, audit, system events).
*   Check Point firewall connection logs (accept, drop, reject, etc.).
*   VPN logs.
*   SmartConsole audit logs (administrator actions on the Management Server).
*   Gaia OS system-level logs (e.g., `/var/log/messages`, `/var/log/secure`, `/var/log/dmesg`) for appliance health and activity.

### Supported use cases

-   Gain centralized visibility into security policies, blocked connections, accepted connections, and VPN activity.
-   Facilitate compliance auditing and reporting by centralizing Check Point logs.
-   Enhance threat detection and incident response capabilities through real-time log analysis.
-   Monitor system health and administrator actions on Check Point appliances.

## What do I need to use this integration?

### Vendor prerequisites

-   Administrative access to Check Point SmartConsole.
-   SSH access to Check Point Security Gateways or Management Servers.
-   Knowledge of your Check Point environment, including IP addresses of Gateways/Management Servers.
-   Ensure network connectivity and open ports (e.g., UDP/TCP 514 or a custom port) between your Check Point devices and the Elastic Agent.

### Elastic prerequisites

-   An active Elastic Stack deployment (Elasticsearch and Kibana) compatible with the integration.
-   An Elastic Agent deployed and enrolled in Fleet.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed to stream data from the syslog or log file receiver and ship it to Elastic. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/install-elastic-agents.html).

### Onboard / configure

#### Vendor set up steps

##### For UDP/TCP (Syslog) Collection:

1.  **Configure Log Exporter in SmartConsole:**
    *   For each Check Point device, create a new [Log Exporter/SIEM object](https://sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_LoggingAndMonitoring_AdminGuide/Topics-LMG/Log-Exporter-Configuration-in-SmartConsole.htm?tocpath=Log%20Exporter%7C_____2) in Check Point SmartConsole.
    *   Navigate to **Objects > More object types > Server > Log Exporter/SIEM**.
    *   Set the **Target Server** to the IP address of your Elastic Agent.
    *   Specify the **Target Port** (e.g., `9001`).
    *   Select the **Protocol** (**UDP** or **TCP**).
    *   Choose the **Format** as **Syslog**.
2.  **Install Policy:**
    *   Install the updated policy on the relevant Security Gateways or Management Server.

##### For Logfile Collection:

1.  **Access the Check Point Appliance:**
    *   Connect to the Check Point device via SSH.
2.  **Identify Log File Locations:**
    *   System logs are typically in `/var/log/` (e.g., `/var/log/messages`, `/var/log/secure`).
    *   Management Server audit logs can be found in `$FWDIR/log/cpm.elg`.

#### Kibana set up steps

1.  In Kibana, navigate to **Integrations** > **Check Point**.
2.  Click **Add Check Point**.
3.  Add the integration to an Elastic Agent policy.
4.  Configure the input type:
    *   **For UDP/TCP (Syslog)**: Select the **Collect Check Point firewall logs (input: tcp)** or **(input: udp)**. Specify the `Syslog Host` and `Syslog Port` to match the Log Exporter configuration.
    *   **For Logfile Collection**: Select the **Collect Check Point firewall logs (input: logfile)**. Provide the `Paths` to the log files.
5.  Save the integration.

### Validation

1.  **Trigger Data Flow on Check Point:**
    *   Generate network traffic to create firewall logs.
    *   Perform an action in SmartConsole to generate audit logs.
2.  **Check Data in Kibana:**
    *   Navigate to **Discover** and select the `checkpoint.firewall` data view.
    *   Verify that logs are being ingested and parsed correctly.
    *   Explore the provided Check Point dashboards.

## Troubleshooting

-   **No data in Kibana**: Verify network connectivity between the Check Point device and the Elastic Agent. Ensure the Log Exporter policy is installed and the port/IP settings match in both configurations.
-   **Parsing issues**: Ensure the format in the Log Exporter is set to `Syslog`.
-   **Fingerprint collisions**: In some instances firewall events may have the same Checkpoint `loguid` and arrive during the same timestamp resulting in a fingerprint collision. To avoid this [enable semi-unified logging](https://sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_LoggingAndMonitoring_AdminGuide/Topics-LMG/Log-Exporter-Appendix.htm?TocPath=Log%20Exporter%7C_____9) in the Checkpoint dashboard.

For additional help, check the [Common problems](https://www.elastic.co/guide/en/fleet/current/troubleshooting.html) documentation.

## Scaling

For high-volume environments, consider deploying multiple Elastic Agents to distribute the log collection load. Refer to Check Point's documentation for sizing guidelines. For more information on scaling, see the [Ingest Architectures](https://www.elastic.co/guide/en/ingest/current/ingest-reference-architectures.html) documentation.

## Reference

### firewall

The `firewall` data stream collects log entries from the Check Point Log Exporter in Syslog format.

#### firewall fields

{{ fields "firewall" }}

{{ event "firewall" }}

### Inputs used

{{ inputDocs }}
