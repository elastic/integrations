# Check Point Integration for Elastic

## Overview

The Check Point integration for Elastic collects logs from Check Point Security Gateways and Management Servers. This enables comprehensive security monitoring, threat detection, and network traffic analysis within the Elastic Stack. By ingesting Check Point logs, you can gain centralized visibility into firewall traffic, security policies, VPN activity, and system health to enhance your security posture.

This integration facilitates:

- Centralized visibility into security policies, blocked connections, accepted connections, and VPN activity.
- Compliance auditing and reporting by centralizing Check Point logs.
- Enhanced threat detection and incident response capabilities through real-time log analysis.
- Monitoring of system health and administrator actions on Check Point appliances.

### Compatibility

This integration is compatible with Check Point Security Gateways and Management Servers running R81.x versions.

This integration is compatible with Elastic Stack versions 8.11.0 or higher.

### How it works

This integration collects logs from Check Point devices by receiving syslog data over TCP or UDP, or by reading directly from log files. An Elastic Agent is deployed on a host that is configured as a syslog receiver or has access to the log files. The agent forwards the logs to your Elastic deployment, where they can be monitored and analyzed.

## What data does this integration collect?

The Check Point integration collects log messages of the following types:

- Check Point Security Gateway and Management Server logs in Syslog format (firewall connections, VPN, audit, system events).
- Check Point firewall connection logs (accept, drop, reject, etc.).
- VPN logs.
- SmartConsole audit logs (administrator actions on the Management Server).
- Gaia OS system-level logs (e.g., `/var/log/messages`, `/var/log/secure`, `/var/log/dmesg`) for appliance health and activity.

### Supported use cases

- **Real-time Threat Detection**: Leverage Elastic SIEM to detect and respond to threats identified in firewall logs.
- **Network Traffic Analysis**: Use Kibana dashboards to visualize and analyze network traffic patterns, helping to identify anomalies and optimize network performance.
- **Compliance and Auditing**: Maintain a searchable, long-term archive of firewall logs to meet compliance requirements and conduct security audits.
- **Incident Response**: Accelerate incident investigation by correlating firewall data with other security and observability data sources within Elastic.

## What do I need to use this integration?

### Vendor prerequisites

- Administrative access to Check Point SmartConsole.
- SSH access to Check Point Security Gateways or Management Servers (required for logfile collection and potentially for advanced troubleshooting).
- Knowledge of your Check Point environment, including IP addresses of Gateways/Management Servers.
- Ensure network connectivity and open ports (e.g., UDP/TCP 514 or a custom port) between your Check Point devices and the Elastic Agent acting as the log collector.

### Elastic prerequisites

- An active Elastic Stack deployment (Elasticsearch and Kibana) compatible with the integration (Kibana 8.11.0+ or 9.0.0+).
- An Elastic Agent deployed and enrolled in Fleet, configured to receive logs from Check Point devices.
- Network connectivity between the Elastic Agent and the Check Point devices.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed on a host that will act as the syslog or log file receiver. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the syslog or log file receiver and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Set up steps in Check Point

#### For UDP/TCP (Syslog) Collection:

1.  **Configure Log Exporter in SmartConsole:**
    - For each Check Point Security Gateway or Management Server you wish to monitor, create a new [Log Exporter/SIEM object](https://sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_LoggingAndMonitoring_AdminGuide/Topics-LMG/Log-Exporter-Configuration-in-SmartConsole.htm?tocpath=Log%20Exporter%7C%5F%5F%5F%5F%5F2) in Check Point SmartConsole.
    - Navigate to **Objects > More object types > Server > Log Exporter/SIEM**.
    - **Name:** Provide a descriptive name for the Log Exporter (e.g., `Elastic_Agent_Syslog_Export`).
    - **Target Server:** Set this to the IP address or hostname of your log collector (e.g., Elastic Agent).
    - **Target Port:** Specify the port number on which your log collector is listening (e.g., `514` for standard Syslog UDP/TCP, or a custom port like `9001` as often used by Elastic Agent).
    - **Protocol:** Select either **UDP** or **TCP**. The Check Point integration supports both.
    - **Format:** Choose **Syslog**.
    - **Export additional log fields:** (Optional) Select any additional fields you wish to export.
    - **Filter (Optional):** Define a filter if you only want to send specific log types or severities.
    - Click **OK** to save the Log Exporter configuration.
2.  **Install Policy:**
    - After configuring the Log Exporter, install the updated policy on the relevant Security Gateways or Management Server for the changes to take effect.

#### For Logfile Collection:

1.  **Access the Check Point Appliance:**
    - Connect to the Check Point Security Gateway or Management Server via SSH.
2.  **Identify Log File Locations:**
    - **Gaia OS System Logs:** Standard Linux system logs are located in `/var/log/`. These include:
      - `/var/log/messages`: General system messages.
      - `/var/log/secure`: Authentication and authorization messages.
      - `/var/log/dmesg`: Kernel ring buffer messages.
    - **Management Server Logs:**
      - `$FWDIR/log/cpm.elg`: For SmartConsole audit events, which can be useful for auditing administrator actions.
3.  **Configure your Log Collector:**
    - Point your log file collector (Elastic Agent) to the desired log file paths on the Check Point appliance. Ensure the collector has appropriate permissions to read these files.
    - **Important:** For proprietary binary logs (e.g., `$FWDIR/log/fw.log`), a generic log collector will not be able to parse the content effectively. If security events are required, use the Log Exporter (Syslog) method. For standard text-based system logs (e.g., `/var/log/messages`), direct collection is viable.

### Set up steps in Kibana

1.  In Kibana, navigate to **Management > Integrations**.
2.  Search for "Check Point" and select the integration.
3.  Click **Add Check Point**.
4.  Follow the prompts to add the integration to an existing Elastic Agent policy or create a new one.
5.  Configure the input types based on your vendor setup:
    - **For UDP/TCP (Syslog)**:
      - Select **Collect Check Point firewall logs (input: tcp)** or **(input: udp)**.
      - Specify the `Syslog Host` (The IP address or hostname for the Elastic Agent to listen on. Use `0.0.0.0` to listen on all available network interfaces.).
      - Specify the `Syslog Port` (e.g., `9001` or `514`), ensuring it matches the `Target Port` configured in your Check Point Log Exporter.
    - **For Logfile Collection**:
      - Select **Collect Check Point firewall logs (input: logfile)**.
      - Provide the `Paths` to the desired log files on the Check Point appliance (e.g., `/var/log/messages`, `$FWDIR/log/cpm.elg`).
6.  Save the integration. The Elastic Agent will automatically update its configuration and begin ingesting data.

### Validation Steps

After configuring both the Check Point Log Exporter and the Elastic Agent integration:

1.  **Trigger Data Flow on Check Point:**
    - **For firewall logs**: On a Check Point Security Gateway, generate some network traffic to ensure firewall logs are generated.
    - **For audit logs**: Perform an action in SmartConsole to generate audit logs on the Management Server.
    - **For system logs**: Log in/out of the Check Point appliance via SSH or perform routine system commands.
2.  **Check Data in Kibana:**
    - Navigate to **Discover** in Kibana.
    - Filter by `data_stream.dataset : checkpoint.firewall`.
    - Verify that logs are being ingested and parsed correctly, looking for recent timestamps.
    - Explore the provided Check Point dashboards (e.g., Overview, Addresses and Ports) to see if data populates as expected.

## Troubleshooting

### Common Configuration Issues

- **No data collected in Kibana**:
  - **Network Connectivity**: Verify network connectivity between your Check Point device and the Elastic Agent. Check any intermediate firewalls or security groups that might block Syslog traffic.
  - **Policy Installation**: Ensure the Log Exporter policy has been successfully installed on the relevant Check Point Security Gateway or Management Server.
  - **Port/IP Mismatch**: Double-check that the `Target Server` IP and `Target Port` in SmartConsole's Log Exporter match the `Syslog Host` and `Syslog Port` in the Elastic Agent integration.
  - **Elastic Agent Status**: Confirm the Elastic Agent is running and healthy. Check its logs for any errors related to input listeners.
  - **Logfile Permissions**: For logfile collection, ensure the Elastic Agent has appropriate read permissions on the specified log file paths.
- **Data collected, but parsing issues or missing fields**:
  - **Syslog Format**: Ensure the `Format` in Check Point Log Exporter is explicitly set to `Syslog`.
  - **Input Type Mismatch**: Verify that the correct input type (UDP, TCP, or Logfile) is selected and configured in the Elastic Agent integration.

### Ingestion Errors

- Check the Elastic Agent logs for any specific error messages related to log processing, parsing failures, or communication with Elasticsearch.
- In Kibana Discover, look for documents with an `error.message` field, which can indicate issues during ingestion or processing.
- In some instances, firewall events may have the same Checkpoint `loguid` and arrive at the same timestamp, resulting in a fingerprint collision. To avoid this, [enable semi-unified logging](https://sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_LoggingAndMonitoring_AdminGuide/Topics-LMG/Log-Exporter-Appendix.htm?TocPath=Log%20Exporter%7C_____9) in the Checkpoint dashboard.

### Vendor Resources

- [Check Point R81 Logging and Monitoring Administration Guide - Log Exporter Configuration](https://sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_LoggingAndMonitoring_AdminGuide/Topics-LMG/Log-Exporter-Configuration-in-SmartConsole.htm?tocpath=Log%20Exporter%7C%5F%5F%5F%5F%5F2)
- [Check Point sk122323: R80.x / R81.x Log Exporter command line utility](https://support.checkpoint.com/results/sk/sk122323)

## Performance and scaling

For high-volume environments, consider deploying multiple Elastic Agents to distribute the log collection load. Check Point's Log Exporter allows for flexible log forwarding, including the ability to send logs to multiple targets, enabling distributed log collection setups.

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### firewall

The `firewall` data stream provides events from Check Point devices, including firewall traffic, VPN logs, audit logs, and system events.

#### firewall fields

{{ fields "firewall" }}

#### firewall sample event

{{ event "firewall" }}

### Inputs used

{{ inputDocs }}
