# Broadcom ProxySG Integration for Elastic

## Overview

The Broadcom ProxySG integration for Elastic enables the collection of access logs from Broadcom ProxySG appliances. This allows for comprehensive monitoring of web traffic, security events, and user activities within the Elastic Stack. By ingesting ProxySG logs, organizations can gain visibility into web usage patterns, enforce compliance policies, and detect security threats.

This integration facilitates:
- **Web Traffic Monitoring and Control**: Monitor, filter, and control web traffic to ensure compliance and enhance security.
- **Data Loss Prevention (DLP)**: Inspect outbound traffic to help prevent sensitive data exfiltration.
- **Malware Protection**: Scan web traffic for malware and block malicious content.
- **SSL Inspection**: Identify and block malicious activities hidden in encrypted traffic.
- **Bandwidth Management**: Optimize network performance by analyzing bandwidth usage.

### Compatibility

This integration is compatible with Broadcom ProxySG appliances that support the following access log formats:
- `main`
- `bcreportermain_v1`
- `bcreporterssl_v1`
- `ssl`

### How it works

This integration collects logs from ProxySG appliances using two primary methods:
1.  **Syslog (UDP/TCP)**: The ProxySG appliance is configured to stream access logs via syslog to the Elastic Agent.
2.  **File-based Collection**: The ProxySG appliance uploads log files to a server where the Elastic Agent is installed and configured to read them.

The Elastic Agent receives the logs, parses them according to the selected format, and forwards them to Elasticsearch for storage and analysis.

## What data does this integration collect?

The Broadcom ProxySG integration collects **Access Logs**, which provide detailed records of web traffic processed by the proxy. Depending on the log format configured, this data includes:

-   **Traffic Details**: URLs accessed, HTTP methods, bytes transferred, status codes, and action taken (e.g., TCP_HIT, TCP_MISS).
-   **User Information**: Usernames, authentication groups, and client IP addresses.
-   **Security Events**: Blocked sites, malware detection events, threat risk scores, and SSL validation status.
-   **Performance Metrics**: Request duration and connection details.

### Supported use cases

Integrating Broadcom ProxySG with Elastic enables several critical security and operational use cases:

-   **Security Auditing**: maintain a complete audit trail of all web access to investigate security incidents and policy violations.
-   **Threat Detection**: Correlate proxy logs with other security data to identify complex threats and compromised hosts.
-   **Usage Analytics**: Analyze web traffic trends to optimize network resources and user productivity.
-   **Compliance Reporting**: Generate reports on web usage and blocked content to meet regulatory requirements.

## What do I need to use this integration?

-   **Broadcom ProxySG Appliance**: Admin access to configure access logging and log transmission.
-   **Elastic Agent**: Installed on a host that is reachable by the ProxySG appliance (for syslog) or has access to the uploaded log files.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed on a host that will receive the syslog data or has access to the log files. For detailed installation instructions, refer to the Elastic Agent [installation guide](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

### Set up steps in Broadcom ProxySG

You can configure Broadcom ProxySG to send logs using either Syslog (recommended for real-time monitoring) or File Upload.

#### For Syslog Collection (TCP/UDP)

1.  **Log in to the Management Console**: Access the ProxySG Management Console with administrative credentials.
2.  **Configure Access Logging**:
    -   Navigate to **Configuration** > **Access Logging** > **Logs**.
    -   Create a new log facility or select an existing one.
    -   Set the **Log Format** to one of the supported formats: `main`, `bcreportermain_v1`, `bcreporterssl_v1`, or `ssl`. *Note: This must match the configuration in the Elastic integration.*
3.  **Set Up Log Destination**:
    -   Navigate to **Log Hosts**.
    -   Add the IP address of the server where the Elastic Agent is running.
    -   Specify the port number (Default UDP: 514, Default TCP: 601).
    -   Select the protocol (UDP or TCP).
4.  **Apply Configuration**:
    -   Ensure logging is enabled for your active policies.
    -   Click **Apply** to save the changes.

#### For File-Based Collection

1.  **Configure File Upload**:
    -   In the Management Console, navigate to **Configuration** > **Access Logging**.
    -   Configure the appliance to upload access logs to the server where Elastic Agent is running.
    -   Define the schedule and the destination directory.
2.  **Select Log Format**:
    -   Ensure the log format for the uploaded files is set to one of the supported formats (`main`, `bcreportermain_v1`, `bcreporterssl_v1`, or `ssl`).

### Set up steps in Kibana

1.  In Kibana, navigate to **Management** > **Integrations**.
2.  Search for "Broadcom ProxySG" and select the integration.
3.  Click **Add Broadcom ProxySG**.
4.  Select the appropriate **Input type** based on your ProxySG configuration:
    -   **Collect logs from ProxySG via UDP**
    -   **Collect logs from ProxySG via TCP**
    -   **Collect access logs from ProxySG via logging server file**

#### Input Configuration

**For UDP/TCP Inputs:**
-   **Listen Address**: Enter the address the agent should listen on (default `localhost`). Use `0.0.0.0` to listen on all interfaces.
-   **Listen Port**: Enter the port configured on the ProxySG appliance (UDP default `514`, TCP default `601`).
-   **Access Log Format**: Select the format that matches your ProxySG configuration (`main`, `bcreportermain_v1`, `bcreporterssl_v1`, or `ssl`).

**For File-based Input:**
-   **Paths**: Specify the path pattern to the log files uploaded by ProxySG (e.g., `/var/log/proxysg/*.log`).
-   **Access Log Format**: Select the format that matches the logs (`main`, `bcreportermain_v1`, `bcreporterssl_v1`, or `ssl`).

#### Common Options
-   **Preserve original event**: Enable this to store the raw log message in `event.original`. This is useful for troubleshooting parsing issues.
-   **Tags**: Add custom tags to your events (e.g., `proxysg`, `forwarded`).

5.  **Save and Deploy**: Click **Save and continue**, then select the agent policy to deploy the integration.

## Troubleshooting

### Common Configuration Issues

-   **No logs appearing in Kibana**:
    -   **Check Connectivity**: Ensure the ProxySG appliance can reach the Elastic Agent on the configured IP and Port. Check firewalls and routing.
    -   **Verify Agent Status**: Ensure the Elastic Agent is healthy and the integration policy is applied.
    -   **Check Listen Interface**: If sending from a remote appliance, ensure Listen Address is set to `0.0.0.0`, not `localhost`.

-   **Parsing Errors / Incorrect Fields**:
    -   **Format Mismatch**: The most common cause is a mismatch between the **Access Log Format** selected in the integration and the actual format configured on the ProxySG appliance. Verify both are set to the same standard format (e.g., both set to `main`).
    -   **Custom Formats**: This integration supports the standard vendor formats. If you have customized the log string on the ProxySG, parsing may fail. Revert to a standard format or use the `preserve_original_event` option to debug.

-   **Missing SSL Fields**:
    -   If SSL-related fields are empty, ensure you are using a log format that supports them, such as `ssl` or `bcreporterssl_v1`.

### Ingestion Errors

-   **Timestamp Issues**: Ensure the ProxySG appliance and the Elastic Agent host are synchronized with a reliable NTP source to prevent timestamp skews.

## Performance and scaling

-   **Log Volume**: ProxySG appliances can generate high volumes of logs. Ensure your network bandwidth and the Elastic Agent host resources (CPU/RAM) are sufficient to handle the load.
-   **Load Balancing**: For high-availability and scaling, you can place a load balancer in front of multiple Elastic Agents and configure the ProxySG to send logs to the load balancer VIP.

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### log

The `log` data stream collects access logs from the ProxySG appliance.

#### log fields

{{ fields "log" }}

#### log sample event

{{ event "log" }}

### Inputs used

{{ inputDocs }}
