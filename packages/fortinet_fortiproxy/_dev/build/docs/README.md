# Fortinet FortiProxy Integration for Elastic

## Overview

The Fortinet FortiProxy integration for Elastic enables the collection of logs from Fortinet FortiProxy devices. FortiProxy serves as a high-performance secure web gateway, protecting users from online threats through advanced URL filtering, SSL/SSH inspection, and content analysis. By ingesting these logs, users can gain visibility into web traffic patterns, security events, and system performance.

This integration facilitates:
- **Secure Web Gateway Monitoring**: specific insights into how the proxy protects users from threats.
- **Web Traffic Analysis**: monitoring user behavior and application usage across the network.
- **Data Loss Prevention (DLP)**: visibility into sensitive data leakage prevention events.
- **Application Control**: monitoring of blocked malware and enforced web application policies.
- **Security Event Detection**: detection of intrusion attempts, malware, and policy violations.

### Compatibility

This integration has been tested against FortiProxy versions 7.x up to 7.4.3. Newer versions are expected to work but have not been tested.

### How it works

This integration collects logs from FortiProxy via Elastic Agent. The agent can receive logs through:
*   **Syslog (TCP/UDP)**: FortiProxy streams logs to the Elastic Agent's listening port.
*   **Filestream**: Elastic Agent reads logs from a file (useful if logs are written to a shared location).

The collected logs are parsed and mapped to the Elastic Common Schema (ECS) for unified analysis.

## What data does this integration collect?

The Fortinet FortiProxy integration collects the following types of log data:

- **Traffic logs**: Network traffic information including source/destination IPs, ports, protocols, bytes transferred, and session details.
- **HTTP transaction logs**: Detailed HTTP/HTTPS request and response data including URLs, methods, status codes, user agents, and timing information.
- **UTM (Unified Threat Management) logs**: Security-related logs from antivirus, web filtering, application control, DLP, and SSL inspection features.
- **Event logs**: System events, administrative actions, user authentication events, configuration changes, and system performance statistics.
- **Security Rating logs**: Security posture assessment results with audit scores and compliance metrics.

### Supported use cases

*   **Security Operations**: Detect and investigate security incidents like malware downloads or intrusion attempts.
*   **Compliance Auditing**: Retain and search logs for regulatory compliance and policy enforcement verification.
*   **Network Troubleshooting**: Analyze traffic flows and connection errors to resolve connectivity issues.
*   **User Behavior Analytics**: Monitor web usage to identify anomalous behavior or policy violations.

## What do I need to use this integration?

### Vendor prerequisites

*   **FortiProxy Device**: A configured and accessible FortiProxy instance.
*   **Syslog Configuration**: FortiProxy must be configured to send syslog messages to the Elastic Agent using either UDP or TCP mode with the default format.

### Elastic prerequisites

*   **Elastic Agent**: Must be installed and running on a system that can receive syslog messages from the FortiProxy device.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the syslog or log file receiver and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Onboard and configure

### Set up steps in Fortinet FortiProxy

#### Configure Syslog on FortiProxy

1.  Access the FortiProxy CLI or GUI.

2.  Configure the syslog settings using the CLI:

    ```bash
    config log syslogd setting
        set status enable
        set server "<Elastic_Agent_IP>"
        set port 514
        set mode <udp|reliable>
        set format default
    end
    ```

    *   Replace `<Elastic_Agent_IP>` with the IP address of your Elastic Agent.
    *   Set `mode` to `udp` for UDP transport or `reliable` for TCP transport.
    *   **Important**: Keep `format` set to `default`.

3.  **TCP Reliability Note**: When using TCP input with `reliable` mode, the TCP framing in the Elastic Agent configuration (in Kibana) must be set to `rfc6587`.

#### Configure Log Settings (Optional)

To control which logs are sent and their verbosity:

1.  Navigate to **Log & Report** > **Log Settings** in the FortiProxy GUI.
2.  Enable logging for the desired event types (traffic, security events, system events).
3.  Set the appropriate severity level for each log type.

### Set up steps in Kibana

1.  In the integration configuration page, choose the appropriate input type based on your FortiProxy setup:
    *   **TCP input**: For reliable syslog transmission.
        *   Set **Listen Address** (default: `localhost`, or `0.0.0.0` to bind to all interfaces).
        *   Set **Listen Port** (default: `514`).
        *   **Critical**: Ensure TCP framing is set to `rfc6587` if FortiProxy is configured with `mode reliable`.
    *   **UDP input**: For standard syslog transmission.
        *   Set **Listen Address** (default: `localhost`, or `0.0.0.0` to bind to all interfaces).
        *   Set **Listen Port** (default: `514`).
    *   **Filestream input**: For reading logs from a file.
        *   Specify the path to the log file.

2.  Configure optional settings:
    *   Enable **Preserve original event** to keep a copy of the raw log in `event.original`.
    *   Add custom tags if needed.
    *   Configure SSL/TLS settings for encrypted TCP connections (if required).

3.  Save and deploy the integration.

## Validation Steps

1.  **Verify FortiProxy is sending logs**:
    *   Generate some web traffic through the FortiProxy device.
    *   Check the FortiProxy logs to confirm syslog is enabled and active.
    *   Verify network connectivity between FortiProxy and the Elastic Agent (check firewall rules, port accessibility).

2.  **Check data ingestion in Kibana**:
    *   Navigate to **Discover** in Kibana.
    *   Select the `logs-fortinet_fortiproxy.log-*` index pattern.
    *   Confirm that logs are appearing with recent timestamps.
    *   Verify that fields are being parsed correctly (check `fortinet.proxy.*`, `source.ip`, `destination.ip`, etc.).

3.  **Review the dashboard**:
    *   Navigate to **Dashboards** in Kibana.
    *   Open the "Fortinet FortiProxy" dashboard.
    *   Verify that visualizations are displaying data correctly.
    *   Check that traffic patterns, top sources/destinations, and security events are visible.

4.  **Test with specific log types**:
    *   Generate traffic logs by accessing websites through the proxy.
    *   Trigger security events (e.g., blocked URLs) to verify UTM log collection.
    *   Perform administrative actions to verify system event logs are collected.

## Troubleshooting

### Common Configuration Issues

**Issue: No data collected / Logs not appearing in Kibana**
*   Verify that syslog is enabled on FortiProxy: `show log syslogd setting`.
*   Check network connectivity between FortiProxy and Elastic Agent (ping, telnet to the syslog port).
*   Verify firewall rules allow traffic on the configured syslog port.
*   Confirm the Elastic Agent is listening on the correct IP address and port.
*   Check the Elastic Agent logs for connection errors or parsing issues.
*   Ensure the FortiProxy server IP and Elastic Agent IP are correctly configured.

**Issue: TCP framing errors**
*   When using FortiProxy in `reliable` mode (TCP), ensure the TCP input framing is set to `rfc6587` in the integration settings.
*   Check the Elastic Agent configuration for the correct `framing` setting under `tcp_options`.

**Issue: Incomplete or malformed log messages**
*   Verify that FortiProxy syslog format is set to `default`.
*   Check for network packet loss or truncation issues.
*   Increase the `max_message_size` setting in the input configuration if logs are being truncated.

### Ingestion Errors

**Issue: Parsing errors in `error.message` field**
*   Check the `event.original` field to see the raw log format.
*   Verify that the log format matches what the integration expects (syslog format with key=value pairs).
*   Check for recent FortiProxy firmware updates that may have changed the log format.

**Issue: Missing fields or incorrect field mappings**
*   Verify that the FortiProxy log contains the expected fields.
*   Check the ingest pipeline processing for any dropped fields.

### API Authentication Errors

This integration collects logs via syslog and does not use API authentication. If you see API-related errors, they may be from a different integration or misconfiguration.

## Performance and scaling

FortiProxy is designed for high scalability and can handle large volumes of web traffic. For cloud deployments, FortiProxy supports active-passive high availability configurations to ensure continuous protection and uptime.

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### log

The `log` data stream collects all log types from FortiProxy, including traffic, UTM, event, and security rating logs.

#### log fields

{{ fields "log" }}

#### log sample event

{{ event "log" }}

### Inputs used

{{ inputDocs }}

