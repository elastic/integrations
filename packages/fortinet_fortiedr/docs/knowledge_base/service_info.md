# Service Info

The Fortinet FortiEDR integration allows organizations to ingest endpoint detection and response logs directly into the Elastic Stack. By capturing real-time security events, system logs, and audit trails from the FortiEDR Central Manager, security teams can centralize their endpoint telemetry for advanced threat hunting, automated alerting, and long-term compliance retention. This integration supports various ingestion methods, including Syslog (over TCP or UDP) and direct logfile polling, ensuring flexibility across different network architectures and performance requirements.

## Common use cases

- **Endpoint Threat Monitoring:** Monitor real-time security events detected by FortiEDR to identify and respond to malware, ransomware, and unauthorized access attempts across the fleet.
- **Audit and Compliance:** Maintain a comprehensive audit trail of administrative actions and user activities within the FortiEDR console to satisfy regulatory compliance requirements.
- **Incident Investigation:** Leverage detailed process and network telemetry from FortiEDR logs to perform root cause analysis and reconstruct the timeline of security incidents.
- **Operational Health Oversight:** Track system-level events and operational status changes within the FortiEDR environment to ensure the security infrastructure is functioning optimally.

## Data types collected
This integration collects various types of telemetry from Fortinet FortiEDR instances. Data is received in Semicolon-separated key-value format via Syslog (TCP/UDP) or through direct logfile monitoring. The FortiEDR export format must be set to **Semicolon** for proper parsing.

This integration includes the following data streams:
- **Fortinet FortiEDR Endpoint Detection and Response logs:**
    - **logfile**: Collect Fortinet FortiEDR Endpoint Detection and Response logs from file. This stream monitors local log files where FortiEDR events are persisted.
    - **tcp**: Collect Fortinet FortiEDR Endpoint Detection and Response logs via a TCP listener. This provides a reliable delivery mechanism for security, system, and audit events.
    - **udp**: Collect Fortinet FortiEDR Endpoint Detection and Response logs via a UDP listener. This provides a low-overhead transport for high-volume telemetry.

FortiEDR can emit several categories of log, including:
- **Security Events:** Detailed logs regarding detected threats, blocked processes, and suspicious behaviors identified by the EDR agents.
- **System Events:** Logs related to the health and operational status of the FortiEDR components, including Central Manager and Collector status updates.
- **Audit Trail:** Comprehensive records of administrative changes, policy modifications, and user login activity within the FortiEDR console.

> **Note:** All log types are processed by the same ingest pipeline using the Semicolon-separated key-value format. The integration does not differentiate between these categories during parsing. All events are assigned `event.category: malware` by default. The specific log type can be identified by inspecting fields such as `fortinet.edr.classification` and `fortinet.edr.severity`.

## Compatibility

The Fortinet FortiEDR integration is compatible with the following vendor versions:
- **Fortinet FortiEDR** version 5.0.0 and higher.

## Scaling and Performance

To ensure optimal performance in high-volume environments, consider the following:

- **Transport/Collection Considerations:** While UDP provides lower overhead for syslog transmission, TCP is recommended for environments where delivery guarantees are required to prevent packet loss during traffic spikes. If using UDP, ensure that the `read_buffer` (e.g., `100MiB`) and `max_message_size` (e.g., `50KiB`) variables are tuned within the **Custom UDP Options** to handle high throughput without dropping packets at the kernel level.
- **Data Volume Management:** To manage the volume of data ingested into Elasticsearch, utilize the FortiEDR Playbook policies to selectively enable "Send Syslog Notification" only for critical event categories. Filtering at the source reduces the processing load on the Elastic Agent and minimizes storage costs associated with high-noise system events.
- **Elastic Agent Scaling:** For large-scale deployments with high event rates, deploy multiple Elastic Agents behind a network load balancer to distribute the Syslog traffic evenly. Place Agents close to the FortiEDR Central Manager to minimize network latency and ensure horizontal scalability.

# Set Up Instructions

## Vendor prerequisites

1. **Administrative Access:** You must have a user account with administrative privileges for the Fortinet FortiEDR Central Manager console to modify Export Settings and Playbook policies.
2. **Network Connectivity:** The FortiEDR Central Manager must be able to reach the Elastic Agent host over the configured Syslog port (default is `9509`). Ensure any intermediate firewalls allow TCP or UDP traffic on the selected port.
3. **Enabled Playbooks:** A functional Playbook must be assigned to the target devices to trigger the generation and transmission of security event notifications.
4. **Format Requirements:** The FortiEDR export format must be set to **Semicolon** to ensure the Elastic Agent can correctly parse the key-value pairs into ECS-compliant fields.

## Elastic prerequisites

*   **Elastic Stack Version:** Use Elastic Stack version 8.11.0 or later for full compatibility (9.0.0 is also supported).
*   **Elastic Agent:** An Elastic Agent must be installed on a host reachable by the FortiEDR Central Manager and enrolled in Fleet.
*   **Connectivity:** Port `9509` (or your custom configured port) must be open on the Elastic Agent host's firewall to accept incoming TCP or UDP traffic.
*   **Integration Deployment:** The Fortinet FortiEDR integration must be added to an Elastic Agent policy via Fleet.

## Vendor set up steps

### For Syslog (TCP/UDP) Collection:

1. Log in to the **Fortinet FortiEDR Central Manager** console.
2. Navigate to **Administration > Export Settings**.
3. Select the **Syslog** tab to view existing configurations.
4. Click the **Add** (+) button to create a new syslog destination.
5. Configure the destination parameters:
    - **Syslog Name**: Enter a unique name, such as `Elastic_Agent_EDR`.
    - **Host**: Enter the IP address of the machine running the Elastic Agent.
    - **Port**: Enter the port configured in the Elastic integration (default is `9509`).
    - **Protocol**: Choose **TCP** or **UDP** (TCP is recommended for reliability).
    - **Format**: Select **Semicolon**. This is critical for proper parsing.
6. Click **Save** to finalize the destination.
7. Locate the newly created destination in the list and find the **Notifications** pane on the right side.
8. Use the toggle sliders to enable the specific categories you wish to export, such as **Security Events**, **System Events**, and **Audit Trail**.
9. Navigate to **Security Settings > Playbooks**.
10. Select the Playbook policy assigned to your monitored devices.
11. In the policy actions, ensure the **Send Syslog Notification** checkbox is enabled for relevant triggers.
12. Click **Save** to apply the policy changes across your environment.

### For Logfile Collection:

1. Configure the FortiEDR console or a secondary forwarder to write logs to a local directory accessible by the Elastic Agent.
2. Identify the absolute path where the logs are being rotated (e.g., `/var/log/fortinet-edr.log`).
3. Ensure the Elastic Agent user has read permissions for the log files and the directory containing them using `chmod` or `chown` as necessary.
4. Verify that the log rotation mechanism (such as logrotate) does not delete files before the Elastic Agent has finished ingesting them.

### Vendor Set up Resources

- [Fortinet FortiEDR Administration Guide: Syslog](https://docs.fortinet.com/document/fortiedr/7.2.0/administration-guide/109591/syslog) - Official guide for configuring syslog export settings.
- [Fortinet FortiEDR Administration Guide: Export Settings](https://docs.fortinet.com/document/fortiedr/7.2.0/administration-guide/918407/export-settings) - Detailed information on managing data exports.
- [Fortinet FortiEDR Administration Guide: Playbooks](https://docs.fortinet.com/document/fortiedr/7.2.0/administration-guide/419440/automated-incident-response-playbooks-page) - Details on playbook-driven alerts.
- [Elastic Fortinet FortiEDR Integration Reference](https://www.elastic.co/docs/reference/integrations/fortinet_fortiedr) - Reference guide for the Elastic integration.

## Kibana set up steps

### Collecting logs from Fortinet FortiEDR instances (input: logfile)
1. In Kibana, navigate to **Integrations** and search for **Fortinet FortiEDR**.
2. Click **Add Fortinet FortiEDR Logs**.
3. Select the **Collecting logs from Fortinet FortiEDR instances (input: logfile)** input type.
4. Configure the following variables:
    - **Paths** (`paths`): The list of paths to the log files. Default: `['/var/log/fortinet-edr.log']`.
    - **Timezone offset (+HH:mm format)** (`tz_offset`): The timezone offset for the logs. Default: `local`.
    - **Preserve original event** (`preserve_original_event`): Preserves a raw copy of the original event in `event.original`. Default: `False`.
    - **Tags** (`tags`): Custom tags to add to the events. Default: `['fortinet-fortiedr', 'forwarded']`.
    - **Enable debug logging** (`debug`): Enable debug logging for the input. Default: `False`.
    - **Processors** (`processors`): Add custom processors to reduce fields or enhance metadata.
5. Save the integration to the desired Elastic Agent policy.

### Collecting logs from Fortinet FortiEDR instances (input: tcp)
1. In Kibana, navigate to **Integrations** and search for **Fortinet FortiEDR**.
2. Click **Add Fortinet FortiEDR Logs**.
3. Select the **Collecting logs from Fortinet FortiEDR instances (input: tcp)** input type.
4. Configure the following variables:
    - **Listen Address** (`tcp_host`): The bind address to listen for TCP connections. Set to `0.0.0.0` to bind to all available interfaces. Default: `localhost`.
    - **Listen Port** (`tcp_port`): The TCP port number to listen on. Default: `9509`.
    - **Timezone offset (+HH:mm format)** (`tz_offset`): The timezone offset for the logs. Default: `local`.
    - **Add non-ECS fields** (`rsa_fields`): Whether to add RSA fields that are not part of ECS. Default: `True`.
    - **Preserve original event** (`preserve_original_event`): Preserves a raw copy of the original event in `event.original`. Default: `False`.
    - **Tags** (`tags`): Custom tags to add to the events. Default: `['fortinet-fortiedr', 'forwarded']`.
    - **Keep raw parser fields** (`keep_raw_fields`): If true, the integration keeps the original fields from the parser. Default: `False`.
    - **Enable debug logging** (`debug`): Enable debug logging for the input. Default: `False`.
    - **Processors** (`processors`): Add custom processors to reduce fields or enhance metadata.
5. Save and deploy the integration.

### Collecting logs from Fortinet FortiEDR instances (input: udp)
1. In Kibana, navigate to **Integrations** and search for **Fortinet FortiEDR**.
2. Click **Add Fortinet FortiEDR Logs**.
3. Select the **Collecting logs from Fortinet FortiEDR instances (input: udp)** input type.
4. Configure the following variables:
    - **Listen Address** (`udp_host`): The bind address to listen for UDP connections. Set to `0.0.0.0` to bind to all available interfaces. Default: `localhost`.
    - **Listen Port** (`udp_port`): The UDP port number to listen on. Default: `9509`.
    - **Timezone offset (+HH:mm format)** (`tz_offset`): The timezone offset for the logs. Default: `local`.
    - **Add non-ECS fields** (`rsa_fields`): Whether to add RSA fields that are not part of ECS. Default: `True`.
    - **Preserve original event** (`preserve_original_event`): Preserves a raw copy of the original event in `event.original`. Default: `False`.
    - **Tags** (`tags`): Custom tags to add to the events. Default: `['fortinet-fortiedr', 'forwarded']`.
    - **Keep raw parser fields** (`keep_raw_fields`): If true, the integration keeps the original fields from the parser. Default: `False`.
    - **Enable debug logging** (`debug`): Enable debug logging for the input. Default: `False`.
    - **Custom UDP Options** (`udp_options`): Specify custom configuration options such as `read_buffer` or `max_message_size`.
    - **Processors** (`processors`): Add custom processors to reduce fields or enhance metadata.
5. Save and deploy the integration.

# Validation Steps

After configuration is complete, verify that data is flowing correctly.

### 1. Trigger Data Flow on Fortinet FortiEDR:
- **Test Connection:** In the FortiEDR Console under **Administration > Export Settings**, select the Elastic Agent syslog destination and click the **Test** button to send a synthetic test message.
- **Trigger Audit Event:** Log out of the FortiEDR Administration Console and log back in to generate an administrative login event.
- **Modify Settings:** Briefly toggle a non-critical notification setting in the **Security Settings** to generate an audit trail event.
- **Trigger Security Event:** If in a test environment, execute a script in a protected directory or trigger a known-safe behavioral rule to generate a "Suspicious" or "Malicious" notification.

### 2. Check Data in Kibana:
1. Navigate to **Analytics > Discover**.
2. Select the `logs-*` data view.
3. Enter the KQL filter: `data_stream.dataset : "fortinet_fortiedr.log"`
4. Verify logs appear. Expand a log entry and confirm these fields:
    - `event.dataset` (should match `fortinet_fortiedr.log`)
    - `event.action` (e.g., `blocked`)
    - `fortinet.edr.severity` and `fortinet.edr.classification`
    - `process.name` and `host.hostname`
    - `event.original` (the raw log payload, if `preserve_original_event` is enabled)

# Troubleshooting

## Common Configuration Issues
- **Missing Syslog Notifications**: Defining the Syslog Export server is a global setting, but you must also enable the **Send Syslog Notification** checkbox within the specific active Playbook. Verify this in **Security Settings > Playbooks**.
- **Port Conflicts**: Ensure that no other service is using the port assigned to the Elastic Agent (default `9509`). You can use `netstat -ano | grep 9509` on the Agent host to check for existing bindings.
- **Firewall Obstructions**: Verify that intermediate firewalls or local host firewalls (e.g., iptables, firewalld, or Windows Firewall) are allowing traffic from the FortiEDR Manager IP to the Elastic Agent on the configured port.
- **Incorrect Listen Address**: If the Elastic Agent is not receiving data from a remote source, ensure the **Listen Address** is set to `0.0.0.0` instead of `localhost`.

## Ingestion Errors
- **Parsing Failures**: Check the `error.message` field in Discover. This often indicates that the syslog header is malformed or the log format does not match the integration's expected Semicolon-separated key-value format. Ensure the FortiEDR export format is set to **Semicolon** in **Administration > Export Settings**.
- **Timezone Misalignment**: If logs appear in the past or future, verify the **Timezone offset** variable in the Kibana integration settings to ensure it matches the FortiEDR Central Manager's timezone.
- **Message Truncation**: For large security events via UDP, logs might be truncated. Increase the `max_message_size` in the **Custom UDP Options** if you notice incomplete payloads.

## Vendor Resources
- [FortiEDR Administration Guide: Syslog](https://docs.fortinet.com/document/fortiedr/7.2.0/administration-guide/109591/syslog) - General product documentation for syslog.
- [FortiEDR Administration Guide: Automated Incident Response - Playbooks](https://docs.fortinet.com/document/fortiedr/7.2.0/administration-guide/419440/automated-incident-response-playbooks-page) - Details on playbook-driven alerts.

# Documentation sites

- [Fortinet FortiEDR Administration Guide](https://docs.fortinet.com/document/fortiedr/7.2.0/administration-guide)
- [Elastic Fortinet FortiEDR Integration Reference](https://www.elastic.co/docs/reference/integrations/fortinet_fortiedr)
