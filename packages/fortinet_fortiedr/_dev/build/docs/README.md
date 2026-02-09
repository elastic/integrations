# Fortinet FortiEDR Logs Integration for Elastic

## Overview

The Fortinet FortiEDR logs integration for Elastic enables you to collect and analyze endpoint security telemetry from your FortiEDR environment. By ingesting these logs into the Elastic Stack, you'll centralize monitoring, maintain long-term retention, and perform advanced threat hunting across your fleet.

This integration facilitates:
- Endpoint threat monitoring: You'll monitor real-time security events detected by FortiEDR to identify and respond to malware, ransomware, and unauthorized access attempts across your fleet.
- Audit and compliance: You'll maintain a comprehensive audit trail of administrative actions and user activities within the FortiEDR console to satisfy regulatory compliance requirements.
- Incident investigation: You'll leverage detailed process and network telemetry from FortiEDR logs to perform root cause analysis and reconstruct the timeline of security incidents.
- Operational health oversight: You'll track system-level events and operational status changes within the FortiEDR environment to ensure your security infrastructure is functioning optimally.

### Compatibility

This integration is compatible with the following vendor versions:
- Fortinet FortiEDR version 5.0.0 and higher.

### How it works

You collect telemetry from Fortinet FortiEDR instances using several transport methods. You can configure the integration to receive logs via a syslog listener using TCP or UDP, or you can set it up to monitor local log files where FortiEDR events are persisted. The data is processed in a semicolon-separated key-value format. For proper parsing, you'll need to set the FortiEDR export format to `Semicolon`.

This integration processes several types of telemetry within the `log` data stream:
- Security events: You'll receive detailed logs regarding detected threats, blocked processes, and suspicious behaviors identified by EDR agents.
- System events: You'll see logs related to the health and operational status of FortiEDR components, including Central Manager and Collector status updates.
- Audit trail: You'll have comprehensive records of administrative changes, policy modifications, and user login activity within the FortiEDR console.

The integration assigns `event.category: malware` to all events by default. You can identify the specific log type by inspecting fields such as `fortinet.edr.classification` and `fortinet.edr.severity`. Once you deploy the Elastic Agent with this integration, it collects these logs and forwards them to your Elastic deployment, where the data is parsed and mapped to the Elastic Common Schema (ECS) for analysis.

## What data does this integration collect?

The integration collects telemetry within a single `log` data stream. The types of log messages and how they are processed are described in the [How it works](#how-it-works) section above.

### Supported use cases

Integrating Fortinet FortiEDR logs with the Elastic Stack provides centralized visibility into your endpoint security posture. You can use this data for several key use cases:
*   Real-time threat detection: You use Elastic Security to alert on threats identified by FortiEDR, allowing you to respond quickly to potential compromises.
*   Security investigation: You correlate your endpoint logs with other security events in the Elastic Stack to perform deep-dive investigations into complex attacks.
*   Compliance and auditing: You maintain a searchable history of administrative actions and user activity to satisfy regulatory and internal compliance requirements.
*   Infrastructure health monitoring: You track the operational status of your EDR management components to ensure your protection remains active and healthy.

## What do I need to use this integration?

You must meet the following vendor and Elastic prerequisites before you can use this integration:

### Vendor prerequisites

Before you configure the integration, ensure your Fortinet FortiEDR environment meets these requirements:
- You must have a user account with administrative privileges for the Fortinet FortiEDR Central Manager console to modify export settings and playbook policies.
- The FortiEDR Central Manager must be able to reach the Elastic Agent host over the configured syslog port (the default is `9509`). Ensure any intermediate firewalls allow TCP or UDP traffic on the selected port.
- A functional playbook must be assigned to the target devices to trigger the generation and transmission of security event notifications.
- You must set the FortiEDR export format to `Semicolon` to ensure the Elastic Agent can correctly parse the key-value pairs into ECS-compliant fields.

### Elastic prerequisites

Before you collect data, ensure you have the following Elastic Stack components ready:
- Elastic Stack version `8.11.0` or later (version `9.0.0` is also supported).
- An Elastic Agent installed on a host reachable by the FortiEDR Central Manager and enrolled in Fleet.
- Port `9509` (or your custom configured port) open on the Elastic Agent host's firewall to accept incoming TCP or UDP traffic.
- The Fortinet FortiEDR integration added to an Elastic Agent policy via Fleet.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the syslog or log file receiver and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Set up steps in Fortinet FortiEDR Logs

To configure Fortinet FortiEDR to send data to Elastic, follow the instructions for your preferred collection method.

#### Syslog (TCP/UDP) collection

Configure the FortiEDR Central Manager to export logs via syslog using these steps:

1. Log in to the **Fortinet FortiEDR Central Manager** console.
2. Navigate to **Administration > Export Settings**.
3. Select the **Syslog** tab to view existing configurations.
4. Click the **Add** (+) button to create a new syslog destination.
5. Configure the destination parameters:
    * **Syslog Name**: Enter a unique name, such as `Elastic_Agent_EDR`.
    * **Host**: Enter the IP address of the machine running the Elastic Agent.
    * **Port**: Enter the port configured in the Elastic integration (default is `9509`).
    * **Protocol**: Choose `TCP` or `UDP` (`TCP` is recommended for reliability).
    * **Format**: Select **Semicolon**. This is critical for proper parsing of the logs.
6. Click **Save** to finalize the destination.
7. Locate the newly created destination in the list and find the **Notifications** pane.
8. Use the toggle sliders to enable the specific categories you wish to export:
    * **Security Events**
    * **System Events**
    * **Audit Trail**
9. Navigate to **Security Settings > Playbooks**.
10. Select the Playbook policy assigned to your monitored devices.
11. In the policy actions, ensure the **Send Syslog Notification** checkbox is enabled for relevant triggers.
12. Click **Save** to apply the policy changes across your environment.

#### Logfile collection

If you prefer to collect logs from a file, follow these steps:

1. Configure the FortiEDR console or a secondary forwarder to write logs to a local directory accessible by the Elastic Agent.
2. Identify the absolute path where the logs are being rotated, such as `/var/log/fortinet-edr.log` (replace with your actual value).
3. Ensure the Elastic Agent user has read permissions for the log files and the directory containing them using `chmod` or `chown` as necessary.
4. Verify that the log rotation mechanism, such as `logrotate`, does not delete files before the Elastic Agent has finished ingesting them.

#### Vendor resources

For more information, refer to the following Fortinet documentation:
- [Fortinet FortiEDR Administration Guide: Syslog](https://docs.fortinet.com/document/fortiedr/7.2.0/administration-guide/109591/syslog)
- [Fortinet FortiEDR Administration Guide: Export Settings](https://docs.fortinet.com/document/fortiedr/7.2.0/administration-guide/918407/export-settings)
- [Fortinet FortiEDR Administration Guide: Playbooks](https://docs.fortinet.com/document/fortiedr/7.2.0/administration-guide/419440/automated-incident-response-playbooks-page)

### Set up steps in Kibana

To configure the integration in Kibana, follow these steps:

1. In Kibana, navigate to **Management > Integrations**.
2. Search for **Fortinet FortiEDR** and select the integration.
3. Click **Add Fortinet FortiEDR Logs**.
4. Configure the integration by selecting an input type and providing the necessary settings.

Choose the setup instructions below that match your configuration:

#### Log file input configuration

Select the **Collecting logs from Fortinet FortiEDR instances (input: logfile)** input type and configure these variables:

* **Paths** (`paths`): The list of paths to the log files. Default: `['/var/log/fortinet-edr.log']`.
* **Timezone offset (+HH:mm format)** (`tz_offset`): The timezone offset for the logs. Default: `local`.
* **Preserve original event** (`preserve_original_event`): Preserves a raw copy of the original event in `event.original`. Default: `false`.
* **Tags** (`tags`): Custom tags to add to the events. Default: `['fortinet-fortiedr', 'forwarded']`.
* **Enable debug logging** (`debug`): Enable debug logging for the input. Default: `false`.
* **Processors** (`processors`): Add custom processors to reduce fields or enhance metadata.

#### TCP input configuration

Select the **Collecting logs from Fortinet FortiEDR instances (input: tcp)** input type and configure these variables:

* **Listen Address** (`tcp_host`): The bind address to listen for TCP connections. Set to `0.0.0.0` to bind to all available interfaces. Default: `localhost`.
* **Listen Port** (`tcp_port`): The TCP port number to listen on. Default: `9509`.
* **Timezone offset (+HH:mm format)** (`tz_offset`): The timezone offset for the logs. Default: `local`.
* **Add non-ECS fields** (`rsa_fields`): Whether to add RSA fields that are not part of ECS. Default: `true`.
* **Preserve original event** (`preserve_original_event`): Preserves a raw copy of the original event in `event.original`. Default: `false`.
* **Tags** (`tags`): Custom tags to add to the events. Default: `['fortinet-fortiedr', 'forwarded']`.
* **Keep raw parser fields** (`keep_raw_fields`): If `true`, the integration keeps the original fields from the parser. Default: `false`.
* **Enable debug logging** (`debug`): Enable debug logging for the input. Default: `false`.
* **Processors** (`processors`): Add custom processors to reduce fields or enhance metadata.

#### UDP input configuration

Select the **Collecting logs from Fortinet FortiEDR instances (input: udp)** input type and configure these variables:

* **Listen Address** (`udp_host`): The bind address to listen for UDP connections. Set to `0.0.0.0` to bind to all available interfaces. Default: `localhost`.
* **Listen Port** (`udp_port`): The UDP port number to listen on. Default: `9509`.
* **Timezone offset (+HH:mm format)** (`tz_offset`): The timezone offset for the logs. Default: `local`.
* **Add non-ECS fields** (`rsa_fields`): Whether to add RSA fields that are not part of ECS. Default: `true`.
* **Preserve original event** (`preserve_original_event`): Preserves a raw copy of the original event in `event.original`. Default: `false`.
* **Tags** (`tags`): Custom tags to add to the events. Default: `['fortinet-fortiedr', 'forwarded']`.
* **Keep raw parser fields** (`keep_raw_fields`): If `true`, the integration keeps the original fields from the parser. Default: `false`.
* **Enable debug logging** (`debug`): Enable debug logging for the input. Default: `false`.
* **Custom UDP Options** (`udp_options`): Specify custom configuration options such as `read_buffer` or `max_message_size`.
* **Processors** (`processors`): Add custom processors to reduce fields or enhance metadata.

After configuring the input, assign the integration to an agent policy and click **Save and continue**.

### Validation

After configuration is complete, verify that data is flowing correctly with these steps:

1. Navigate to **Management > Fleet > Agents** and verify that the Elastic Agent status is **Healthy**.
2. Trigger data flow on Fortinet FortiEDR:
    * **Test Connection**: In the FortiEDR Console under **Administration > Export Settings**, select the Elastic Agent syslog destination and click the **Test** button to send a synthetic test message.
    * **Trigger Audit Event**: Log out of the FortiEDR Administration Console and log back in to generate an administrative login event.
    * **Modify Settings**: Briefly toggle a non-critical notification setting in the **Security Settings** to generate an audit trail event.
    * **Trigger Security Event**: If in a test environment, execute a script in a protected directory or trigger a known-safe behavioral rule to generate a "Suspicious" or "Malicious" notification.
3. Check data in Kibana:
    * Navigate to **Analytics > Discover**.
    * Select the `logs-*` data view.
    * Enter the KQL filter: `data_stream.dataset : "fortinet_fortiedr.log"`
    * Verify logs appear and confirm fields like `event.dataset`, `event.action`, `fortinet.edr.severity`, `fortinet.edr.classification`, `process.name`, and `host.hostname`.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Common configuration issues

If you encounter issues while setting up or using the Fortinet FortiEDR Logs integration, check the following common scenarios:

- No data is being collected:
    Verify that you've enabled the **Send Syslog Notification** checkbox within the specific active Playbook in the FortiEDR console. Defining the Syslog Export server is a global setting, but alerts are triggered via Playbooks in **Security Settings > Playbooks**. You can verify this by checking the following:
    * Go to **Security Settings > Playbooks** and ensure the specific active Playbook has syslog notifications enabled.
    * Confirm that the FortiEDR Central Manager can reach the Elastic Agent host over the network.
- Port conflicts:
    Verify that no other service is using the port assigned to the Elastic Agent (default is `9509`). You can check for existing bindings on the Agent host using the following command:
    ```bash
    netstat -ano | grep 9509
    ```
- Firewall obstructions:
    Verify that intermediate firewalls or local host firewalls, such as `iptables`, `firewalld`, or Windows Firewall, are allowing traffic from the FortiEDR Manager IP address to the Elastic Agent on the configured port.
- Incorrect listen address:
    If the Elastic Agent isn't receiving data from a remote source, ensure the **Listen Address** is set to `0.0.0.0` instead of `localhost` in the integration settings.
- Parsing failures:
    Check the `error.message` field in Discover. This often indicates the syslog format doesn't match the integration's expectations. Ensure the FortiEDR export format is set to `Semicolon` in the **Administration > Export Settings** menu.
- Timezone misalignment:
    If logs appear in the past or future, verify the `Timezone offset` variable in the Kibana integration settings to ensure it matches the FortiEDR Central Manager's timezone.
- Message truncation:
    For large security events sent via UDP, logs might be truncated. Increase the `max_message_size` and `read_buffer` in the **Custom UDP Options** if you notice incomplete payloads.

For vendor documentation links, see the [Vendor documentation links](#vendor-documentation-links) section.

## Performance and scaling

To ensure optimal performance in high-volume environments, consider these strategies:

*   Transport and collection considerations: While `UDP` provides lower overhead for syslog transmission, you should use `TCP` in environments where you need delivery guarantees to prevent packet loss during traffic spikes. If you use `UDP`, ensure that you tune the `read_buffer` (for example, `100MiB`) and `max_message_size` (for example, `50KiB`) variables within the `Custom UDP Options` to handle high throughput without dropping packets at the kernel level.
*   Data volume management: You can manage the volume of data ingested into Elasticsearch by using FortiEDR Playbook policies to selectively enable the "Send Syslog Notification" option only for critical event categories. Filtering at the source reduces the processing load on the Elastic Agent and helps minimize storage costs associated with high-noise system events.
*   Elastic Agent scaling: For large-scale deployments with high event rates, you'll want to deploy multiple Elastic Agents behind a network load balancer to distribute the syslog traffic evenly. Place agents close to the FortiEDR Central Manager to minimize network latency and ensure horizontal scalability.

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

This reference guide provides details about the inputs and data streams used by the Fortinet FortiEDR Logs integration.

### Inputs used

{{ inputDocs }}

### Data streams

#### log

The `log` data stream provides events from Fortinet FortiEDR of the following types: security alerts, incident details, and endpoint logs.

##### log fields

{{ fields "log" }}

##### log sample event

{{ event "log" }}

### Vendor documentation links

You can find additional information about Fortinet FortiEDR logs in the following resources:
- [FortiEDR Administration Guide: Syslog](https://docs.fortinet.com/document/fortiedr/7.2.0/administration-guide/109591/syslog)
- [FortiEDR Administration Guide: Export Settings](https://docs.fortinet.com/document/fortiedr/7.2.0/administration-guide/918407/export-settings)
- [FortiEDR Administration Guide: Automated Incident Response - Playbooks](https://docs.fortinet.com/document/fortiedr/7.2.0/administration-guide/419440/automated-incident-response-playbooks-page)
- [Fortinet FortiEDR Administration Guide](https://docs.fortinet.com/document/fortiedr/7.2.0/administration-guide)
- [Fortinet Documentation Library](https://docs.fortinet.com/)
- [Elastic Fortinet FortiEDR Integration Reference](https://www.elastic.co/docs/reference/integrations/fortinet_fortiedr)
