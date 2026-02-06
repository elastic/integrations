# QNAP NAS Integration for Elastic

> **Note**: This documentation was generated using AI and should be reviewed for accuracy.

## Overview

The QNAP NAS integration for Elastic enables you to collect and analyze Event and Access logs from your QNAP devices. By ingesting these logs into the Elastic Stack, you can improve your security posture, monitor system health, and maintain audit trails for compliance.

This integration facilitates:
- Security monitoring: Monitor for unauthorized access attempts, failed logins, successful user authentications, and changes to user permissions to detect potential threats and malicious activity.
- Operational insight: Track critical system events such as device reboots, firmware updates, service starts or stops, and storage volume health to manage device status effectively.
- Compliance auditing: Maintain a comprehensive and immutable record of system and user activities on the QNAP NAS, which is essential for meeting regulatory requirements and internal auditing processes.
- Troubleshooting and diagnostics: Use detailed event and access logs to diagnose system problems, identify performance bottlenecks, and resolve configuration issues affecting the NAS device and its users.

### Compatibility

This integration has been tested against QNAP NAS QTS 4.5.4 and is expected to work with versions later than QTS 4.5.4. It's only compatible with logs sent using the "Send to Syslog Server" option, which uses the RFC-3164 syslog format.

This integration is compatible with Elastic Stack version 8.11.0 or higher.

### How it works

This integration collects logs by receiving syslog data over TCP or UDP. You configure your QNAP NAS device to forward its logs to an Elastic Agent running on a host that is reachable from your NAS. The agent acts as a syslog receiver, processes the RFC-3164 formatted logs from the `log` data stream, and forwards them to your Elastic deployment for monitoring and analysis.

## What data does this integration collect?

The QNAP NAS integration collects various types of system and activity logs from your NAS devices. This integration collects the following types of data:
* QNAP NAS logs (TCP): This data stream collects QNAP NAS Event and Access logs using the TCP protocol. It processes logs formatted according to RFC-3164, providing detailed records of system events and user activities.
* QNAP NAS logs (UDP): This data stream collects QNAP NAS Event and Access logs using the UDP protocol. It also processes RFC-3164 formatted logs, offering an alternative for collecting event and access data.

These logs are processed and stored in the `log` data stream.

### Supported use cases

Integrating QNAP NAS logs with the Elastic Stack provides visibility into your storage environment and enhances your security posture. You can use this integration for the following use cases:
* Security monitoring: Monitor user authentication, file access, and administrative changes to identify unauthorized activity or potential security breaches.
* System health tracking: Review system events, hardware status, and service logs to ensure your NAS infrastructure is performing optimally and to receive early warnings of hardware issues.
* Compliance and auditing: Maintain a searchable, long-term archive of access and system logs to satisfy regulatory requirements and simplify internal audits.
* Troubleshooting: Quickly identify the root cause of service interruptions or configuration issues by analyzing detailed system event logs.

## What do I need to use this integration?

To use this integration, you need to satisfy several vendor and Elastic prerequisites.

### Vendor prerequisites

You'll need administrative access and specific applications configured on your QNAP NAS:

- Full administrator access to the QNAP QTS web administration interface to configure log forwarding using the `QuLog Center`.
- The `QuLog Center` application must be installed on your QNAP NAS. If it's not present, you can install it from the App Center.
- Network connectivity between the QNAP NAS and the Elastic Agent host using the chosen protocol (`TCP`, `UDP`, or `TLS`) and port (for example, `9301`). Ensure no firewalls are blocking communication between the NAS and the agent.
- The IP address of the server where the Elastic Agent is running to configure it as the syslog server destination.
- A decision on the protocol and port number the Elastic Agent will listen on, which must match the configuration on both the QNAP NAS and the Elastic Agent.

### Elastic prerequisites

You'll need to have your Elastic environment prepared:

- An Elastic Agent installed and successfully enrolled in Fleet, connected to your Elastic Stack instance.
- Network connectivity that allows the Elastic Agent host to be reached from the QNAP NAS on the configured syslog port (for example, `9301`) and protocol (`TCP`, `UDP`, or `TLS`). Ensure that any host-based firewalls on the Elastic Agent server or network firewalls allow inbound connections on the specified port.
- An Elastic Stack (Elasticsearch and Kibana) version compatible with the version of the Elastic Agent you're using.

## How do I deploy this integration?

### Agent-based deployment

You'll need to install Elastic Agent to use this integration. For detailed instructions, you can follow the Elastic Agent [installation guide](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can only install one Elastic Agent on each host.

You use Elastic Agent to stream data from the syslog receiver and ship it to Elastic, where the events are then processed by the integration's ingest pipelines.

### Set up steps in QNAP NAS

Perform the following steps to configure your QNAP NAS device to send logs to the Elastic Agent:

1.  Log in to your QNAP QTS web administration interface using an administrator account.
2.  Open the QuLog Center application. If you haven't installed it, you can find it in the App Center.
3.  In QuLog Center, navigate to QuLog Service using the left-hand menu.
4.  Click the Log Sender tab to manage your log forwarding settings.
5.  Select the checkbox next to Send logs to a syslog server to enable the forwarding service.
6.  Click Add a log sending rule to start configuring a new syslog destination for your Elastic Agent.
7.  In the rule creation window, configure these settings:
    *   Server: Enter the IP address of the host where your Elastic Agent is running.
    *   Protocol: Choose the protocol (`UDP`, `TCP`, or `TLS`) that matches what you'll configure in the Kibana integration settings.
    *   Port: Specify the port number (for example, `9301`) that you'll configure your Elastic Agent to listen on.
    *   Log Format: Select `RFC-3164` as the log format. This is required for the integration to parse your logs correctly.
8.  Under Log Type, choose the types of logs you want to send. It's recommended that you select both Event Log and Access Log for complete monitoring.
9.  Click the Test button to send a test message to the Elastic Agent and verify that the connection works.
10. If the test is successful, click Apply to save your rule.

#### Vendor resources

For more information about configuring your device, you can refer to the following documentation:

-   [QNAP QTS 5.0.x User Manual](https://docs.qnap.com/operating-system/qts/5.0.x/en-us/configuring-samba-microsoft-networking-settings-7447174D.html)

### Set up steps in Kibana

To set up the integration in Kibana, follow these steps:

1.  In Kibana, navigate to Management > Integrations.
2.  Search for QNAP NAS and select the integration.
3.  Click Add QNAP NAS.
4.  Follow the prompts to add the integration to an existing Elastic Agent policy or create a new one.
5.  Choose the input type that matches your QNAP NAS syslog configuration (TCP or UDP).

#### TCP input configuration

If you're using TCP, configure these fields:

-   Syslog Host: The host address to listen on for syslog messages (for example, `0.0.0.0` or `localhost`).
-   Syslog Port: The port number to listen on (for example, `9301`).
-   Timezone Offset: By default, log timestamps are interpreted based on the agent host's timezone. If your logs come from a different timezone, set the offset (for example, `Europe/Amsterdam` or `-05:00`).
-   SSL Configuration: If you're using TLS, configure your SSL settings here. You can find more details in the [SSL documentation](https://www.elastic.co/guide/en/beats/filebeat/current/configuration-ssl.html#ssl-common-config).
-   Preserve original event: If you enable this, a raw copy of the original event is stored in the `event.original` field.
-   Processors: You can add custom processors to filter or enhance your data before it's parsed.

#### UDP input configuration

If you're using UDP, configure these fields:

-   Syslog Host: The host address to listen on for syslog messages (for example, `0.0.0.0` or `localhost`).
-   Syslog Port: The port number to listen on (for example, `9301`).
-   Timezone Offset: Use this to set the correct timezone offset if the QNAP NAS is in a different timezone than the agent host.
-   Custom UDP Options: You can specify advanced settings like `read_buffer` (for example, `100MiB`), `max_message_size` (for example, `50KiB`), and `timeout` (for example, `300s`).
-   Preserve original event: If you enable this, the raw log is saved in the `event.original` field.
-   Processors: Add processors to modify the events before the agent sends them.

After you've finished configuring the settings, click Save and Deploy to update your agent policy.

### Validation

To verify that your integration is working and data is flowing, follow these steps:

1.  Perform some actions on your QNAP NAS to generate logs:
    *   Log out and log back in to the QTS web interface to create authentication events.
    *   Create or delete a file in a shared folder to generate access logs.
    *   Change a minor system setting, like the Date & Time, to trigger a configuration event.
2.  In Kibana, navigate to Analytics > Discover.
3.  Select the `logs-*` data view.
4.  Enter the following KQL filter to see your logs: `data_stream.dataset : "qnap_nas.log"`
5.  Check that documents are appearing with recent timestamps and that fields like `event.dataset`, `source.ip`, and `message` are correctly populated.
6.  Navigate to Analytics > Dashboards and search for QNAP NAS to view the pre-built dashboards.

## Troubleshooting

For help with Elastic ingest tools, check the [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems) documentation.

### Common configuration issues

Check the following issues if you encounter problems with the integration:
- No logs appearing in Kibana: Verify that the server IP address configured in the QNAP QuLog Center matches the IP address of the Elastic Agent host. Ensure the port number matches the `syslog_port` configured in your integration (the default is `9301`). Confirm that the protocol (UDP, TCP, or TLS) on the QNAP NAS matches the input type selected in the integration. Also, check firewall rules on both the NAS and the Agent host to ensure traffic can pass through. You can use a utility like `tcpdump` on the Agent host to verify reception: `tcpdump -i any port 9301`.
- Logs are present but unparsed or missing fields: In the QNAP QuLog Center, confirm that the log format is set to `RFC-3164`, as other formats are not supported. Check the `error.message` field in Kibana Discover for specific parsing error details. If you've enabled the `preserve_original_event` setting, check the `event.original` field to see the raw log payload. Additionally, verify that the `Timezone Offset` is correctly configured if the NAS is in a different timezone than the Elastic Agent host.
- Parsing failures for specific log types: If certain logs are received but not processed correctly, inspect the `error.message` field for clues. This often happens if the log content deviates from the expected `RFC-3164` standard. Compare the raw log in `event.original` with the standard format to identify discrepancies.

### Vendor resources

For more information about QNAP NAS logging and configuration, refer to the following resources:
- [QNAP QTS 5.0.x User Manual](https://docs.qnap.com/operating-system/qts/5.0.x/en-us/configuring-samba-microsoft-networking-settings-7447174D.html)
- [QNAP NAS Official Website](https://qnap.com)

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

### Transport protocol considerations

When you're configuring syslog collection from QNAP NAS devices, consider the trade-offs between UDP and TCP:
- UDP offers faster, connectionless transmission. It's suitable for high-volume logs where occasional packet loss is acceptable.
- TCP provides reliable, ordered delivery. It ensures all logs are received and is preferred for critical security and audit events, though it's got more overhead.
- TLS can be used with TCP for encrypted transport. It adds security but increases the processing load on both the NAS and the Elastic Agent.

### Data volume management

To optimize performance and reduce the amount of data you're sending to the Elastic stack, configure the QNAP NAS device in the QuLog Center to send only necessary log types:
- Limit forwarding to `Event Log` and `Access Log`.
- Avoid sending unnecessary log categories if they're available in your QNAP software version.
- Be careful about high log volumes, as they can impact the performance of your NAS device.

### Elastic Agent scaling

A single Elastic Agent can handle a significant volume of syslog traffic. For high-throughput environments or when you're collecting from multiple QNAP NAS devices, consider these strategies:
- Deploy multiple Elastic Agents to distribute the log forwarding load.
- Assign each agent to listen on a unique port or IP address.
- Ensure the host running the Elastic Agent has enough CPU, memory, and disk I/O resources to process and forward logs efficiently.

## Reference

### Inputs used

{{ inputDocs }}

### Data streams

#### log

You can use the `log` data stream to view events from your QNAP NAS devices. It's designed to track system activities and connection details across various protocols like `Samba`, `FTP`, `HTTP`, `HTTPS`, and `SSH`.

##### log fields

{{ fields "log" }}

##### log sample event

{{ event "log" }}

### Vendor documentation links

You can find more information about QNAP NAS on these sites:
- [QNAP NAS Official Website](https://qnap.com)
