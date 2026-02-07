# QNAP NAS Integration for Elastic

> **Note**: This documentation was generated using AI and should be reviewed for accuracy.

## Overview

The QNAP NAS integration for Elastic enables you to collect and analyze Event and Access logs from your QNAP devices. By ingesting these logs into the Elastic Stack, you'll improve your security posture, monitor system health, and maintain audit trails for compliance.

This integration facilitates:
- Security monitoring: Monitor for unauthorized access attempts, failed logins, successful user authentications, and changes to user permissions to detect potential threats and malicious activity.
- Operational insight: Track critical system events such as device reboots, firmware updates, service starts or stops, and storage volume health to manage device status effectively.
- Compliance auditing: Maintain a comprehensive and immutable record of system and user activities on the QNAP NAS, which is essential for meeting regulatory requirements and internal auditing processes.
- Troubleshooting and diagnostics: Use detailed event and access logs to diagnose system problems, identify performance bottlenecks, and resolve configuration issues affecting the NAS device and its users.

### Compatibility

This integration has been tested against QNAP NAS QTS 4.5.4 and is expected to work with versions later than QTS 4.5.4. It's only compatible with logs sent using the "Send to Syslog Server" option, which uses the RFC-3164 syslog format.

### How it works

This integration collects logs by receiving syslog data over TCP or UDP. You configure your QNAP NAS device to forward its logs to an Elastic Agent running on a host that is reachable from your NAS. The agent acts as a syslog receiver, processes the RFC-3164 formatted logs from the `log` data stream, and forwards them to your Elastic deployment for monitoring and analysis.

## What data does this integration collect?

You can use the QNAP NAS integration to collect various system and activity logs from your NAS devices. It's designed to collect the following types of log messages:
- QNAP NAS logs (TCP): This data stream collects QNAP NAS event and access logs using the TCP protocol. It processes logs formatted according to RFC-3164, providing you with detailed records of system events and user activities.
- QNAP NAS logs (UDP): This data stream collects QNAP NAS event and access logs using the UDP protocol. It also processes RFC-3164 formatted logs, offering you an alternative for collecting event and access data.

You'll find these logs processed and stored in the `log` data stream.

### Supported use cases

Integrating your QNAP NAS logs with the Elastic Stack gives you visibility into your storage environment and helps you improve your security posture. You can use this integration for the following use cases:
- Security monitoring: You can monitor user authentication, file access, and administrative changes to identify unauthorized activity or potential security breaches.
- System health tracking: You'll be able to review system events, hardware status, and service logs to ensure your NAS infrastructure is performing optimally and to receive early warnings of hardware issues.
- Compliance and auditing: You'll maintain a searchable, long-term archive of access and system logs to satisfy regulatory requirements and simplify your internal audits.
- Troubleshooting: You can quickly identify the root cause of service interruptions or configuration issues by analyzing detailed system event logs.

## What do I need to use this integration?

You'll need to satisfy several vendor and Elastic prerequisites before you can use this integration.

### Vendor prerequisites

You'll need administrative access and specific applications configured on your QNAP NAS:
- You'll need full administrator access to the QNAP QTS web administration interface to configure log forwarding using the `QuLog Center`.
- You must install the `QuLog Center` application on your QNAP NAS. If it's not present, you can install it from the App Center.
- Ensure you have network connectivity between the QNAP NAS and the Elastic Agent host using your chosen protocol (`TCP`, `UDP`, or `TLS`) and port (for example, `9301`). Check that no firewalls are blocking communication between the NAS and the agent.
- You'll need the IP address of the server where the Elastic Agent is running so you can configure it as the syslog server destination.
- Decide on the protocol and port number the Elastic Agent will listen on; your choice must match the configuration on both the QNAP NAS and the Elastic Agent.

### Elastic prerequisites

You'll need to have your Elastic environment prepared:
- You must have an Elastic Agent installed and successfully enrolled in Fleet, connected to your Elastic Stack instance.
- Ensure the Elastic Agent host is reachable from the QNAP NAS on the configured syslog port (for example, `9301`) and protocol (`TCP`, `UDP`, or `TLS`). You should verify that any host-based firewalls on the Elastic Agent server or network firewalls allow inbound connections on the specified port.
- Use an Elastic Stack (Elasticsearch and Kibana) version that is compatible with the version of the Elastic Agent you're using.

## How do I deploy this integration?

### Agent-based deployment

You must install Elastic Agent to use this integration. For detailed installation instructions, refer to the Elastic Agent [installation guide](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can only install one Elastic Agent per host.

Elastic Agent is required to stream data from the syslog receiver and ship the data to Elastic, where the events are then processed using the integration's ingest pipelines.

### Set up steps in QNAP NAS

Follow these steps to configure your QNAP NAS device to send logs to the Elastic Agent:

1.  Log in to your QNAP QTS web administration interface using an administrator account.
2.  Open the **QuLog Center** application. If it's not installed, navigate to the **App Center** and install it.
3.  In QuLog Center, navigate to **QuLog Service** using the left-hand menu.
4.  Click the **Log Sender** tab to manage log forwarding settings.
5.  Select the checkbox next to **Send logs to a syslog server** to enable the log forwarding service.
6.  Click **Add a log sending rule** to initiate the configuration of a new syslog destination for the Elastic Agent.
7.  In the rule creation window, configure the following settings:
    *   Server: Enter the IP address of the server where your Elastic Agent is running.
    *   Protocol: Choose the protocol (`UDP`, `TCP`, or `TLS`) that precisely matches the syslog input configuration of your Elastic Agent.
    *   Port: Specify the port number (for example, `9301`) that your Elastic Agent is configured to listen on for syslog messages.
    *   Log Format: Select `RFC-3164` as the log format. This is critical for the integration to correctly parse the logs.
8.  Under Log Type, choose the types of logs you wish to send. It's recommended to select both **Event Log** and **Access Log** for comprehensive monitoring.
9.  Click the **Test** button to send a test message from the QNAP NAS to the configured Elastic Agent and verify that the connection is successful.
10. If the test is successful, click **Apply** to save the log sending rule.

#### Vendor resources

For more information about configuring your device, you can refer to the following documentation:

- [QNAP QTS 5.0.x User Manual](https://docs.qnap.com/operating-system/qts/5.0.x/en-us/configuring-samba-microsoft-networking-settings-7447174D.html)

### Set up steps in Kibana

To set up the integration in Kibana, follow these steps:

1.  In Kibana, navigate to **Management > Integrations**.
2.  Search for QNAP NAS and select the integration.
3.  Click **Add QNAP NAS**.
4.  Follow the prompts to add the integration to an existing Elastic Agent policy or create a new one.
5.  Choose the setup instructions below that match your QNAP NAS syslog configuration.

#### Collecting logs from QNAP NAS using TCP

This input collects logs over a TCP socket. Configure the following fields:

- Syslog Host: The host address to listen on for syslog messages (for example, `0.0.0.0` or `localhost`).
- Syslog Port: The port number to listen on (for example, `9301`).
- Timezone Offset: By default, log timestamps are interpreted based on the agent host's timezone. Use this field to set the correct offset (for example, `Europe/Amsterdam` or `-05:00`) if the logs come from a different timezone.
- SSL Configuration: Configure SSL options for encrypted communication. Refer to the [SSL documentation](https://www.elastic.co/guide/en/beats/filebeat/current/configuration-ssl.html#ssl-common-config) for details.
- Preserve original event: If enabled, a raw copy of the original log is stored in the `event.original` field.
- Tags: Add custom tags to your events (defaults to `qnap-nas` and `forwarded`).
- Processors: Add custom processors to enhance or reduce event fields before parsing.

#### Collecting logs from QNAP NAS using UDP

This input collects logs over a UDP socket. Configure the following fields:

- Syslog Host: The host address to listen on for syslog messages (for example, `0.0.0.0` or `localhost`).
- Syslog Port: The port number to listen on (for example, `9301`).
- Timezone Offset: Use this to set the correct timezone offset if the QNAP NAS is in a different timezone than the agent host.
- Preserve original event: If enabled, the raw log is saved in the `event.original` field.
- Tags: Add custom tags to your events (defaults to `qnap-nas` and `forwarded`).
- Custom UDP Options: Specify advanced configuration options for the UDP input, such as:
  ```yaml
  read_buffer: 100MiB
  max_message_size: 50KiB
  timeout: 300s
  ```
- Processors: Add custom processors to modify the events before the agent sends them.

After configuring the settings, click **Save and Deploy** to update your agent policy.

### Validation

Follow these steps to verify that the integration is working and data is flowing to the Elastic Stack:

1.  Trigger data flow on the QNAP NAS by performing any of the following actions:
    - Log out of the QNAP QTS web administration interface and then log back in to generate authentication events.
    - Access a shared folder and create or delete a file to generate access logs.
    - Change a system setting like Date & Time or network settings to trigger configuration events.
    - Access a shared folder from a client device using SMB/CIFS or NFS to generate additional access logs.
2.  Check the data in Kibana using these steps:
    - Navigate to **Analytics > Discover**.
    - Select the `logs-*` data view.
    - Enter the following KQL filter: `data_stream.dataset : "qnap_nas.log"`.
    - Verify that logs appear in the results and confirm that fields like `event.dataset`, `source.ip`, and `message` are populated.
    - Navigate to **Analytics > Dashboards** and search for QNAP NAS to view the pre-built visualizations.

## Troubleshooting

For help with Elastic ingest tools, check the [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems) documentation.

### Common configuration issues

If you encounter problems with the integration, check these common issues:
- No logs appearing in Kibana: Verify that the server IP address you configured in the QNAP QuLog Center's Send to Syslog Server tab matches the IP address of the Elastic Agent host. Make sure the port number matches the `syslog_port` you configured in your integration (the default is `9301`). You'll also want to confirm that the protocol (UDP, TCP, or TLS) on the QNAP NAS matches the input type you selected in the integration. Also, check firewall rules on both the NAS and the Agent host to ensure traffic can pass through. You can use a utility like `tcpdump` on the Agent host to verify reception: `tcpdump -i any port 9301`.
- Logs are present but unparsed or missing fields: In the QNAP QuLog Center, confirm that you've set the log format to `RFC-3164`, as other formats aren't supported. Check the `error.message` field in Kibana Discover for specific parsing error details. If you've enabled the `preserve_original_event` setting, check the `event.original` field to view the raw log payload. Additionally, verify that you've correctly configured the `Timezone Offset` if the NAS is in a different timezone than the Elastic Agent host.
- Parsing failures for specific log types: If you receive certain logs but they aren't processed correctly, inspect the `error.message` field for clues. This often happens if the log content deviates from the expected `RFC-3164` standard. You can compare the raw log in `event.original` with the standard format to identify discrepancies.

### Vendor resources

For more information about QNAP NAS logging and configuration, you can refer to these resources:
- [QNAP QTS 5.0.x User Manual](https://docs.qnap.com/operating-system/qts/5.0.x/en-us/configuring-samba-microsoft-networking-settings-7447174D.html)
- [QNAP NAS Official Website](https://qnap.com)

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

### Transport protocol considerations

When you're configuring syslog collection from QNAP NAS devices, consider these trade-offs between `UDP` and `TCP`:
- `UDP` offers faster, connectionless transmission. It's suitable for high-volume logs where occasional packet loss is acceptable.
- `TCP` provides reliable, ordered delivery. It ensures all logs are received and is preferred for critical security and audit events, though it has more overhead.
- `TLS` can be used with `TCP` for encrypted transport. It adds security but increases the processing load on both the NAS and the Elastic Agent.

### Data volume management

To optimize performance and reduce the amount of data you're sending to the Elastic Stack, configure the QNAP NAS device in the `QuLog Center` to send only necessary log types:
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

The `log` data stream provides events from QNAP NAS of the following types: system activities and connection details for protocols such as `Samba`, `FTP`, `HTTP`, `HTTPS`, and `SSH`.

##### log fields

{{ fields "log" }}

##### log sample event

{{ event "log" }}

### Vendor documentation links

This resource provides additional information about QNAP NAS:
- [QNAP NAS Official Website](https://qnap.com)
