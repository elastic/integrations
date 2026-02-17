# Imperva Integration for Elastic

> **Note**: This documentation was generated using AI and should be reviewed for accuracy.

## Overview

The Imperva integration for Elastic enables you to collect and analyze logs from Imperva SecureSphere devices using Elastic Agent. By ingesting these logs into the Elastic Stack, you can monitor security events, audit database activity, and gain comprehensive visibility into web application traffic.

### Compatibility

This integration is compatible with Imperva SecureSphere. It supports log collection from SecureSphere appliances configured to export logs via syslog.

This integration is compatible with Elastic Stack version 8.11.0 or higher.

### How it works

This integration collects logs from Imperva SecureSphere by receiving data over the network or by reading from log files. You can configure an Elastic Agent to act as a syslog receiver listening on a specific TCP or UDP port. Alternatively, if logs are being written to a file system accessible by the Elastic Agent, you can use the filestream input to ingest them.

The Elastic Agent processes the incoming logs, parses them into the Elastic Common Schema (ECS) format, and forwards them to your Elastic deployment. This allows you to use pre-built dashboards to visualize security events and perform detailed analysis of your Imperva log data.

## What data does this integration collect?

The Imperva integration collects log messages from your SecureSphere appliances. You'll gain visibility into your security posture and administrative activity through several types of data.

The integration supports the following data stream:
* `securesphere`: You can ingest logs that include security alerts, `audit` records, and system-level events from Imperva SecureSphere.

The types of logs you'll collect include:
* Security alerts: These logs contain details about potential threats, policy violations, and firewall decisions.
* `audit` logs: You'll see records of administrative actions and configuration changes made within the Imperva environment.
* `log` messages: You'll receive system-level information about the health and status of your SecureSphere appliances.

### Supported use cases

Integrating Imperva logs with the Elastic Stack helps you enhance your security operations in several ways:
- Real-time threat detection: You can use Elastic Security to monitor Imperva alerts and respond to potential attacks as they happen.
- Compliance and reporting: You'll be able to store and search through your `audit` and `log` data to satisfy regulatory requirements and simplify security audits.
- Incident investigation: You can correlate Imperva events with other data sources in Elastic to understand the full scope of a security incident.
- Operational monitoring: You'll track system events and hardware status to ensure your Imperva deployment remains healthy and effective.

## What do I need to use this integration?

You need the following to use this integration:

- An Imperva SecureSphere device with administrative access to configure log forwarding or log file generation.
- Network connectivity between your Imperva SecureSphere device and the Elastic Agent host for TCP or UDP syslog delivery. By default, the integration listens on port `9507`.
- Permissions for the Elastic Agent to read log files if you're using the filestream input method.
- Elastic Stack version 8.11.0 or higher.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed on a host that will receive the syslog data or has access to the log files from the Imperva SecureSphere device. For detailed installation instructions, refer to the Elastic Agent [installation guide](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). Only one Elastic Agent is needed per host.

### Set up steps in Imperva

To send logs from Imperva SecureSphere to Elastic Agent, you'll need to create or modify an action set that sends data via syslog:

1. Log in to the SecureSphere Management Server (MX) console.
2. Navigate to **Main > Policies > Action Sets**.
3. Click the **New** icon to create a new action set.
4. Provide a name for the action set (for example, `Elastic_Agent_Syslog`).
5. In the **Action Interface** column, select **Gateway System Log** or **External Log**.
6. In the **Action** column, select the specific action to send the log.
7. Configure the following parameters for the action:
    *   **Syslog Host**: The IP address of the host where the Elastic Agent is installed.
    *   **Syslog Port**: The port number configured in the Elastic integration (for example, `9507`).
    *   **Protocol**: The protocol configured in the Elastic integration (`TCP` or `UDP`).
    *   **Message Format**: Choose a format that provides the necessary detail (standard Syslog or LEEF/CEF if applicable).
8. Navigate to the relevant policy (for example, Security, Audit, or System) where you want to apply this action set.
9. In the **Apply To** or **Action** section of the policy, select the action set you just created.
10. Click **Save** to apply the changes.

### Set up steps in Kibana

To set up the integration in Kibana, follow these steps:

1. In Kibana, navigate to **Management > Integrations**.
2. Search for **Imperva** and select the integration.
3. Click **Add Imperva**.
4. Configure the integration by selecting an input type and providing the necessary settings. This integration supports `TCP`, `UDP`, and `Filestream` inputs.

#### TCP input configuration

This input collects logs over a TCP socket. Configure the following settings:

| Setting | Description |
|---|---|
| **Listen address** | The bind address for the TCP listener (for example, `localhost` or `0.0.0.0`). |
| **Listen port** | The TCP port number to listen on (for example, `9507`). |
| **Timezone offset** | Specify an IANA timezone or offset (for example, `+0200`) for logs with no timezone information. |
| **Preserve original event** | If checked, a raw copy of the original log is stored in the `event.original` field. |

Under **Advanced options**, you can configure the following optional parameters:

| Setting | Description |
|---|---|
| **Custom TCP options** | Specify custom configuration options for the TCP input, such as `max_message_size` or `max_connections`. |
| **SSL configuration** | Configure SSL options for encrypted communication. See the [SSL documentation](https://www.elastic.co/guide/en/beats/filebeat/current/configuration-ssl.html#ssl-common-config) for details. |
| **Preserve duplicate custom fields** | If checked, `imperva.securesphere` fields that were copied to Elastic Common Schema (ECS) fields are preserved. |
| **Processors** | Add custom processors to enhance or reduce event fields before parsing. |

#### UDP input configuration

This input collects logs over a UDP socket. Configure the following settings:

| Setting | Description |
|---|---|
| **Listen address** | The bind address for the UDP listener (for example, `localhost` or `0.0.0.0`). |
| **Listen port** | The UDP port number to listen on (for example, `9507`). |
| **Timezone offset** | Specify an IANA timezone or offset (for example, `+0200`) for logs with no timezone information. |
| **Preserve original event** | If checked, a raw copy of the original log is stored in the `event.original` field. |

Under **Advanced options**, you can configure the following optional parameters:

| Setting | Description |
|---|---|
| **Custom UDP options** | Specify custom configuration options for the UDP input, such as `max_message_size` or `timeout`. |
| **Preserve duplicate custom fields** | If checked, `imperva.securesphere` fields that were copied to Elastic Common Schema (ECS) fields are preserved. |
| **Processors** | Add custom processors to enhance or reduce event fields before parsing. |

#### Filestream input configuration

This input collects logs directly from log files on the host where the Elastic Agent is running. Configure the following settings:

| Setting | Description |
|---|---|
| **Paths** | A list of file paths to monitor (for example, `/var/log/imperva-securesphere.log`). |
| **Timezone offset** | Specify an IANA timezone or offset (for example, `+0200`) for logs with no timezone information. |
| **Preserve original event** | If checked, a raw copy of the original log is stored in the `event.original` field. |

Under **Advanced options**, you can configure the following optional parameters:

| Setting | Description |
|---|---|
| **Custom filestream options** | Specify custom configuration options for the Filestream input. |
| **Preserve duplicate custom fields** | If checked, `imperva.securesphere` fields that were copied to Elastic Common Schema (ECS) fields are preserved. |
| **Processors** | Add custom processors to enhance or reduce event fields before parsing. |

### Validation

To validate that the integration is working properly and data is flowing into Elasticsearch:

1. Verify on the Imperva SecureSphere device that logs are being sent to the configured Elastic Agent host and port.
2. In Kibana, navigate to **Discover**.
3. Select the `logs-*` index pattern or use the search bar to enter `data_stream.dataset: "imperva.securesphere"` and check for incoming documents.
4. Verify that events are appearing with recent timestamps and that fields are being parsed correctly.
5. Navigate to **Management > Dashboards** and search for **Imperva SecureSphere Overview** to see if the visualizations are populated with data.
6. Trigger a test alert or generate traffic in Imperva that would be logged to confirm the data appears in Kibana.

## Troubleshooting

For help with Elastic ingest tools, you can check the [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems) documentation.

### Common configuration issues

You might encounter the following issues when configuring the integration:

- No data is being collected: Check that the Imperva device can reach the Elastic Agent host on the configured port. By default, this is port `9507`. You can use tools like `tcpdump` or `nc` to verify that traffic is arriving at the host.
- Incorrect timestamps: If your logs don't include a timezone, the agent assumes the local timezone of the host where it's running. You can use the `tz_offset` setting in the integration configuration to adjust this if the Imperva device is in a different timezone.
- Parsing errors or missing fields: This integration expects logs in the Common Event Format (CEF). You'll need to ensure that your Imperva SecureSphere SIEM logging policy is configured to use the CEF format; otherwise, the agent won't be able to extract fields correctly.
- Connection refused for TCP: If you've enabled SSL/TLS for the TCP input, ensure that the certificates are valid and that the client (Imperva) is configured to use the correct CA. You should also check that the `listen_address` is set to `0.0.0.0` if you want the agent to listen on all network interfaces.
- UDP packet loss: If you're using UDP and notice missing logs, you might be experiencing packet loss due to network congestion or small buffer sizes. You can try increasing the `max_message_size` in the UDP options or switching to TCP for more reliable delivery.

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

When you're dealing with high-volume log environments, particularly with syslog-based inputs like TCP or UDP used by Imperva SecureSphere, consider the following scaling strategies:

- Use a load balancer: Place a network load balancer in front of multiple Elastic Agents to distribute the incoming syslog traffic evenly. This ensures that no single agent becomes a bottleneck.
- Increase agent resources: Monitor the CPU and memory usage of your Elastic Agents. You might need to increase the allocated resources if you're processing a high volume of events per second.
- Adjust buffer sizes: For the UDP input, you can adjust the `max_message_size` or kernel receive buffer sizes to prevent packet loss during traffic spikes.
- Use dedicated collectors: For extremely high throughput, consider using Logstash as an intermediate collector and buffer before sending data to Elasticsearch.

You can also optimize performance by managing how much data you store. For example:
- Disable `preserve_original_event` in the integration settings if you don't need the raw log message stored in the `event.original` field. This reduces the disk space used in Elasticsearch.
- Use the `processors` setting to drop unnecessary fields or events at the agent level before they're sent over the network.

## Reference

The following resources provide additional information for configuring Imperva SecureSphere:
- [Imperva Documentation Portal](https://docs.imperva.com/)
- [SecureSphere Administration Guide - Action Sets](https://docs-cybersec.thalesgroup.com/bundle/v15.0-waf-management-server-manager-user-guide/page/Working_with_Action_Sets_and_Followed_Actions.htm)

### Inputs used

{{ inputDocs }}

### Data streams

#### securesphere

The `securesphere` data stream provides events from Imperva SecureSphere of the following types:
- Security alerts and policy violations
- Database activity monitoring logs
- Administrative audit trails and system events

##### securesphere fields

{{ fields "securesphere" }}

##### securesphere sample event

{{ event "securesphere" }}
