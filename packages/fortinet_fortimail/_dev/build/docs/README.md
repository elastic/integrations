# Fortinet FortiMail Integration for Elastic

> **Note**: This AI-assisted guide was validated by our engineers. You may need to adjust the steps to match your environment.

## Overview

The Fortinet FortiMail integration for Elastic enables you to collect and analyze logs from your FortiMail instances. FortiMail provides multi-layered protection against a wide spectrum of email-borne threats, including spam, phishing, malware, zero-day threats, impersonation, and Business Email Compromise (BEC) attacks. By integrating FortiMail with the Elastic Stack, you gain visibility into your email environment and can correlate security events across your infrastructure.

This integration facilitates:
- Email traffic analysis: Monitor all incoming and outgoing email traffic, including sender, recipient, subject, and delivery status, to gain insights into mail flow patterns and identify anomalies.
- System activity monitoring: Track system management activities, administrator logins/logouts, and configuration changes to maintain an audit trail and detect unauthorized modifications.
- Threat detection and response: Identify and analyze antispam and antivirus events to detect email-borne threats like spam, phishing, malware, and zero-day attacks, enabling quicker response.
- Encryption event auditing: Keep a record of IBE-related (Identity-Based Encryption) events to ensure compliance and monitor the usage and effectiveness of email encryption policies.

### Compatibility

This integration is compatible with Fortinet FortiMail version 7.2.2.

This integration is compatible with Elastic Stack version 8.11.0 or higher.

### How it works

This integration collects logs from FortiMail by receiving syslog data or reading log files directly. You configure your FortiMail instance to forward logs in CSV format to an Elastic Agent using `tcp` or `udp`. Alternatively, the agent can read logs from a local file using the `filestream` input. The agent then processes the data through the `log` data stream and maps it to the Elastic Common Schema (ECS), allowing you to visualize and analyze it using Kibana dashboards.

The integration supports the following event types:
- History events
- System events
- Mail events
- Antispam events
- Antivirus events
- Encryption events

## What data does this integration collect?

The Fortinet FortiMail integration collects log messages in CSV format for the following types:
* History events: Records of email processing, delivery status, and message flow through the appliance.
* System events: Logs related to appliance management, administrator actions, and system health status.
* Mail events: Details about processed email messages and their attributes.
* Antispam events: Records of messages identified as spam, phishing, or graymail based on your configured filters.
* Antivirus events: Details about detected malware, viruses, and suspicious attachments found in emails.
* Encryption events: Records of secure email delivery, including encryption and decryption actions.

This integration includes the following data stream:
* `log`: Collects FortiMail event logs sent via Syslog (`TCP` or `UDP`) or read from a file using `filestream`.

### Supported use cases

Integrating your FortiMail logs with Elastic provides visibility into your email security environment and helps you with several key tasks:
* Email threat detection: You can monitor and analyze spam, malware, and phishing attempts across your organization in real-time.
* Security incident response: You'll be able to correlate email security events with data from other sources in Elastic to investigate complex attacks.
* Compliance and auditing: You can maintain long-term, searchable archives of mail flow and administrative actions to meet regulatory requirements.
* Operational monitoring: You'll gain insights into mail delivery performance and system health to ensure your email infrastructure is running smoothly.

## What do I need to use this integration?

You'll need the following to use this integration:
- Full administrative access to the FortiMail web UI to configure logging settings.
- Network connectivity between your FortiMail device and the server hosting the Elastic Agent.
- Open ports in any intervening firewalls, such as `UDP 514` or `TCP 9024`, to allow Syslog traffic.
- The `CSV` format option enabled in your FortiMail logging configuration. This setting is mandatory for the integration to parse logs correctly.
- The IP address of your Elastic Agent host and the specific port it's configured to listen on for Syslog messages.
- An Elastic Agent installed and enrolled in Fleet.
- Connectivity that allows the Elastic Agent host to be reached from the FortiMail device over the configured Syslog protocol (TCP or UDP) and port.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed on a host that can receive syslog data or access the log files from Fortinet FortiMail. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

Elastic Agent is required to:
- Stream data from the syslog or log file receiver.
- Ship the data to Elastic, where the events are processed via the integration's ingest pipelines.

### Set up steps in Fortinet FortiMail

Follow these steps to configure your FortiMail instance:

1. Log in to the FortiMail web UI.
2. Navigate to **Log & Report > Log Setting > Remote**.
3. Click **New** to create a new remote logging profile.
4. In the configuration dialog, check the **Enable** box to activate the profile.
5. You'll need to configure the following settings for the syslog server:
    * Name: Enter a descriptive name for the logging target, such as `elastic-agent-syslog`.
    * Server name/IP: Enter the IP address of the server where the Elastic Agent is running (replace with your actual value).
    * Port: Enter the port number that the Elastic Agent is configured to listen on for syslog messages, such as UDP `9024` or TCP `9024` (replace with your actual value).
    * Level: Select the minimum severity level of logs to be sent. A common starting point is `Notice` or `Information`.
    * Facility: Choose a facility identifier to distinguish FortiMail logs, for example, `local7`. This must match what you expect in the agent's configuration.
    * CSV format: This is a mandatory step. Enable this option to ensure logs are sent in the comma-separated value (CSV) format required for parsing.
    * Log protocol: Select **Syslog**.
6. In the **Logging Policy Configuration** section at the bottom of the dialog, select the checkboxes for all the log types you wish to collect:
    * History
    * System Event
    * Mail Event
    * Antispam
    * Antivirus
    * Encryption
7. Click **Create** to save the remote logging profile. FortiMail will begin forwarding logs that match your configuration to the specified Elastic Agent.

#### Vendor resources

For more information, refer to the following vendor documentation:
- [FortiMail Administration Guide: Configuring Syslog](https://docs.fortinet.com/document/fortimail/7.2.2/administration-guide/332364)
- [FortiMail Administration Guide: About FortiMail Logging](https://docs.fortinet.com/document/fortimail/7.2.2/administration-guide/435158/about-fortimail-logging)

### Set up steps in Kibana

1. In Kibana, navigate to **Management > Integrations**.
2. Search for **Fortinet FortiMail** and select it.
3. Click **Add Fortinet FortiMail**.
4. Follow the prompts to add the integration to an existing Elastic Agent policy or create a new one.
5. Configure the input type based on your FortiMail setup.

The integration supports the following input types:

#### Filestream input configuration

Configure these fields to collect logs from a file:
- Paths: Provide a list of glob-based paths for the agent to crawl and fetch (e.g., `/var/log/fortimail/*.log`).
- Timezone Offset: Set the timezone offset so datetimes are correctly parsed if you're ingesting logs from a host on a different timezone. Use a canonical ID (e.g., `Europe/Amsterdam`) or an HH:mm differential (e.g., `-05:00`). Default: `local`.
- Preserve original event: Check this to preserve a raw copy of the original event in the `event.original` field. Default: `false`.
- Tags: Add custom tags to your events. Default: `['forwarded', 'fortinet_fortimail-log']`.
- Preserve duplicate custom fields: Check this to preserve `fortinet_fortimail.log` fields that were copied to Elastic Common Schema (ECS) fields. Default: `false`.
- Processors: Add custom processors to reduce or enhance the exported event metadata before parsing.

#### TCP input configuration

Configure these fields to collect logs over a TCP socket:
- Listen Address: Set the bind address to listen for TCP connections (e.g., `0.0.0.0` to bind to all available interfaces). Default: `localhost`.
- Listen Port: Set the TCP port number to listen on. Default: `9024`.
- Preserve original event: Check this to preserve a raw copy of the original event in the `event.original` field. Default: `false`.
- Custom TCP Options: Specify custom configuration options such as `framing: rfc6587`, `max_message_size: 50KiB`, or `max_connections: 1`.
- SSL Configuration: Set the SSL configuration options for encrypted communication. See the [SSL documentation](https://www.elastic.co/guide/en/beats/filebeat/current/configuration-ssl.html#ssl-common-config) for details.
- Timezone Offset: Set the timezone offset so datetimes are correctly parsed. Default: `local`.
- Tags: Add custom tags to your events. Default: `['forwarded', 'fortinet_fortimail-log']`.
- Preserve duplicate custom fields: Check this to preserve fields that were copied to ECS fields. Default: `false`.
- Processors: Add custom processors to enhance or reduce event fields.

#### UDP input configuration

Configure these fields to collect logs over a UDP socket:
- Listen Address: Set the bind address to listen for UDP connections (e.g., `0.0.0.0`). Default: `localhost`.
- Listen Port: Set the UDP port number to listen on. Default: `9024`.
- Timezone Offset: Set the timezone offset for correct parsing of datetimes. Default: `local`.
- Preserve original event: Check this to preserve a raw copy of the original event in the `event.original` field. Default: `false`.
- Custom UDP Options: Specify options such as `read_buffer` or `max_message_size: 50KiB`.
- Tags: Add custom tags to your events. Default: `['forwarded', 'fortinet_fortimail-log']`.
- Preserve duplicate custom fields: Check this to preserve fields that were copied to ECS fields. Default: `false`.
- Processors: Add custom processors to manage event data before parsing.

After you finish the configuration, save and deploy the integration.

### Validation

To verify your deployment, follow these steps:

1. Navigate to **Management > Fleet > Agents** and confirm the status of your Elastic Agent is `Healthy`.
2. You can perform the following actions to generate test data in Fortinet FortiMail:
    * Send a test email through the FortiMail unit to generate `History` and `Mail Event` logs.
    * Log in and out of the FortiMail web UI to generate `System Event` logs.
    * Trigger an antispam or antivirus rule with a test email to generate `Antispam` or `Antivirus` logs.
    * Modify a non-critical configuration setting to generate a `System Event` log.
3. In Kibana, navigate to **Analytics > Discover**.
4. Select the `logs-*` data view and enter the following KQL filter: `data_stream.dataset : "fortinet_fortimail.log"`
5. Verify the following fields are populated:
    * `event.dataset` (should be `fortinet_fortimail.log`)
    * `fortinet_fortimail.log.type` (e.g., `History`, `System`, `Mail`, `Antispam`, `Antivirus`)
    * `event.outcome` or `event.action`
    * `message` (containing the raw log)
6. Navigate to **Analytics > Dashboards** and search for **Fortinet FortiMail** to view pre-built visualizations.

## Troubleshooting

For help with Elastic ingest tools, check the [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems) documentation.

### Common configuration issues

The following issues are commonly encountered when setting up the Fortinet FortiMail integration:
- CSV format not enabled: If your logs aren't being parsed correctly or fields appear unorganized, the FortiMail device might not be sending logs in CSV format. To fix this, log in to the FortiMail web UI, navigate to Log & Report > Log Setting > Remote, edit the logging profile for the Elastic Agent, and ensure you've checked the CSV format option.
- Incorrect syslog server IP or port: If no logs reach the Elastic Agent, double-check the Server name/IP and Port settings in your FortiMail remote logging profile against the `listen_address` and `listen_port` you configured in the Elastic Agent's integration policy.
- Firewall blocking syslog traffic: Network firewalls between the FortiMail appliance and the Elastic Agent host can block syslog traffic. Ensure the configured syslog port (e.g., `9024`) is open bi-directionally on all firewalls. You can use tools like `nc` or `telnet` to test connectivity from the FortiMail to the Elastic Agent host.
- Facility or level mismatch: Logs might not be forwarded if the FortiMail's logging level or facility code doesn't match what you expect. For troubleshooting, set the FortiMail's logging Level to Debug or Information and ensure you've selected all relevant log types in the Logging Policy Configuration section.
- Parsing failures due to malformed CSV: If you see `error.message` fields in Kibana or events are dropped, it indicates the logs aren't in the expected CSV format or have unexpected deviations. Verify that the CSV format option is explicitly enabled on the FortiMail device and check the raw `message` field in Kibana for any discrepancies.
- TCP framing issues: When you use the TCP input, ensure the framing settings match between your FortiMail device and the Elastic Agent configuration. The integration defaults to `rfc6587`. If you've customized the syslog format on the vendor side, you may need to adjust the Custom TCP Options to match the expected framing or line delimiters.

### Vendor resources

For more information, refer to the following Fortinet documentation:
- [Fortinet FortiMail Product Page](https://www.fortinet.com/products/email-security)
- [About FortiMail logging](https://docs.fortinet.com/document/fortimail/7.2.2/administration-guide/435158/about-fortimail-logging)
- [FortiMail Administration Guide: Configuring Syslog](https://docs.fortinet.com/document/fortimail/7.2.2/administration-guide/332364)

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

### Transport and collection
When you collect logs via syslog for the `log` data stream, you can choose between `TCP` and `UDP` protocols:
*   `TCP` offers reliable, ordered delivery. This ensures all your log data arrives, which is crucial for auditing and security monitoring.
*   `UDP` provides faster, connectionless delivery. It's suitable for high-volume, less critical logs where you can accept some data loss in exchange for performance gains.

### Data volume management
To manage high data volumes and reduce processing overhead on both the FortiMail device and the Elastic Agent, you should configure the FortiMail device to forward only necessary logs. You can do this by:
*   Selecting `Notice` or `Information` severity levels.
*   Enabling only specific log categories required for monitoring, such as `History`, `System Event`, `Mail Event`, `Antispam`, `Antivirus`, or `Encryption`.

### Elastic Agent scaling
While a single Elastic Agent can handle a significant volume of syslog data, you should deploy multiple Elastic Agents for high-throughput environments or geographically dispersed FortiMail instances. To ensure optimal performance:
*   Resource each agent with appropriate CPU and memory based on your expected log volume.
*   Distribute your FortiMail devices across multiple agents to balance the load and ensure no single agent becomes a bottleneck.

## Reference

### Inputs used

{{ inputDocs }}

### Data streams

#### log

The `log` data stream collects various log types from Fortinet FortiMail instances, including system events, virus detections, spam filtering results, and mail delivery logs.

##### log fields

{{ fields "log" }}

##### log sample event

{{ event "log" }}

### Vendor documentation links

For more information about Fortinet FortiMail logging and configuration, you can refer to the following resources:
* [Fortinet FortiMail Product Page](https://www.fortinet.com/products/email-security)
* [About FortiMail logging](https://docs.fortinet.com/document/fortimail/7.2.2/administration-guide/435158/about-fortimail-logging)
* [FortiMail Administration Guide: About Logging](https://docs.fortinet.com/document/fortimail/7.2.2/administration-guide/435158/about-fortimail-logging)
* [FortiMail Administration Guide: Configuring Syslog](https://docs.fortinet.com/document/fortimail/7.2.2/administration-guide/332364/configuring-logging#logging_2063907032_1949484)
