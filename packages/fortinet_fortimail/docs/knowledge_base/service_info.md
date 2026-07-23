# Service Info

## Common use cases

The Fortinet FortiMail integration provides comprehensive visibility into email security and system operations by collecting and parsing various event logs.
- **Email Traffic Analysis**: Monitor all incoming and outgoing email traffic, including sender, recipient, subject, and delivery status, to gain insights into mail flow patterns and identify anomalies.
- **System Activity Monitoring**: Track system management activities, administrator logins/logouts, and configuration changes to maintain an audit trail and detect unauthorized modifications.
- **Threat Detection and Response**: Identify and analyze Antispam and Antivirus events to detect email-borne threats like spam, phishing, malware, and zero-day attacks, enabling quicker response.
- **Encryption Event Auditing**: Keep a record of IBE-related (Identity-Based Encryption) events to ensure compliance and monitor the usage and effectiveness of email encryption policies.

## Data types collected

This integration can collect the following types of data:
- **Fortinet FortiMail logs (log)**: Collects Fortinet FortiMail logs via Filestream input. This datastream provides event logs including History, System, Mail, Antispam, Antivirus, and Encryption events, all expected in CSV format.
- **Fortinet FortiMail logs (log)**: Collects Fortinet FortiMail logs via TCP input. This datastream provides event logs including History, System, Mail, Antispam, Antivirus, and Encryption events, sent over TCP, formatted as CSV.
- **Fortinet FortiMail logs (log)**: Collects Fortinet FortiMail logs via UDP input. This datastream provides event logs including History, System, Mail, Antispam, Antivirus, and Encryption events, sent over UDP, formatted as CSV.

## Compatibility

**Fortinet FortiMail** version 7.2.2

## Scaling and Performance

To ensure optimal performance in high-volume environments, consider the following:
- **Transport/Collection Considerations:** When collecting logs via Syslog, users can choose between TCP and UDP protocols. TCP offers reliable, ordered delivery, ensuring all log data arrives, which is crucial for auditing and security monitoring. UDP provides faster, connectionless delivery, suitable for high-volume, less critical logs where some loss is acceptable for performance gains. For file-based collection, Filebeat efficiently monitors log files, handling rotation and ensuring all entries are processed.
- **Data Volume Management:** To manage high data volumes, it is recommended to configure the FortiMail device to only forward necessary log types and severity levels. By selecting `Notice` or `Information` levels and enabling only the specific log categories (History, System Event, Mail Event, Antispam, Antivirus, Encryption) required for monitoring, you can reduce the amount of data sent to the Elastic Agent, thereby minimizing processing overhead on both the FortiMail and the agent.
- **Elastic Agent Scaling:** A single Elastic Agent can handle a significant volume of Syslog data, but for extremely high-throughput environments or geographically dispersed FortiMail instances, deploying multiple Elastic Agents is recommended. Each agent should be appropriately resourced with CPU and memory based on the expected log volume. Distribute FortiMail devices across multiple agents to balance the load, ensuring no single agent becomes a bottleneck.

# Set Up Instructions

## Vendor prerequisites

- **Administrative Access**: Full administrative access to the FortiMail web UI is required to configure logging settings.
- **Network Connectivity**: Ensure network connectivity between the FortiMail device and the server hosting the Elastic Agent. Specific ports (e.g., UDP 514, TCP 9024) must be open in any intervening firewalls.
- **CSV Format Enabled**: It is mandatory to enable the CSV format option in the FortiMail logging configuration for proper parsing by the integration.
- **Elastic Agent IP and Port**: The IP address of the Elastic Agent host and the specific port it is configured to listen on for Syslog messages must be known prior to configuration.

## Elastic prerequisites

- **Elastic Agent**: An Elastic Agent must be installed and enrolled in Fleet.
- **Network Connectivity**: The Elastic Agent host must be reachable from the FortiMail device over the configured Syslog protocol (TCP or UDP) and port.

## Vendor set up steps

### For Syslog (TCP/UDP) Collection:

1.  Log in to the FortiMail web UI.
2.  Navigate to **Log & Report > Log Setting > Remote**.
3.  Click **New** to create a new remote logging profile.
4.  In the configuration dialog, check the **Enable** box to activate the profile.
5.  Configure the following settings for the syslog server:
    *   **Name**: Enter a descriptive name for the logging target, such as `elastic-agent-syslog`.
    *   **Server name/IP**: Enter the IP address of the server where the Elastic Agent is running.
    *   **Port**: Enter the port number that the Elastic Agent is configured to listen on for syslog messages (e.g., UDP 9024 for UDP, TCP 9024 for TCP).
    *   **Level**: Select the minimum severity level of logs to be sent. A common starting point is `Notice` or `Information`.
    *   **Facility**: Choose a facility identifier to distinguish FortiMail logs, for example, `local7`. This must match what is expected by the agent's configuration.
    *   **CSV format**: **This is a mandatory step.** Enable this option to ensure logs are sent in the comma-separated value (CSV) format required for parsing.
    *   **Log protocol**: Select **Syslog**.
6.  In the **Logging Policy Configuration** section at the bottom of the dialog, select the checkboxes for all the log types you wish to collect. This includes `History`, `System Event`, `Mail Event`, `Antispam`, `Antivirus`, and `Encryption`.
7.  Click **Create** to save the remote logging profile. FortiMail will begin forwarding logs that match your configuration to the specified Elastic Agent.

### Vendor Set up Resources

- [FortiMail Administration Guide: Configuring Syslog](https://docs.fortinet.com/document/fortimail/7.2.2/administration-guide/332364) - This guide provides detailed instructions on how to configure syslog settings on your FortiMail device.
- [FortiMail Administration Guide: About FortiMail Logging](https://docs.fortinet.com/document/fortimail/7.2.2/administration-guide/435158/about-fortimail-logging) - This resource explains the different types of logs generated by FortiMail and their significance.

## Kibana set up steps

1. In Kibana, navigate to **Integrations** > **Fortinet FortiMail**.
2. Click **Add Fortinet FortiMail**.
3. Follow the prompts to add the integration to an existing Elastic Agent policy or create a new one.
4. Configure the input types based on your FortiMail setup:

### Collecting logs from Fortinet FortiMail instances via filestream input.
1. Select the **Collect Fortinet FortiMail logs via Filestream input** input type.
2. Configure the following fields:
   - **Paths**: A list of glob-based paths that will be crawled and fetched.
   - **Timezone Offset**: By default, datetimes in the logs will be interpreted as relative to the timezone configured in the host where the agent is running. If ingesting logs from a host on a different timezone, use this field to set the timezone offset so that datetimes are correctly parsed. Acceptable timezone formats are: a canonical ID (e.g. "Europe/Amsterdam") or an HH:mm differential (e.g. "-05:00"). Default: `local`.
   - **Preserve original event**: Preserves a raw copy of the original event, added to the field `event.original`. Default: `False`.
   - **Tags**: Default: `['forwarded', 'fortinet_fortimail-log']`.
   - **Preserve duplicate custom fields**: Preserve fortinet_fortimail.log fields that were copied to Elastic Common Schema (ECS) fields. Default: `False`.
   - **Processors**: Processors are used to reduce the number of fields in the exported event or to enhance the event with metadata. This executes in the agent before the logs are parsed. See [Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details.
3. Save and deploy the integration.

### Collecting logs from Fortinet FortiMail instances via tcp input.
1. Select the **Collect Fortinet FortiMail logs via TCP input** input type.
2. Configure the following fields:
   - **Listen Address**: The bind address to listen for TCP connections. Set to `0.0.0.0` to bind to all available interfaces. Default: `localhost`.
   - **Listen Port**: The TCP port number to listen on. Default: `9024`.
   - **Preserve original event**: Preserves a raw copy of the original event, added to the field `event.original`. Default: `False`.
   - **Custom TCP Options**: Specify custom configuration options for the TCP input. Default: `framing: rfc6587 #max_message_size: 50KiB #max_connections: 1 #line_delimiter: "\n"`.
   - **SSL Configuration**: SSL configuration options. See [documentation](https://www.elastic.co/guide/en/beats/filebeat/current/configuration-ssl.html#ssl-common-config) for details. Default: `#certificate_authorities: #  - | #    -----BEGIN CERTIFICATE----- #    MIIDCjCCAfKgAwIBAgITJ706Mu2wJlKckpIvkWxEHvEyijANBgkqhkiG9w0BAQsF #    ADAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwIBcNMTkwNzIyMTkyOTA0WhgPMjExOTA2 #    MjgxOTI5MDRaMBQxEjAQBgN…`.
   - **Timezone Offset**: By default, datetimes in the logs will be interpreted as relative to the timezone configured in the host where the agent is running. If ingesting logs from a host on a different timezone, use this field to set the timezone offset so that datetimes are correctly parsed. Acceptable timezone formats are: a canonical ID (e.g. "Europe/Amsterdam") or an HH:mm differential (e.g. "-05:00"). Default: `local`.
   - **Tags**: Default: `['forwarded', 'fortinet_fortimail-log']`.
   - **Preserve duplicate custom fields**: Preserve fortinet_fortimail.log fields that were copied to Elastic Common Schema (ECS) fields. Default: `False`.
   - **Processors**: Processors are used to reduce the number of fields in the exported event or to enhance the event with metadata. This executes in the agent before the logs are parsed. See [Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details.
3. Save and deploy the integration.

### Collecting logs from Fortinet FortiMail instances via udp input.
1. Select the **Collect Fortinet FortiMail logs via UDP input** input type.
2. Configure the following fields:
   - **Listen Address**: The bind address to listen for UDP connections. Set to `0.0.0.0` to bind to all available interfaces. Default: `localhost`.
   - **Listen Port**: The UDP port number to listen on. Default: `9024`.
   - **Timezone Offset**: By default, datetimes in the logs will be interpreted as relative to the timezone configured in the host where the agent is running. If ingesting logs from a host on a different timezone, use this field to set the timezone offset so that datetimes are correctly parsed. Acceptable timezone formats are: a canonical ID (e.g. "Europe/Amsterdam") or an HH:mm differential (e.g. "-05:00"). Default: `local`.
   - **Preserve original event**: Preserves a raw copy of the original event, added to the field `event.original`. Default: `False`.
   - **Custom UDP Options**: Specify custom configuration options for the UDP input. Default: `#max_message_size: 50KiB #timeout: 300s`.
   - **Tags**: Default: `['forwarded', 'fortinet_fortimail-log']`.
   - **Preserve duplicate custom fields**: Preserve fortinet_fortimail.log fields that were copied to Elastic Common Schema (ECS) fields. Default: `False`.
   - **Processors**: Processors are used to reduce the number of fields in the exported event or to enhance the event with metadata. This executes in the agent before the logs are parsed. See [Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details.
3. Save and deploy the integration.

# Validation Steps

After configuration is complete, follow these steps to verify data is flowing correctly from Fortinet FortiMail to the Elastic Stack.

### 1. Trigger Data Flow on Fortinet FortiMail:
1.  **Send a test email**: Send an email through the FortiMail unit from an external or internal source. This should generate `History` and `Mail Event` logs.
2.  **Login to FortiMail UI**: Log in and out of the FortiMail web administration interface. This will generate `System Event` logs.
3.  **Trigger Antispam/Antivirus scan**: Configure a test email to intentionally trigger an antispam or antivirus rule, if possible, to generate `Antispam` or `Antivirus` logs.
4.  **Modify a configuration setting**: Make a minor change to a non-critical system setting (e.g., change a description) and save it. This should generate a `System Event` log indicating a configuration change.

### 2. Check Data in Kibana:
1. Navigate to **Analytics > Discover**.
2. Select the `logs-*` data view or the specific integration data view.
3. Enter the following KQL filter: `data_stream.dataset : "fortinet_fortimail.log"`
4. Verify logs appear in the results. Expand a log entry and confirm these fields are populated:
   - `event.dataset` (should be `fortinet_fortimail.log`)
   - `source.ip` and/or `destination.ip` (for email-related events)
   - `event.action` or `event.outcome` (e.g., "accept", "reject", "block")
   - `fortinet_fortimail.log.type` (e.g., "History", "System", "Mail", "Antispam", "Antivirus", "Encryption")
   - `message` (containing the raw log payload)
5. Navigate to **Analytics > Dashboards** and search for "Fortinet FortiMail" to view pre-built visualizations.

# Troubleshooting

## Common Configuration Issues

- **CSV Format Not Enabled**: If logs are not being parsed correctly or fields appear unorganized, the FortiMail device might not be sending logs in CSV format.
  - **Solution**: Log in to the FortiMail web UI, navigate to **Log & Report > Log Setting > Remote**, edit the logging profile for the Elastic Agent, and ensure the **CSV format** option is checked.
- **Incorrect Syslog Server IP or Port**: If no logs are reaching the Elastic Agent, verify the Syslog server IP and port configured on FortiMail.
  - **Solution**: Double-check the **Server name/IP** and **Port** settings in the FortiMail remote logging profile against the `listen_address` and `listen_port` configured in the Elastic Agent's Fortinet FortiMail integration policy.
- **Firewall Blocking Syslog Traffic**: Network firewalls between the FortiMail and the Elastic Agent host can block Syslog traffic.
  - **Solution**: Ensure that the configured Syslog port (e.g., UDP 9024 or TCP 9024) is open bi-directionally on all firewalls between the FortiMail device and the Elastic Agent host. You can use tools like `netcat` or `telnet` to test connectivity from the FortiMail to the Elastic Agent host on the specified port.
- **Facility/Level Mismatch**: Logs might not be forwarded if the FortiMail's logging level or facility code does not match the Elastic Agent's expectations, although the Elastic Agent typically accepts all.
  - **Solution**: For troubleshooting, set the FortiMail's logging **Level** to `Debug` or `Information` and ensure all relevant log types are selected in the **Logging Policy Configuration** section of the remote logging profile.

## Ingestion Errors

- **Parsing Failures due to Malformed CSV**: If the `error.message` field in Kibana shows parsing errors or events are dropped, it indicates that the logs received are not in the expected CSV format, or there are unexpected deviations in the CSV structure.
  - **Solution**: Verify that FortiMail's **CSV format** option is explicitly enabled as a mandatory step. Check the FortiMail configuration for any custom log format settings that might override the standard CSV. Review the raw `message` field in Kibana for problematic events to identify discrepancies with the expected CSV structure.

## Vendor Resources

- [Fortinet FortiMail Product Page](https://www.fortinet.com/products/email-security) - Overview of Fortinet FortiMail's capabilities and features.
- [About FortiMail logging](https://docs.fortinet.com/document/fortimail/7.2.2/administration-guide/435158/about-fortimail-logging) - Detailed information on FortiMail's logging features and event types.

# Documentation sites

- [FortiMail Administration Guide: About Logging](https://docs.fortinet.com/document/fortimail/7.2.2/administration-guide/435158/about-fortimail-logging)
- [FortiMail Administration Guide: Configuring Syslog](https://docs.fortinet.com/document/fortimail/7.2.2/administration-guide/332364/configuring-logging#logging_2063907032_1949484)