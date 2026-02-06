# Common Event Format (CEF) Integration for Elastic

> **Note**: This documentation was generated using AI and should be reviewed for accuracy.

## Overview

The Common Event Format (CEF) integration for Elastic enables you to collect and parse logs from any device or application that supports the CEF standard. CEF is a common log format used by many security vendors to ensure interoperability between different security systems. By using this integration, you'll gain visibility into firewall activity, audit policy compliance, and network issues across your infrastructure.

This integration facilitates:
- Centralized security monitoring: You can ingest CEF-formatted audit and security logs from diverse security devices like firewalls and intrusion prevention systems into a unified platform for real-time threat detection and incident response.
- Compliance and auditing: You'll be able to collect and retain detailed CEF logs from network devices to meet regulatory compliance requirements and facilitate security audits.
- Enhanced threat intelligence: You can leverage the structured nature of CEF data, enriched with Elastic Common Schema (ECS) fields, to correlate events from different sources and identify attack patterns.
- Operational visibility: You'll gain insights into network traffic, application usage, and system events, which helps in monitoring network health and troubleshooting connectivity issues.

### Compatibility

This integration is compatible with any device or application capable of outputting logs in the Common Event Format. It's been specifically tested with the following:
- Forcepoint NGFW Security Management Center (SMC) version 6.6.1.
- Check Point devices using Log Exporter for forwarding logs in CEF format.

This integration is compatible with Elastic Stack version 8.11.0 or higher.

### How it works

This integration collects logs by receiving or reading CEF-formatted data. You can configure the Elastic Agent to collect data in the following ways:
- Network (UDP): The agent acts as a syslog server, listening for CEF logs sent over UDP.
- Network (TCP): The agent listens for CEF logs sent over a reliable TCP connection.
- Log file: The agent reads CEF logs directly from local files on the host system.

Once the logs are ingested, the integration automatically parses the CEF header and the extension fields for the `cef.log` data stream. It maps these fields to the Elastic Common Schema (ECS), allowing you to search and analyze the data consistently alongside logs from other sources.

## What data does this integration collect?

The Common Event Format (CEF) integration lets you collect log messages from several sources:
*   `logfile` logs: You'll gather CEF logs from specified local file paths, which lets you ingest security and audit events recorded by various applications and devices.
*   `udp` logs: You can collect CEF logs sent over UDP, which is a common way network devices forward security events to a syslog host.
*   `tcp` logs: This receives CEF logs transmitted using TCP, giving you a reliable transport mechanism for security events from your sources to the Elastic Agent.

### Supported use cases

You'll be able to use this integration for several security and observability workflows:
*   Security information and event management (SIEM): You'll centralize security logs from diverse vendors that use the CEF standard, like firewalls and intrusion detection systems, into Elastic Security.
*   Compliance monitoring: You can maintain a searchable archive of security events to satisfy your regulatory and internal auditing requirements.
*   Unified data analysis: It's easy to normalize vendor-specific log formats into the Elastic Common Schema (ECS), so you can correlate CEF data with other observability data streams.
*   Proactive threat hunting: You'll search and visualize event data in Kibana to identify patterns and potential security incidents across your infrastructure.

## What do I need to use this integration?

Before you can collect logs using this integration, you must have the following:

- An Elastic Agent installed and enrolled in Fleet and connected to your Elastic Stack instance.
- Network access for the Elastic Agent host to communicate with your Elasticsearch cluster and Kibana instance.
- Network reachability between your source devices (such as Forcepoint or Check Point) and the Elastic Agent host on the configured syslog ports.
- Administrative access to your Forcepoint Security Management Center (SMC) or Check Point SmartConsole to configure log forwarding rules and exporter objects.
- Appropriate firewall rules to ensure the Elastic Agent's listening host and port (for example, `syslog_host: <your-ip>` and `syslog_port: <your-port>`) are reachable from your Forcepoint Log Server or Check Point Management Server.
- Source devices configured to export logs in the Common Event Format (CEF).
- For Forcepoint, the Log Server within SMC configured to forward logs.
- For Check Point, the Log Exporter feature configured and assigned to the Management or Log Server.
- For Forcepoint NGFW, "Connection Closing: Log Accounting Information" enabled in your access policies to include connection-related byte counts.
- If you use the TCP input with SSL enabled, a valid certificate and private key must be available on the Elastic Agent host.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the syslog or log file receiver and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Set up steps in Common Event Format (CEF)

You can configure various third-party systems to send data to Elastic in `CEF` format.

#### Forcepoint NGFW Security Management Center (SMC)

To configure Forcepoint SMC to forward logs, perform the following:
1.  Log in to the Forcepoint Security Management Center.
2.  Navigate to the **Management Server properties** and select the **Audit Forwarding** tab.
3.  Configure a new forwarding rule: Specify the IP address or FQDN of the Elastic Agent host, the port (for example, `9003` for `UDP` or `9004` for `TCP`), and select the protocol (`UDP` or `TCP`) that the Elastic Agent is configured to listen on.
4.  Access the Management Server's file system and open the configuration file located at `<installation directory>/data/SGConfiguration.txt`.
5.  Add the following parameter to the `SGConfiguration.txt` file to enable custom `CEF` field configuration: `CEF_ADDITIONAL_FIELDS_CONF_FILE=<path_to_your_custom_cef_config_file>` (for example, `/opt/Forcepoint/SMC/data/cef_audit_fields.txt`).
6.  Create the custom `CEF` configuration file at the path specified in the previous step (for example, `cef_audit_fields.txt`). In this file, define the specific audit log fields you wish to export in `CEF` format. Refer to `<installation_directory>/data/fields/datatypes/audit_datatype.xml` for a list of available fields.
7.  Save the `SGConfiguration.txt` file and your custom `CEF` configuration file.
8.  Restart the Management Server service for the changes to take effect and begin forwarding logs.

#### Check Point Log Exporter

To configure Check Point to export logs in `CEF` format, perform the following:
1.  Log in to the Check Point SmartConsole.
2.  Create a new Log Exporter object by navigating to **Objects > More object types > Server > Log Exporter/SIEM**.
3.  Provide a descriptive name for the new object, such as `elastic-agent-cef`.
4.  On the **General** page of the Log Exporter object:
    *   Set **Export Configuration** to **Enabled**.
    *   For **Target Server**, enter the IP address or FQDN of the server running the Elastic Agent.
    *   For **Target Port**, specify the port number the Elastic Agent is listening on for syslog messages (for example, `9003` for `UDP` or `9004` for `TCP`).
    *   Select the **Protocol** (`UDP` or `TCP`) to match your Elastic Agent's input configuration.
5.  On the **Data Manipulation** page, set the **Format** dropdown list to **Common Event Format (CEF)**.
6.  Click **OK** to save the newly configured Log Exporter object.
7.  Next, navigate to **Gateways & Servers**.
8.  Open the properties for your **Management Server** or the specific **Dedicated Log Server** responsible for forwarding logs.
9.  From the navigation tree, select **Logs > Export**.
10. Click the `+` icon and select the `elastic-agent-cef` Log Exporter object you created earlier. Click **OK**.
11. To ensure all configuration changes are applied, install the database. From the top menu, click **Menu > Install database**.
12. Select all objects in the confirmation window and click **Install**.

#### Vendor resources

Refer to these resources for more information on vendor configuration:
- [How to Configure SMC Audit Log Forwarding - Forcepoint](https://support.forcepoint.com/s/article/How-to-configure-Security-Management-Center-audit-log-forwarding)
- [Log Exporter - Check Point R81.20 Logging and Monitoring Administration Guide](https://sc1.checkpoint.com/documents/R81.20/WebAdminGuides/EN/CP_R81.20_LoggingAndMonitoring_AdminGuide/Content/Topics-LMG/Log-Exporter.htm)
- [Configuring Log Exporter in SmartConsole - Check Point R81.20 Guide](https://sc1.checkpoint.com/documents/R81.20/WebAdminGuides/EN/CP_R81.20_LoggingAndMonitoring_AdminGuide/Content/Topics-LMG/Log-Exporter-Configuration-in-SmartConsole.htm)
- [sk122323 - Log Exporter - Check Point Log Export](https://support.checkpoint.com/results/sk/sk122323)

### Set up steps in Kibana

To set up the `CEF` integration in Kibana, follow these steps:
1.  In Kibana, navigate to **Management > Integrations**.
2.  Search for `CEF` and click on the **Common Event Format (CEF)** integration.
3.  Click **Add Common Event Format (CEF)**.
4.  Follow the prompts to add the integration to an existing Elastic Agent policy or create a new one.
5.  After adding the integration, you'll be directed to the integration's settings page. Here, you can select and configure the specific input types based on your `CEF` log source.

Choose one or more of the following input types:

#### Log file input configuration

Use this input to collect logs directly from log files on the host where the Elastic Agent is running.
1. Within the integration settings, click **Add input** and select **Collecting application logs from CEF instances (input: logfile)**.
2. Configure the following fields:
   - **Paths**: List of paths from which to read log files. Default: `['/var/log/cef.log']`.
   - **Ignore Empty Values**: Ignore `CEF` fields that are empty. The alternative behavior is to treat an empty field as an error. Default: `false`.
   - **Dataset name**: Dataset to write data to. Default: `cef.log`.
   - **Preserve original event**: Preserves a raw copy of the original event, added to the field `event.original`. Default: `false`.
   - **CEF Timezone**: IANA time zone or time offset (for example, `+0200`) to use when interpreting timestamps without a time zone in the `CEF` message.
   - **Tags**: A list of tags to include in events. Including `forwarded` indicates that the events didn't originate on this host and causes `host.name` to not be added to events. Default: `['cef', 'forwarded']`.
   - **Pre-Processors**: Pre-processors are run before the `CEF` message is decoded. See the [processors documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details.
   - **Processors**: Processors are used to reduce fields or enhance the event with metadata. This executes in the agent after the logs are parsed.
3. Click **Save and deploy**.

#### UDP input configuration

Use this input to collect logs over a `UDP` socket.
1. Within the integration settings, click **Add input** and select **Collecting application logs from CEF instances (input: udp)**.
2. Configure the following fields:
   - **Syslog Host**: The interface to listen to `UDP` based syslog traffic. Set to `0.0.0.0` to bind to all available interfaces. Default: `localhost`.
   - **Syslog Port**: The `UDP` port to listen for syslog traffic. Default: `9003`.
   - **Dataset name**: Dataset to write data to. Default: `cef.log`.
   - **Preserve original event**: Preserves a raw copy of the original event in `event.original`. Default: `false`.
   - **Ignore Empty Values**: Ignore `CEF` fields that are empty. Default: `false`.
   - **CEF Timezone**: IANA time zone or time offset (for example, `+0200`) to use when interpreting timestamps without a time zone.
   - **Tags**: A list of tags to include in events. Default: `['cef', 'forwarded']`.
   - **Custom UDP Options**: Specify custom configuration options. For example, `read_buffer: 100MiB`, `max_message_size: 50KiB`, and `timeout: 300s`.
3. Click **Save and deploy**.

#### TCP input configuration

Use this input to collect logs over a `TCP` socket.
1. Within the integration settings, click **Add input** and select **Collecting application logs from CEF instances (input: tcp)**.
2. Configure the following fields:
   - **Syslog Host**: The interface to listen to `TCP` based syslog traffic. Set to `0.0.0.0` to bind to all available interfaces. Default: `localhost`.
   - **Syslog Port**: The `TCP` port to listen for syslog traffic. Default: `9004`.
   - **Dataset name**: Dataset to write data to. Default: `cef.log`.
   - **Preserve original event**: Preserves a raw copy of the original event in `event.original`. Default: `false`.
   - **Ignore Empty Values**: Ignore `CEF` fields that are empty. Default: `false`.
   - **CEF Timezone**: IANA time zone or time offset (for example, `+0200`) to use when interpreting timestamps without a time zone.
   - **Tags**: A list of tags to include in events. Default: `['cef', 'forwarded']`.
   - **SSL Configuration**: SSL configuration options for encrypted communication. See the [SSL documentation](https://www.elastic.co/guide/en/beats/filebeat/current/configuration-ssl.html#ssl-common-config) for details.
   - **Custom TCP Options**: Specify custom configuration options for the `TCP` input. For example, `max_connections: 1`, `framing: delimiter`, and `line_delimiter: "\n"`.
3. Click **Save and deploy**.

### Validation

After configuration is complete, perform these steps to verify data is flowing correctly.

#### Verify Elastic Agent status

Ensure the Elastic Agent is healthy and connected to Fleet:
1. In Kibana, navigate to **Management > Fleet > Agents**.
2. Search for the agent host you configured.
3. Verify the status is **Healthy**.

#### Trigger data flow

Generate test logs depending on your configured source:
- **For Forcepoint NGFW SMC**: Log in to the SMC, make a small change to a policy or rule (for example, enable/disable a rule, then re-enable), and install the policy to generate configuration change logs. Alternatively, browse several websites from a client behind the Forcepoint firewall to generate web filtering or connection logs.
- **For Check Point devices**: Log in to SmartConsole and install policy on a gateway. Initiate network traffic through a Check Point gateway (for example, browse to a blocked website) to trigger log generation via Log Exporter.
- **For log file input**: Manually append a test `CEF` message to the configured log file path:
  ```bash
  # Manually append a test message to the log file (replace path with your actual path)
  echo "CEF:0|TestVendor|TestProduct|1.0|100|Test Event|1|msg=This is a test event" >> /var/log/cef.log
  ```

#### Check data in Kibana

To confirm data is flowing:
1.  Navigate to **Analytics > Discover**.
2.  Select the `logs-*` data view.
3.  Enter the following filter: `data_stream.dataset : "cef.log"`.
4.  Verify logs appear in the results. Expand a log entry and confirm these fields are populated:
    -   `event.dataset` (should be `cef.log`)
    -   `source.ip` and/or `destination.ip`
    -   `event.action` or `event.outcome`
    -   `cef.name`
    -   `cef.deviceProduct`
    -   `message` (containing the raw log payload)
5.  Navigate to **Analytics > Dashboards** and search for "CEF" to view the pre-built visualizations.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Common configuration issues

Use the following information to resolve common issues you might encounter while using this integration:

- No data is being collected:
    - Verify that the Elastic Agent is listening on the expected interface and port. Use `netstat -tulnp` on the Agent host to confirm it's bound to the correct `syslog_host` and `syslog_port` (for example, `9003` or `9004`).
    - Check network connectivity between your vendor device and the Elastic Agent host using `ping`.
    - Ensure firewall rules or network Access Control Lists (ACLs) are not blocking traffic on the configured syslog ports.
    - Use a tool like `tcpdump` or `wireshark` on the Elastic Agent host to confirm that packets are reaching the network interface.
- CEF parsing errors or malformed messages:
    - If logs appear in Kibana but are not correctly parsed, inspect the raw `event.original` field. Some vendors send non-standard headers or malformed extensions.
    - Use the `Pre-Processors` setting in the integration configuration to apply ingest processors like `dissect`, `grok`, or `gsub` to clean up the message before it reaches the CEF decoder.
- Empty CEF fields causing ingestion failures:
    - If your logs contain empty extension fields that cause parsing errors, ensure the `Ignore Empty Values` setting is set to `true` in the integration configuration.
- Incorrect event timestamps:
    - If the `@timestamp` field doesn't match the event time, check if the CEF message includes a timezone. If it doesn't, you must configure the correct `CEF Timezone` (for example, `+0200` or an IANA name like `America/New_York`) in the integration settings.
- TCP framing issues:
    - If you're using the TCP input, ensure the `framing` and `line_delimiter` settings in the integration's custom TCP options match the format used by your log source. Mismatched framing can result in merged logs or parsing failures.
- Check Point Log Exporter instance is not running:
    - On the Check Point CLI, run `cp_log_export status name <exporter_name>` to verify the status. If it's stopped, start it using `cp_log_export start name <exporter_name>`.
    - Verify the configuration with `cp_log_export show name <exporter_name>` and confirm the `target-server` and `target-port` match your Agent's settings.
- Incorrect syslog host or port configuration:
    - Double-check the `syslog_host` and `syslog_port` settings in the Elastic Agent integration configuration. Ensure these match the destination IP and port configured on the vendor device, such as Forcepoint SMC or Check Point Log Exporter.

### Vendor resources

For more information about CEF formatting and specific vendor configurations, refer to the following resources:

- [How to configure Security Management Center audit log forwarding - Forcepoint](https://support.forcepoint.com/s/article/How-to-configure-Security-Management-Center-audit-log-forwarding)
- [Log Exporter - Check Point R81.20 Logging and Monitoring Administration Guide](https://sc1.checkpoint.com/documents/R81.20/WebAdminGuides/EN/CP_R81.20_LoggingAndMonitoring_AdminGuide/Content/Topics-LMG/Log-Exporter.htm)
- [Configuring Log Exporter in SmartConsole - Check Point R81.20 Guide](https://sc1.checkpoint.com/documents/R81.20/WebAdminGuides/EN/CP_R81.20_LoggingAndMonitoring_AdminGuide/Content/Topics-LMG/Log-Exporter-Configuration-in-SmartConsole.htm)
- [sk122323 - Log Exporter - Check Point Log Export](https://support.checkpoint.com/results/sk/sk122323)
- [Log Exporter CEF Field Mappings - Check Point Community](https://community.checkpoint.com/t5/Management/Log-Exporter-CEF-Field-Mappings/td-p/41060)

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

### Transport and collection considerations

To ensure you get optimal performance in high-volume environments, consider these factors when choosing a protocol for network-based collection:

- UDP offers high-speed, connectionless transmission. This is suitable for environments where you can accept occasional packet loss and need high throughput.
- TCP provides reliable, ordered delivery. This ensures all log messages are received, which is important for audit and compliance, though it might increase latency and overhead.
- For logfile inputs, ensure you've configured proper log rotation on the source system to prevent large file sizes and maintain efficient read performance by the Elastic Agent.

You can tune the following settings for your specific network conditions and load:

- UDP options: `read_buffer`, `max_message_size`, and `timeout`.
- TCP options: `max_connections`, `framing`, and `line_delimiter`.

### Data volume management

You can manage data volume more efficiently by configuring your source systems to filter the events they forward:

- In Forcepoint SMC, define specific audit forwarding rules.
- In Check Point Log Exporter, select only the relevant log types to send necessary security and operational events.

Filtering at the source reduces the load on both your source device and the Elastic Stack. High data volume without filtering can slow down the source system and increase resource use on the Elastic Agent.

### Elastic Agent scaling

A single Elastic Agent can handle a significant volume of `log` logs. However, for high-throughput environments or when you collect from many high-volume sources, consider deploying multiple Elastic Agents. To scale your ingestion horizontally, you can take these steps:

- Distribute log forwarding across several Agents, with each Agent listening on different ports or interfaces.
- Size the resources (CPU, memory, and disk I/O) for the Elastic Agent host based on your expected peak log volume and the complexity of any processors you've applied.
- Place your Agents strategically close to the log sources to minimize network latency.

## Reference

### Inputs used

{{ inputDocs }}

### Data streams

The Common Event Format (CEF) integration includes the `log` data stream.

#### `log`

The `log` data stream collects events from various security devices and applications that support the Common Event Format (CEF). This data stream is designed to handle logs from many different vendors by mapping standard CEF fields to the Elastic Common Schema (ECS).

The `log` data stream provides events from CEF-compatible sources of the following types:
- Security alerts and intrusion detection events
- Network traffic and firewall logs
- System status and health information
- User authentication and access control logs

##### `log` fields

{{ fields "log" }}

##### `log` sample event

{{ event "log" }}

### Vendor documentation links

For more information about CEF field mappings and configuration for specific vendors, refer to the following resources:
- [Log Exporter CEF Field Mappings](https://community.checkpoint.com:443/t5/Management/Log-Exporter-CEF-Field-Mappings/td-p/41060) — Provides detailed field mappings for Check Point's CEF extension fields.
- Forcepoint SMC Configuration Guide (KB 15002) — Forcepoint knowledge base article offering guidance on configuring the Security Management Center.
