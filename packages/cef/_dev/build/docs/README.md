# Common Event Format (CEF) Integration for Elastic

> **Note**: This documentation was generated using AI and should be reviewed for accuracy.

## Overview

The Common Event Format (CEF) integration for Elastic enables you to collect and parse logs from any device or application that supports the CEF standard. CEF is a common log format used by many security vendors to ensure interoperability between different security systems. By using this integration, you'll gain visibility into firewall activity and audit policy compliance, and you can troubleshoot network issues across your infrastructure.

This integration facilitates:
- Centralized security monitoring: You can ingest CEF-formatted audit and security logs from diverse security devices like firewalls and intrusion prevention systems into a unified platform.
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

The Common Event Format (CEF) integration collects log messages of the following types:
*   `logfile` logs: Gathers CEF logs from specified local file paths, which allows you to ingest security and audit events recorded by various applications and devices.
*   `udp` logs: Collects CEF logs sent over UDP, which is commonly used by network devices to forward security events to a syslog host.
*   `tcp` logs: Receives CEF logs transmitted via TCP, providing a reliable transport mechanism for security events from your sources to the Elastic Agent.

### Supported use cases

You can use this integration to enable several security and observability workflows:
*   Security information and event management (SIEM): Centralize security logs from diverse vendors that use the CEF standard, such as firewalls and intrusion detection systems, into Elastic Security.
*   Compliance monitoring: Maintain a searchable archive of security events to satisfy regulatory and internal auditing requirements.
*   Unified data analysis: Normalize vendor-specific log formats into the Elastic Common Schema (ECS), which lets you correlate CEF data with other observability data streams.
*   Proactive threat hunting: Search and visualize event data in Kibana to identify patterns and potential security incidents across your infrastructure.

## What do I need to use this integration?

Before you can collect logs using this integration, you must have the following:

- You must install and enroll an Elastic Agent in Fleet and connect it to your Elastic Stack instance.
- Your Elastic Agent host needs network access to communicate with your Elasticsearch cluster and Kibana instance. It also needs to be reachable by your vendor devices (such as Forcepoint or Check Point) on the configured syslog ports.
- You need full administrative access to your Forcepoint Security Management Center (SMC) or Check Point SmartConsole to configure log forwarding rules and exporter objects.
- Ensure your Elastic Agent's listening host and port (for example, `syslog_host: 0.0.0.0`, `syslog_port: 9003` for UDP, or `9004` for TCP) are reachable from your Forcepoint Log Server or Check Point Management Server. You should also ensure you have appropriate firewall rules in place.
- Configure your source devices to export logs in the Common Event Format (CEF).
- If you use Forcepoint, you must configure the Log Server within SMC to forward logs.
- If you use Check Point, you must configure the Log Exporter feature and assign it to the Management/Log Server.
- To include connection-related byte counts for Forcepoint, ensure you enable "Connection Closing: Log Accounting Information" in your access policies on the Forcepoint NGFW.

## How do I deploy this integration?

### Agent-based deployment

You'll need to install Elastic Agent. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

You use Elastic Agent to stream data from the syslog or log file receiver and ship the data to Elastic, where the ingest pipelines process the events.

### Set up steps in Common Event Format (CEF)

You can configure various third-party systems to send data to Elastic in CEF format.

#### Forcepoint NGFW Security Management Center (SMC)

To configure Forcepoint SMC to forward logs:
1.  Log in to the Forcepoint Security Management Center.
2.  Navigate to the **Management Server properties** and select the **Audit Forwarding** tab.
3.  Configure a new forwarding rule: Specify the IP address or FQDN of the host where you installed Elastic Agent, the port (for example, `9003` for `UDP` or `9004` for `TCP`), and select the protocol (`UDP` or `TCP`) that you'll configure Elastic Agent to listen on.
4.  Access the Management Server's file system and open the configuration file located at `<installation directory>/data/SGConfiguration.txt`.
5.  Add this parameter to the `SGConfiguration.txt` file to enable custom CEF field configuration: `CEF_ADDITIONAL_FIELDS_CONF_FILE=<path_to_your_custom_cef_config_file>` (for example, `/opt/Forcepoint/SMC/data/cef_audit_fields.txt`).
6.  Create the custom CEF configuration file at the path you specified. In this file, define the specific audit log fields you want to export in CEF format. You can refer to `<installation_directory>/data/fields/datatypes/audit_datatype.xml` for a list of available fields.
7.  Save the `SGConfiguration.txt` file and your custom CEF configuration file.
8.  Restart the Management Server service to apply the changes and start forwarding logs.

#### Check Point Log Exporter

To configure Check Point to export logs in CEF format:
1.  Log in to the Check Point SmartConsole.
2.  Create a new Log Exporter object by navigating to **Objects > More object types > Server > Log Exporter/SIEM**.
3.  Provide a descriptive name for the new object, such as `elastic-agent-cef`.
4.  On the **General** page of the Log Exporter object:
    *   Set **Export Configuration** to **Enabled**.
    *   For **Target Server**, enter the IP address or FQDN of the server running Elastic Agent.
    *   For **Target Port**, specify the port number you'll configure Elastic Agent to listen on for syslog messages (for example, `9003` for `UDP` or `9004` for `TCP`).
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

You can find more information in the following vendor documentation:
- [How to Configure SMC Audit Log Forwarding - Forcepoint](https://support.forcepoint.com/s/article/How-to-configure-Security-Management-Center-audit-log-forwarding)
- [Log Exporter - Check Point R81.20 Logging and Monitoring Administration Guide](https://sc1.checkpoint.com/documents/R81.20/WebAdminGuides/EN/CP_R81.20_LoggingAndMonitoring_AdminGuide/Content/Topics-LMG/Log-Exporter.htm)
- [Configuring Log Exporter in SmartConsole - Check Point R81.20 Guide](https://sc1.checkpoint.com/documents/R81.20/WebAdminGuides/EN/CP_R81.20_LoggingAndMonitoring_AdminGuide/Content/Topics-LMG/Log-Exporter-Configuration-in-SmartConsole.htm)
- [sk122323 - Log Exporter - Check Point Log Export](https://support.checkpoint.com/results/sk/sk122323)

### Set up steps in Kibana

You'll need to add the integration to an Elastic Agent policy.

1.  In Kibana, navigate to **Management > Integrations**.
2.  Search for `CEF` and select the **Common Event Format (CEF)** integration.
3.  Click **Add Common Event Format (CEF)**.
4.  Follow the prompts to add the integration to an existing Elastic Agent policy or create a new one.
5.  After adding the integration, configure the specific input types based on your CEF log source. You can choose one or more of the following:

#### Log file input configuration

Use this input to collect logs directly from log files on the host where the Elastic Agent is running.
1. Within the integration settings, click **Add input** and select **Collecting application logs from CEF instances (input: logfile)**.
2. Configure the following settings:
   - **Paths**: List of file paths to monitor (for example, `['/var/log/cef.log']`).
   - **Ignore Empty Values**: Select this to ignore CEF fields that are empty. Otherwise, empty fields are treated as errors.
   - **Dataset name**: Specify the dataset to write data to. Default is `cef.log`.
   - **Preserve original event**: Select this to save a raw copy of the original event in the `event.original` field.
   - **CEF Timezone**: Specify an IANA time zone or offset (for example, `+0200`) to interpret timestamps that lack time zone data.
   - **Tags**: A list of tags to include in events. The `forwarded` tag indicates events did not originate on this host and prevents the addition of `host.name`.
   - **Pre-Processors**: Configure pre-processors to run before the CEF message is decoded. These can correct formatting inconsistencies. See the [processors documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details.
   - **Processors**: Use processors to reduce fields or enhance events with metadata after logs are parsed.

#### UDP input configuration

Use this input to collect logs over a `UDP` socket.
1. Within the integration settings, click **Add input** and select **Collecting application logs from CEF instances (input: udp)**.
2. Configure the following settings:
   - **Syslog Host**: The interface to listen for `UDP` syslog traffic. Set to `0.0.0.0` to bind to all available interfaces. Default is `localhost`.
   - **Syslog Port**: The `UDP` port to listen on. Default is `9003`.
   - **Dataset name**: Specify the dataset to write data to. Default is `cef.log`.
   - **Preserve original event**: Select this to save a raw copy of the original event in the `event.original` field.
   - **Ignore Empty Values**: Select this to ignore empty CEF fields.
   - **CEF Timezone**: Specify an IANA time zone or offset to interpret timestamps that lack time zone data.
   - **Custom UDP Options**: Configure advanced settings such as `read_buffer` (for example, `100MiB`), `max_message_size` (for example, `50KiB`), and `timeout` (for example, `300s`).

#### TCP input configuration

Use this input to collect logs over a `TCP` socket.
1. Within the integration settings, click **Add input** and select **Collecting application logs from CEF instances (input: tcp)**.
2. Configure the following settings:
   - **Syslog Host**: The interface to listen for `TCP` syslog traffic. Set to `0.0.0.0` to bind to all available interfaces. Default is `localhost`.
   - **Syslog Port**: The `TCP` port to listen on. Default is `9004`.
   - **Dataset name**: Specify the dataset to write data to. Default is `cef.log`.
   - **Preserve original event**: Select this to save a raw copy of the original event in the `event.original` field.
   - **Ignore Empty Values**: Select this to ignore empty CEF fields.
   - **SSL Configuration**: Configure SSL options for encrypted communication. See the [SSL documentation](https://www.elastic.co/guide/en/beats/filebeat/current/configuration-ssl.html#ssl-common-config) for details.
   - **Custom TCP Options**: Configure advanced settings such as `max_connections`, `framing` (for example, `delimiter`), and `line_delimiter`.

Click **Save and deploy** to apply the configuration to your Elastic Agent.

### Validation

You can verify the integration is working correctly by triggering data flow and checking Kibana.

#### Trigger data flow

Generate test logs depending on your configured source:
- **Forcepoint NGFW SMC**: Log in to the SMC, make a small change to a policy or rule (for example, toggle a rule), and install the policy to generate configuration change logs. You can also browse websites from a client behind the Forcepoint firewall to generate traffic logs.
- **Check Point**: Log in to SmartConsole and install the policy on a Gateway. Initiate network traffic (for example, browse to a site) through the gateway to trigger log generation via Log Exporter.
- **Log file input**: Manually append a test CEF message to your configured log file:
  ```bash
  echo "CEF:0|TestVendor|TestProduct|1.0|100|Test Event|1|msg=This is a test event" >> /var/log/cef.log
  ```

#### Check data in Kibana

To confirm data is flowing:
1.  Navigate to **Analytics > Discover**.
2.  Select the `logs-*` data view.
3.  Enter the filter `data_stream.dataset: "cef.log"` in the search bar.
4.  Verify that logs appear in the results and confirm that fields like `event.dataset`, `cef.name`, and `cef.deviceProduct` are populated.
5.  Navigate to **Analytics > Dashboards** and search for "CEF" to view the pre-built visualizations.

## Troubleshooting

For help with Elastic ingest tools, check the [common problems documentation](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Common configuration issues

You can use the following information to resolve common issues you might encounter while using this integration:

- No data is being collected:
    * Verify that the Elastic Agent is listening on the expected interface and port. Use `netstat -tulnp` on the Agent host to confirm it's bound to the correct `syslog_host` and `syslog_port` (e.g., `9003` or `9004`).
    * Check network connectivity between your vendor device and the Elastic Agent host using `ping`.
    * Ensure firewall rules or network Access Control Lists (ACLs) are not blocking traffic on the configured syslog ports.
    * Use a tool like `tcpdump` or `wireshark` on the Elastic Agent host to confirm that packets are reaching the network interface.
- CEF parsing errors or malformed messages:
    * If logs appear in Kibana but are not correctly parsed, inspect the raw `event.original` field. Some vendors send non-standard headers or malformed extensions.
    * Use the `Pre-Processors` setting in the integration configuration to apply ingest processors like `dissect`, `grok`, or `gsub` to clean up the message before it reaches the CEF decoder.
- Empty CEF fields causing ingestion failures:
    * If your logs contain empty extension fields that cause parsing errors, ensure the `Ignore Empty Values` setting is set to `true` in the integration configuration.
- Incorrect event timestamps:
    * If the `@timestamp` field doesn't match the event time, check if the CEF message includes a timezone. If it doesn't, you must configure the correct `CEF Timezone` (e.g., `+0200` or an IANA name like `America/New_York`) in the integration settings.
- TCP framing issues:
    * If you're using the TCP input, ensure the `framing` and `line_delimiter` settings in the integration's custom TCP options match the format used by your log source. Mismatched framing can result in merged logs or parsing failures.
- Check Point Log Exporter instance is not running:
    * On the Check Point CLI, run `cp_log_export status name <exporter_name>` to verify the status. If it's stopped, start it using `cp_log_export start name <exporter_name>`.
    * Verify the configuration with `cp_log_export show name <exporter_name>` and confirm the `target-server` and `target-port` match your Agent's settings.

### Vendor resources

For more information about CEF formatting and specific vendor configurations, refer to these resources:

- [How to configure Security Management Center audit log forwarding - Forcepoint](https://support.forcepoint.com/s/article/How-to-configure-Security-Management-Center-audit-log-forwarding)
- [Log Exporter - Check Point R81.20 Logging and Monitoring Administration Guide](https://sc1.checkpoint.com/documents/R81.20/WebAdminGuides/EN/CP_R81.20_LoggingAndMonitoring_AdminGuide/Content/Topics-LMG/Log-Exporter.htm)
- [Configuring Log Exporter in SmartConsole - Check Point R81.20 Guide](https://sc1.checkpoint.com/documents/R81.20/WebAdminGuides/EN/CP_R81.20_LoggingAndMonitoring_AdminGuide/Content/Topics-LMG/Log-Exporter-Configuration-in-SmartConsole.htm)
- [sk122323 - Log Exporter - Check Point Log Export](https://support.checkpoint.com/results/sk/sk122323)
- [Log Exporter CEF Field Mappings - Check Point Community](https://community.checkpoint.com:443/t5/Management/Log-Exporter-CEF-Field-Mappings/td-p/41060)

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

To ensure you get optimal performance in high-volume environments, consider the following factors:

### Transport and collection considerations
When you collect data over the network, the protocol you choose affects performance and reliability:
- UDP offers high-speed, connectionless transmission. This is suitable for environments where you can accept occasional packet loss and need high throughput.
- TCP provides reliable, ordered delivery. This ensures all log messages are received, which is important for audit and compliance, though it might increase latency and overhead.
- For logfile inputs, ensure you've configured proper log rotation on the source system to prevent large file sizes and maintain efficient read performance by the Elastic Agent.

You can tune the following settings for your specific network conditions and load:
- UDP options: `read_buffer`, `max_message_size`, and `timeout`.
- TCP options: `max_connections`, `framing`, and `line_delimiter`.

### Data volume management
You can manage data volume more efficiently by configuring your source systems to filter the events they forward. For example:
- In Forcepoint SMC, define specific audit forwarding rules.
- In Check Point Log Exporter, select only the relevant log types to send necessary security and operational events.

Filtering at the source reduces the load on both your source device and the Elastic Stack. High data volume without filtering can slow down the source system and increase resource use on the Elastic Agent.

### Elastic Agent scaling
A single Elastic Agent can handle a significant volume of CEF logs. However, for high-throughput environments or when you collect from many high-volume sources, consider deploying multiple Elastic Agents.

To scale your ingestion horizontally, you can:
- Distribute log forwarding across several Agents, with each Agent listening on different ports or interfaces.
- Size the resources (CPU, memory, and disk I/O) for the Elastic Agent host based on your expected peak log volume and the complexity of any processors you've applied.
- Place your Agents strategically close to the log sources to minimize network latency.

## Reference

### Inputs used

{{ inputDocs }}

### Data streams

The Common Event Format (CEF) integration includes the `log` data stream.

#### log

The `log` data stream collects events from various security devices and applications that support the Common Event Format (CEF). This data stream is designed to handle logs from many different vendors by mapping standard CEF fields to the Elastic Common Schema (ECS).

The `log` data stream provides events from CEF-compatible sources of the following types:
- Security alerts and intrusion detection events
- Network traffic and firewall logs
- System status and health information
- User authentication and access control logs

##### log fields

{{ fields "log" }}

##### log sample event

{{ event "log" }}

### Vendor documentation links

For more information about CEF field mappings and vendor-specific configurations, refer to the following resources:
- [Log Exporter CEF Field Mappings](https://community.checkpoint.com:443/t5/Management/Log-Exporter-CEF-Field-Mappings/td-p/41060) — Detailed field mappings for Check Point CEF extensions.
- Forcepoint SMC Configuration Guide (KB 15002) — Guidance on configuring the Forcepoint Security Management Center for CEF logging.
