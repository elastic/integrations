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

These inputs can be used with this integration:
<details>
<summary>logfile</summary>

## Setup
For more details about the logfile input settings, check the [Filebeat documentation](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-log).

### Collecting logs from logfile

To collect logs via logfile, select **Collect logs via the logfile input** and configure the following parameter:

- Paths: List of glob-based paths to crawl and fetch log files from. Supports glob patterns like
  `/var/log/*.log` or `/var/log/*/*.log` for subfolder matching. Each file found starts a
  separate harvester.
</details>
<details>
<summary>tcp</summary>

## Setup

For more details about the TCP input settings, check the [Filebeat documentation](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-tcp).

### Collecting logs from TCP

To collect logs via TCP, select **Collect logs via TCP** and configure the following parameters:

**Required Settings:**
- Host
- Port

**Common Optional Settings:**
- Max Message Size - Maximum size of incoming messages
- Max Connections - Maximum number of concurrent connections
- Timeout - How long to wait for data before closing idle connections
- Line Delimiter - Character(s) that separate log messages

## SSL/TLS Configuration

To enable encrypted connections, configure the following SSL settings:

**SSL Settings:**
- Enable SSL*- Toggle to enable SSL/TLS encryption
- Certificate - Path to the SSL certificate file (`.crt` or `.pem`)
- Certificate Key - Path to the private key file (`.key`)
- Certificate Authorities - Path to CA certificate file for client certificate validation (optional)
- Client Authentication - Require client certificates (`none`, `optional`, or `required`)
- Supported Protocols - TLS versions to support (e.g., `TLSv1.2`, `TLSv1.3`)

**Example SSL Configuration:**
```yaml
ssl.enabled: true
ssl.certificate: "/path/to/server.crt"
ssl.key: "/path/to/server.key"
ssl.certificate_authorities: ["/path/to/ca.crt"]
ssl.client_authentication: "optional"
```
</details>
<details>
<summary>udp</summary>

## Setup

For more details about the UDP input settings, check the [Filebeat documentation](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-udp).

### Collecting logs from UDP

To collect logs via UDP, select **Collect logs via UDP** and configure the following parameters:

**Required Settings:**
- Host
- Port

**Common Optional Settings:**
- Max Message Size - Maximum size of UDP packets to accept (default: 10KB, max: 64KB)
- Read Buffer - UDP socket read buffer size for handling bursts of messages
- Read Timeout - How long to wait for incoming packets before checking for shutdown
</details>


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

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cef.device.event_class_id | Unique identifier of the event type. | keyword |
| cef.device.product | Product of the device that produced the message. | keyword |
| cef.device.vendor | Vendor of the device that produced the message. | keyword |
| cef.device.version | Version of the product that produced the message. | keyword |
| cef.extensions.TrendMicroDsDetectionConfidence |  | keyword |
| cef.extensions.TrendMicroDsFileMD5 |  | keyword |
| cef.extensions.TrendMicroDsFileSHA1 |  | keyword |
| cef.extensions.TrendMicroDsFileSHA256 |  | keyword |
| cef.extensions.TrendMicroDsFrameType |  | keyword |
| cef.extensions.TrendMicroDsMalwareTarget |  | keyword |
| cef.extensions.TrendMicroDsMalwareTargetType |  | keyword |
| cef.extensions.TrendMicroDsPacketData |  | keyword |
| cef.extensions.TrendMicroDsRelevantDetectionNames |  | keyword |
| cef.extensions.TrendMicroDsTenant |  | keyword |
| cef.extensions.TrendMicroDsTenantId |  | keyword |
| cef.extensions.ad |  | flattened |
| cef.extensions.agentAddress | The IP address of the ArcSight connector that processed the event. | ip |
| cef.extensions.agentHostName | The hostname of the ArcSight connector that processed the event. | keyword |
| cef.extensions.agentId | The agent ID of the ArcSight connector that processed the event. | keyword |
| cef.extensions.agentMacAddress | The MAC address of the ArcSight connector that processed the event. | keyword |
| cef.extensions.agentReceiptTime | The time at which information about the event was received by the ArcSight connector. | date |
| cef.extensions.agentTimeZone | The agent time zone of the ArcSight connector that processed the event. | keyword |
| cef.extensions.agentType | The agent type of the ArcSight connector that processed the event. | keyword |
| cef.extensions.agentVersion | The version of the ArcSight connector that processed the event. | keyword |
| cef.extensions.agentZoneURI |  | keyword |
| cef.extensions.aggregationType |  | keyword |
| cef.extensions.applicationProtocol | Application level protocol, example values are HTTP, HTTPS, SSHv2, Telnet, POP, IMPA, IMAPS, and so on. | keyword |
| cef.extensions.assetCriticality |  | keyword |
| cef.extensions.baseEventCount | A count associated with this event. How many times was this same event observed? Count can be omitted if it is 1. | long |
| cef.extensions.bytesIn | Number of bytes transferred inbound, relative to the source to destination relationship, meaning that data was flowing from source to destination. | long |
| cef.extensions.bytesOut | Number of bytes transferred outbound relative to the source to destination relationship. For example, the byte number of data flowing from the destination to the source. | long |
| cef.extensions.categoryBehavior | Action or a behavior associated with an event. It's what is being done to the object (ArcSight). | keyword |
| cef.extensions.categoryDeviceGroup | General device group like Firewall (ArcSight). | keyword |
| cef.extensions.categoryDeviceType | Device type. Examples - Proxy, IDS, Web Server (ArcSight). | keyword |
| cef.extensions.categoryObject | Object that the event is about. For example it can be an operating sytem, database, file, etc (ArcSight). | keyword |
| cef.extensions.categoryOutcome | Outcome of the event (e.g. sucess, failure, or attempt) (ArcSight). | keyword |
| cef.extensions.categorySignificance | Characterization of the importance of the event (ArcSight). | keyword |
| cef.extensions.categoryTechnique | Technique being used (e.g. /DoS) (ArcSight). | keyword |
| cef.extensions.cp_app_risk |  | keyword |
| cef.extensions.cp_severity |  | keyword |
| cef.extensions.destinationAddress | Identifies the destination address that the event refers to in an IP network. The format is an IPv4 address. | ip |
| cef.extensions.destinationHostName | Identifies the destination that an event refers to in an IP network. The format should be a fully qualified domain name (FQDN) associated with the destination node, when a node is available. | keyword |
| cef.extensions.destinationMacAddress | Six colon-separated hexadecimal numbers. | keyword |
| cef.extensions.destinationNtDomain | Outcome of the event (e.g. sucess, failure, or attempt) (ArcSight). | keyword |
| cef.extensions.destinationPort | The valid port numbers are between 0 and 65535. | long |
| cef.extensions.destinationServiceName | The service targeted by this event. | keyword |
| cef.extensions.destinationTranslatedAddress | Identifies the translated destination that the event refers to in an IP network. | ip |
| cef.extensions.destinationTranslatedPort | Port after it was translated; for example, a firewall. Valid port numbers are 0 to 65535. | long |
| cef.extensions.destinationUserName | Identifies the destination user by name. This is the user associated with the event's destination. Email addresses are often mapped into the UserName fields. The recipient is a candidate to put into this field. | keyword |
| cef.extensions.destinationUserPrivileges | The typical values are "Administrator", "User", and "Guest". This identifies the destination user's privileges. In UNIX, for example, activity executed on the root user would be identified with destinationUser Privileges of "Administrator". | keyword |
| cef.extensions.deviceAction | Action taken by the device. | keyword |
| cef.extensions.deviceAddress | Identifies the device address that an event refers to in an IP network. | ip |
| cef.extensions.deviceAssetId |  | keyword |
| cef.extensions.deviceCustomDate2 | One of two timestamp fields available to map fields that do not apply to any other in this dictionary. | keyword |
| cef.extensions.deviceCustomDate2Label | All custom fields have a corresponding label field. Each of these fields is a string and describes the purpose of the custom field. | keyword |
| cef.extensions.deviceCustomIPv6Address1 | One of four IPv6 address fields available to map fields that do not apply to any other in this dictionary. | ip |
| cef.extensions.deviceCustomIPv6Address1Label | All custom fields have a corresponding label field. Each of these fields is a string and describes the purpose of the custom field. | keyword |
| cef.extensions.deviceCustomIPv6Address2 | One of four IPv6 address fields available to map fields that do not apply to any other in this dictionary. | ip |
| cef.extensions.deviceCustomIPv6Address2Label | All custom fields have a corresponding label field. Each of these fields is a string and describes the purpose of the custom field. | keyword |
| cef.extensions.deviceCustomIPv6Address3 | One of four IPv6 address fields available to map fields that do not apply to any other in this dictionary. | ip |
| cef.extensions.deviceCustomIPv6Address3Label | All custom fields have a corresponding label field. Each of these fields is a string and describes the purpose of the custom field. | keyword |
| cef.extensions.deviceCustomIPv6Address4 | One of four IPv6 address fields available to map fields that do not apply to any other in this dictionary. | ip |
| cef.extensions.deviceCustomIPv6Address4Label | All custom fields have a corresponding label field. Each of these fields is a string and describes the purpose of the custom field. | keyword |
| cef.extensions.deviceCustomNumber1 | One of three number fields available to map fields that do not apply to any other in this dictionary. Use sparingly and seek a more specific, dictionary supplied field when possible. | long |
| cef.extensions.deviceCustomNumber1Label | All custom fields have a corresponding label field. Each of these fields is a string and describes the purpose of the custom field. | keyword |
| cef.extensions.deviceCustomNumber2 | One of three number fields available to map fields that do not apply to any other in this dictionary. Use sparingly and seek a more specific, dictionary supplied field when possible. | long |
| cef.extensions.deviceCustomNumber2Label | All custom fields have a corresponding label field. Each of these fields is a string and describes the purpose of the custom field. | keyword |
| cef.extensions.deviceCustomNumber3 | One of three number fields available to map fields that do not apply to any other in this dictionary. Use sparingly and seek a more specific, dictionary supplied field when possible. | long |
| cef.extensions.deviceCustomNumber3Label | All custom fields have a corresponding label field. Each of these fields is a string and describes the purpose of the custom field. | keyword |
| cef.extensions.deviceCustomString1 | One of six strings available to map fields that do not apply to any other in this dictionary. Use sparingly and seek a more specific, dictionary supplied field when possible. | keyword |
| cef.extensions.deviceCustomString1Label | All custom fields have a corresponding label field. Each of these fields is a string and describes the purpose of the custom field. | keyword |
| cef.extensions.deviceCustomString2 | One of six strings available to map fields that do not apply to any other in this dictionary. Use sparingly and seek a more specific, dictionary supplied field when possible. | keyword |
| cef.extensions.deviceCustomString2Label | All custom fields have a corresponding label field. Each of these fields is a string and describes the purpose of the custom field. | keyword |
| cef.extensions.deviceCustomString3 | One of six strings available to map fields that do not apply to any other in this dictionary. Use sparingly and seek a more specific, dictionary supplied field when possible. | keyword |
| cef.extensions.deviceCustomString3Label | All custom fields have a corresponding label field. Each of these fields is a string and describes the purpose of the custom field. | keyword |
| cef.extensions.deviceCustomString4 | One of six strings available to map fields that do not apply to any other in this dictionary. Use sparingly and seek a more specific, dictionary supplied field when possible. | keyword |
| cef.extensions.deviceCustomString4Label | All custom fields have a corresponding label field. Each of these fields is a string and describes the purpose of the custom field. | keyword |
| cef.extensions.deviceCustomString5 | One of six strings available to map fields that do not apply to any other in this dictionary. Use sparingly and seek a more specific, dictionary supplied field when possible. | keyword |
| cef.extensions.deviceCustomString5Label | All custom fields have a corresponding label field. Each of these fields is a string and describes the purpose of the custom field. | keyword |
| cef.extensions.deviceCustomString6 | One of six strings available to map fields that do not apply to any other in this dictionary. Use sparingly and seek a more specific, dictionary supplied field when possible. | keyword |
| cef.extensions.deviceCustomString6Label | All custom fields have a corresponding label field. Each of these fields is a string and describes the purpose of the custom field. | keyword |
| cef.extensions.deviceDirection | Any information about what direction the observed communication has taken. The following values are supported - "0" for inbound or "1" for outbound. | long |
| cef.extensions.deviceEventCategory | Represents the category assigned by the originating device. Devices often use their own categorization schema to classify event. Example "/Monitor/Disk/Read". | keyword |
| cef.extensions.deviceExternalId | A name that uniquely identifies the device generating this event. | keyword |
| cef.extensions.deviceFacility | The facility generating this event. For example, Syslog has an explicit facility associated with every event. | keyword |
| cef.extensions.deviceHostName | The format should be a fully qualified domain name (FQDN) associated with the device node, when a node is available. | keyword |
| cef.extensions.deviceInboundInterface | Interface on which the packet or data entered the device. | keyword |
| cef.extensions.deviceOutboundInterface | Interface on which the packet or data left the device. | keyword |
| cef.extensions.deviceProcessName | Process name associated with the event. An example might be the process generating the syslog entry in UNIX. | keyword |
| cef.extensions.deviceReceiptTime | The time at which the event related to the activity was received. The format is MMM dd yyyy HH:mm:ss or milliseconds since epoch (Jan 1st 1970) | keyword |
| cef.extensions.deviceSeverity |  | keyword |
| cef.extensions.deviceTimeZone | The time zone for the device generating the event. | keyword |
| cef.extensions.deviceZoneID |  | keyword |
| cef.extensions.deviceZoneURI | Thee URI for the Zone that the device asset has been assigned to in ArcSight. | keyword |
| cef.extensions.dvc | This field is used by Trend Micro if the hostname is an IPv4 address. | ip |
| cef.extensions.dvchost | This field is used by Trend Micro for hostnames and IPv6 addresses. | keyword |
| cef.extensions.eventAnnotationAuditTrail |  | keyword |
| cef.extensions.eventAnnotationEndTime |  | date |
| cef.extensions.eventAnnotationFlags |  | keyword |
| cef.extensions.eventAnnotationManagerReceiptTime |  | date |
| cef.extensions.eventAnnotationModificationTime |  | date |
| cef.extensions.eventAnnotationStageUpdateTime |  | date |
| cef.extensions.eventAnnotationVersion |  | keyword |
| cef.extensions.eventId | This is a unique ID that ArcSight assigns to each event. | long |
| cef.extensions.fileHash | Hash of a file. | keyword |
| cef.extensions.filePath | Full path to the file, including file name itself. | keyword |
| cef.extensions.fileSize | Size of the file. | long |
| cef.extensions.fileType | Type of file (pipe, socket, etc.) | keyword |
| cef.extensions.filename | Name of the file only (without its path). | keyword |
| cef.extensions.ifname |  | keyword |
| cef.extensions.inzone |  | keyword |
| cef.extensions.layer_name |  | keyword |
| cef.extensions.layer_uuid |  | keyword |
| cef.extensions.locality |  | keyword |
| cef.extensions.logid |  | keyword |
| cef.extensions.loguid |  | keyword |
| cef.extensions.managerReceiptTime | When the Arcsight ESM received the event. | date |
| cef.extensions.match_id |  | keyword |
| cef.extensions.message | An arbitrary message giving more details about the event. Multi-line entries can be produced by using \n as the new line separator. | keyword |
| cef.extensions.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| cef.extensions.modelConfidence |  | keyword |
| cef.extensions.nat_addtnl_rulenum |  | keyword |
| cef.extensions.nat_rulenum |  | keyword |
| cef.extensions.oldFileHash | Hash of the old file. | keyword |
| cef.extensions.origin |  | keyword |
| cef.extensions.originalAgentAddress |  | keyword |
| cef.extensions.originalAgentHostName |  | keyword |
| cef.extensions.originalAgentId |  | keyword |
| cef.extensions.originalAgentType |  | keyword |
| cef.extensions.originalAgentVersion |  | keyword |
| cef.extensions.originalAgentZoneURI |  | keyword |
| cef.extensions.originsicname |  | keyword |
| cef.extensions.outzone |  | keyword |
| cef.extensions.parent_rule |  | keyword |
| cef.extensions.priority |  | keyword |
| cef.extensions.product |  | keyword |
| cef.extensions.relevance |  | keyword |
| cef.extensions.repeatCount |  | keyword |
| cef.extensions.requestContext | Description of the content from which the request originated (for example, HTTP Referrer). | keyword |
| cef.extensions.requestMethod | The HTTP method used to access a URL. | keyword |
| cef.extensions.requestUrl | In the case of an HTTP request, this field contains the URL accessed. The URL should contain the protocol as well. | keyword |
| cef.extensions.requestUrlFileName |  | keyword |
| cef.extensions.rule_action |  | keyword |
| cef.extensions.rule_uid |  | keyword |
| cef.extensions.sequencenum |  | keyword |
| cef.extensions.service_id |  | keyword |
| cef.extensions.severity |  | keyword |
| cef.extensions.sourceAddress | Identifies the source that an event refers to in an IP network. | ip |
| cef.extensions.sourceGeoLatitude |  | long |
| cef.extensions.sourceGeoLongitude |  | long |
| cef.extensions.sourceHostName | Identifies the source that an event refers to in an IP network. The format should be a fully qualified domain name (FQDN) associated with the source node, when a mode is available. | keyword |
| cef.extensions.sourceMacAddress | Six colon-separated hexadecimal numbers. | keyword |
| cef.extensions.sourceNtDomain | The Windows domain name for the source address. | keyword |
| cef.extensions.sourcePort | The valid port numbers are 0 to 65535. | long |
| cef.extensions.sourceServiceName | The service that is responsible for generating this event. | keyword |
| cef.extensions.sourceTranslatedAddress | Identifies the translated source that the event refers to in an IP network. | ip |
| cef.extensions.sourceTranslatedPort | A port number after being translated by, for example, a firewall. Valid port numbers are 0 to 65535. | long |
| cef.extensions.sourceTranslatedZoneID |  | keyword |
| cef.extensions.sourceTranslatedZoneURI | The URI for the Translated Zone that the destination asset has been assigned to in ArcSight. | keyword |
| cef.extensions.sourceUserId | Identifies the source user by ID. This is the user associated with the source of the event. For example, in UNIX, the root user is generally associated with user ID 0. | keyword |
| cef.extensions.sourceUserName | Identifies the source user by name. Email addresses are also mapped into the UserName fields. The sender is a candidate to put into this field. | keyword |
| cef.extensions.sourceUserPrivileges | The typical values are "Administrator", "User", and "Guest". It identifies the source user's privileges. In UNIX, for example, activity executed by the root user would be identified with "Administrator". | keyword |
| cef.extensions.sourceZoneID | Identifies the source user by ID. This is the user associated with the source of the event. For example, in UNIX, the root user is generally associated with user ID 0. | keyword |
| cef.extensions.sourceZoneURI | The URI for the Zone that the source asset has been assigned to in ArcSight. | keyword |
| cef.extensions.startTime | The time when the activity the event referred to started. The format is MMM dd yyyy HH:mm:ss or milliseconds since epoch (Jan 1st 1970). | date |
| cef.extensions.target |  | keyword |
| cef.extensions.transportProtocol | Identifies the Layer-4 protocol used. The possible values are protocols such as TCP or UDP. | keyword |
| cef.extensions.type | 0 means base event, 1 means aggregated, 2 means correlation, and 3 means action. This field can be omitted for base events (type 0). | long |
| cef.extensions.version |  | keyword |
| cef.forcepoint.virus_id | Virus ID | keyword |
| cef.name |  | keyword |
| cef.severity |  | keyword |
| cef.version |  | keyword |
| checkpoint.app_risk | Application risk. | keyword |
| checkpoint.app_severity | Application threat severity. | keyword |
| checkpoint.app_sig_id | The signature ID which the application was detected by. | keyword |
| checkpoint.auth_method | Password authentication protocol used. | keyword |
| checkpoint.category | Category. | keyword |
| checkpoint.confidence_level | Confidence level determined. | integer |
| checkpoint.connectivity_state | Connectivity state. | keyword |
| checkpoint.cookie | IKE cookie. | keyword |
| checkpoint.dst_phone_number | Destination IP-Phone. | keyword |
| checkpoint.email_control | Engine name. | keyword |
| checkpoint.email_id | Internal email ID. | keyword |
| checkpoint.email_recipients_num | Number of recipients. | long |
| checkpoint.email_session_id | Internal email session ID. | keyword |
| checkpoint.email_spool_id | Internal email spool ID. | keyword |
| checkpoint.email_subject | Email subject. | keyword |
| checkpoint.event_count | Number of events associated with the log. | long |
| checkpoint.frequency | Scan frequency. | keyword |
| checkpoint.icmp_code | ICMP code. | long |
| checkpoint.icmp_type | ICMP type. | long |
| checkpoint.identity_type | Identity type. | keyword |
| checkpoint.incident_extension | Format of original data. | keyword |
| checkpoint.integrity_av_invoke_type | Scan invoke type. | keyword |
| checkpoint.malware_family | Malware family. | keyword |
| checkpoint.peer_gateway | Main IP of the peer Security Gateway. | ip |
| checkpoint.performance_impact | Protection performance impact. | integer |
| checkpoint.protection_id | Protection malware ID. | keyword |
| checkpoint.protection_name | Specific signature name of the attack. | keyword |
| checkpoint.protection_type | Type of protection used to detect the attack. | keyword |
| checkpoint.scan_result | Scan result. | keyword |
| checkpoint.sensor_mode | Sensor mode. | keyword |
| checkpoint.severity | Threat severity. | keyword |
| checkpoint.spyware_name | Spyware name. | keyword |
| checkpoint.spyware_status | Spyware status. | keyword |
| checkpoint.subs_exp | The expiration date of the subscription. | date |
| checkpoint.tcp_flags | TCP packet flags. | keyword |
| checkpoint.termination_reason | Termination reason. | keyword |
| checkpoint.update_status | Update status. | keyword |
| checkpoint.user_status | User response. | keyword |
| checkpoint.uuid | External ID. | keyword |
| checkpoint.virus_name | Virus name. | keyword |
| checkpoint.voip_log_type | VoIP log types. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.service.name |  | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.path | Path to the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| source.service.name |  | keyword |


##### `log` sample event

An example event for `log` looks as following:

```json
{
    "@timestamp": "2023-04-19T09:52:39.939Z",
    "agent": {
        "ephemeral_id": "1e43410c-3849-4180-9c14-e3264e4a47e6",
        "id": "f1ee4a83-b99b-4611-925d-b83b001f8b86",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.6.2"
    },
    "cef": {
        "device": {
            "event_class_id": "18",
            "product": "Vaporware",
            "vendor": "Elastic",
            "version": "1.0.0-alpha"
        },
        "extensions": {
            "destinationAddress": "192.168.10.1",
            "destinationPort": 443,
            "eventId": 3457,
            "requestContext": "https://www.google.com",
            "requestMethod": "POST",
            "requestUrl": "https://www.example.com/cart",
            "sourceAddress": "89.160.20.156",
            "sourceGeoLatitude": 38.915,
            "sourceGeoLongitude": -77.511,
            "sourcePort": 33876,
            "sourceServiceName": "httpd",
            "transportProtocol": "TCP"
        },
        "name": "Web request",
        "severity": "low",
        "version": "0"
    },
    "data_stream": {
        "dataset": "cef.log",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "ip": "192.168.10.1",
        "port": 443
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "f1ee4a83-b99b-4611-925d-b83b001f8b86",
        "snapshot": false,
        "version": "8.6.2"
    },
    "event": {
        "agent_id_status": "verified",
        "code": "18",
        "dataset": "cef.log",
        "id": "3457",
        "ingested": "2023-04-19T09:52:40Z",
        "severity": 0
    },
    "http": {
        "request": {
            "method": "POST",
            "referrer": "https://www.google.com"
        }
    },
    "input": {
        "type": "udp"
    },
    "log": {
        "source": {
            "address": "172.29.0.4:33227"
        }
    },
    "message": "Web request",
    "network": {
        "community_id": "1:UgazGyZMuRDtuImGjF+6GveZFw0=",
        "transport": "tcp"
    },
    "observer": {
        "product": "Vaporware",
        "vendor": "Elastic",
        "version": "1.0.0-alpha"
    },
    "related": {
        "ip": [
            "192.168.10.1",
            "89.160.20.156"
        ]
    },
    "source": {
        "as": {
            "number": 29518,
            "organization": {
                "name": "Bredband2 AB"
            }
        },
        "geo": {
            "city_name": "Linköping",
            "continent_name": "Europe",
            "country_iso_code": "SE",
            "country_name": "Sweden",
            "location": {
                "lat": 58.4167,
                "lon": 15.6167
            },
            "region_iso_code": "SE-E",
            "region_name": "Östergötland County"
        },
        "ip": "89.160.20.156",
        "port": 33876,
        "service": {
            "name": "httpd"
        }
    },
    "tags": [
        "cef",
        "forwarded"
    ],
    "url": {
        "original": "https://www.example.com/cart"
    }
}
```

### Vendor documentation links

For more information about CEF field mappings and configuration for specific vendors, refer to the following resources:
- [Log Exporter CEF Field Mappings](https://community.checkpoint.com:443/t5/Management/Log-Exporter-CEF-Field-Mappings/td-p/41060) — Provides detailed field mappings for Check Point's CEF extension fields.
- Forcepoint SMC Configuration Guide (KB 15002) — Forcepoint knowledge base article offering guidance on configuring the Security Management Center.
