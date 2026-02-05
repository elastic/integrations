markdown
# Service Info

## Common use cases

This integration provides a robust solution for collecting and parsing Common Event Format (CEF) data, enabling centralized security monitoring and analysis. Specific use cases include:
- **Centralized Security Monitoring:** Ingest CEF-formatted audit and security logs from various security devices and applications, such as firewalls and intrusion prevention systems, into a unified platform for real-time threat detection and incident response.
- **Compliance and Auditing:** Collect and retain detailed CEF logs from network devices like Forcepoint NGFW and Check Point gateways to meet regulatory compliance requirements and facilitate security audits by providing a comprehensive historical record of network activity.
- **Enhanced Threat Intelligence:** Leverage the structured nature of CEF data, enriched with Elastic Common Schema (ECS) fields, to correlate events from different sources, identify attack patterns, and enrich security alerts with context from various vendor products.
- **Operational Visibility:** Gain insights into network traffic, application usage, and system events by collecting CEF logs, which helps in monitoring network health, troubleshooting connectivity issues, and understanding user behavior.

## Data types collected

This integration can collect the following types of data:
- **CEF logs (type: logs, input: logfile) - Dataset: `cef.log`:** Collects Common Event Format (CEF) logs from specified local file paths, enabling the ingestion of security and audit events recorded by various applications and devices.
- **CEF logs (type: logs, input: udp) - Dataset: `cef.log`:** Gathers Common Event Format (CEF) logs sent over UDP, typically from network devices configured to forward their security events to a designated syslog host.
- **CEF logs (type: logs, input: tcp) - Dataset: `cef.log`:** Collects Common Event Format (CEF) logs transmitted via TCP, providing a reliable transport mechanism for security events from various sources to the Elastic Agent.

## Compatibility

- **Forcepoint NGFW Security Management Center**: Tested and compatible with version 6.6.1.
- **Check Point devices**: Compatible with devices using Log Exporter for forwarding logs in CEF format.

## Scaling and Performance

To ensure optimal performance in high-volume environments, consider the following:
- **Transport/Collection Considerations:** For network-based collection, UDP offers high-speed, connectionless transmission, suitable for environments where occasional packet loss is acceptable and high throughput is critical. TCP provides reliable, ordered delivery, ensuring all log messages are received, which is crucial for audit and compliance needs, but may introduce higher latency and overhead. For logfile inputs, ensure proper log rotation is configured on the source system to prevent excessive file sizes and maintain efficient read performance by the Elastic Agent. Custom UDP options like `read_buffer`, `max_message_size`, and `timeout` and TCP options like `max_connections`, `framing`, and `line_delimiter` can be tuned for specific network conditions and load.
- **Data Volume Management:** To manage data volume efficiently, configure source systems like Forcepoint SMC or Check Point Log Exporter to filter or limit the types of events or log levels forwarded to the Elastic Agent. Define specific audit forwarding rules in Forcepoint SMC or select relevant log types in Check Point's Log Exporter to send only necessary security and operational events, reducing the load on both the source device and the Elastic Stack. High data volume without filtering can impact the performance of the source system and increase resource consumption on the Elastic Agent.
- **Elastic Agent Scaling:** A single Elastic Agent can handle a significant volume of CEF logs, but for high-throughput environments or when collecting from multiple high-volume sources, consider deploying multiple Elastic Agents. Distribute the log forwarding across several Agents, each listening on different ports or interfaces, to scale ingestion horizontally. Resource sizing (CPU, memory, disk I/O) for the Elastic Agent host should be based on the expected peak log volume and the complexity of any pre-processors or processors applied. Place Agents strategically close to the log sources to minimize network latency.

# Set Up Instructions

## Vendor prerequisites

-   **Administrative Access**: Full administrative access to the Forcepoint Security Management Center (SMC) or Check Point SmartConsole is required to configure log forwarding rules and exporter objects.
-   **Network Connectivity**: The Elastic Agent's listening host and port (e.g., `syslog_host: 0.0.0.0`, `syslog_port: 9003` for UDP or `9004` for TCP) must be reachable from the Forcepoint Log Server or Check Point Management Server. Ensure appropriate firewall rules are in place.
-   **CEF Formatting**: The source devices must be configured to export logs in the Common Event Format (CEF).
-   **Log Server Configuration**: For Forcepoint, the Log Server within SMC must be configured to forward logs. For Check Point, the Log Exporter feature must be configured and assigned to the Management/Log Server.
-   **Forcepoint Connection Accounting**: To include connection-related byte counts, ensure access policies on Forcepoint NGFW have "Connection Closing: Log Accounting Information" enabled.

## Elastic prerequisites

- **Elastic Agent:** An Elastic Agent must be installed and enrolled in Fleet, connected to your Elastic Stack instance.
- **Network Connectivity:** The Elastic Agent host must have network access to communicate with your Elasticsearch cluster and Kibana instance. It also needs to be reachable by the vendor device (Forcepoint, Check Point) on the configured syslog ports.

## Vendor set up steps

### For Forcepoint NGFW Security Management Center (SMC):
1.  Log in to the Forcepoint Security Management Center.
2.  Navigate to the **Management Server properties** and select the **Audit Forwarding** tab.
3.  Configure a new forwarding rule: Specify the IP address or FQDN of the Elastic Agent host, the port (e.g., `9003` for UDP or `9004` for TCP), and select the protocol (UDP or TCP) that the Elastic Agent is configured to listen on.
4.  Access the Management Server's file system and open the configuration file located at `<installation directory>/data/SGConfiguration.txt`.
5.  Add the following parameter to the `SGConfiguration.txt` file to enable custom CEF field configuration:
    `CEF_ADDITIONAL_FIELDS_CONF_FILE=<path_to_your_custom_cef_config_file>` (e.g., `/opt/Forcepoint/SMC/data/cef_audit_fields.txt`).
6.  Create the custom CEF configuration file at the path specified in the previous step (e.g., `cef_audit_fields.txt`). In this file, define the specific audit log fields you wish to export in CEF format. Refer to `<installation_directory>/data/fields/datatypes/audit_datatype.xml` for a list of available fields.
7.  Save the `SGConfiguration.txt` file and your custom CEF configuration file.
8.  Restart the Management Server service for the changes to take effect and begin forwarding logs.

### For Check Point Log Exporter:
1.  Log in to the Check Point SmartConsole.
2.  Create a new Log Exporter object by navigating to **Objects > More object types > Server > Log Exporter/SIEM**.
3.  Provide a descriptive name for the new object, such as `elastic-agent-cef`.
4.  On the **General** page of the Log Exporter object:
    *   Set **Export Configuration** to **Enabled**.
    *   For **Target Server**, enter the IP address or FQDN of the server running the Elastic Agent.
    *   For **Target Port**, specify the port number the Elastic Agent is listening on for syslog messages (e.g., `9003` for UDP or `9004` for TCP).
    *   Select the **Protocol** (`UDP` or `TCP`) to match your Elastic Agent's input configuration.
5.  On the **Data Manipulation** page, set the **Format** dropdown list to **Common Event Format (CEF)**.
6.  Click **OK** to save the newly configured Log Exporter object.
7.  Next, navigate to **Gateways & Servers**.
8.  Open the properties for your **Management Server** or the specific **Dedicated Log Server** responsible for forwarding logs.
9.  From the navigation tree on the left, select **Logs > Export**.
10. Click the `+` icon and select the `elastic-agent-cef` Log Exporter object you created earlier. Click **OK**.
11. To ensure all configuration changes are applied, install the database. From the top menu, click **Menu > Install database**.
12. Select all objects in the confirmation window and click **Install**.

## Vendor Set up Resources

- [How to Configure SMC Audit Log Forwarding - Forcepoint](https://support.forcepoint.com/s/article/How-to-configure-Security-Management-Center-audit-log-forwarding)
- [Log Exporter - Check Point R81.20 Logging and Monitoring Administration Guide](https://sc1.checkpoint.com/documents/R81.20/WebAdminGuides/EN/CP_R81.20_LoggingAndMonitoring_AdminGuide/Content/Topics-LMG/Log-Exporter.htm)
- [Configuring Log Exporter in SmartConsole - Check Point R81.20 Guide](https://sc1.checkpoint.com/documents/R81.20/WebAdminGuides/EN/CP_R81.20_LoggingAndMonitoring_AdminGuide/Content/Topics-LMG/Log-Exporter-Configuration-in-SmartConsole.htm)
- [sk122323 - Log Exporter - Check Point Log Export](https://support.checkpoint.com/results/sk/sk122323)

## Kibana set up steps

To set up the CEF integration in Kibana:
1.  In Kibana, navigate to **Integrations**.
2.  Search for `CEF` and click on the **Common Event Format (CEF)** integration.
3.  Click **Add Common Event Format (CEF)**.
4.  Follow the prompts to add the integration to an existing Elastic Agent policy or create a new one.
5.  After adding the integration, you will be directed to the integration's settings page. Here, you can select and configure the specific input types based on your CEF log source. Choose one or more of the following:

### Collecting application logs from CEF instances (input: logfile)
1. Within the integration settings, click **Add input** and select **Collecting application logs from CEF instances (input: logfile)**.
2. Configure the following fields:
   - **Paths**: List of paths from which to read log files. Default: `['/var/log/cef.log']`.
   - **Ignore Empty Values**: Ignore CEF fields that are empty. The alternative behavior is to treat an empty field as an error. Default: `False`.
   - **Dataset name**: Dataset to write data to. Changing the dataset will send the data to a different index. You can't use `-` in the name of a dataset and only valid characters for [Elasticsearch index names](https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-index_.html). Default: `cef.log`.
   - **Preserve original event**: Preserves a raw copy of the original event, added to the field `event.original`. Default: `False`.
   - **CEF Timezone**: IANA time zone or time offset (e.g. `+0200`) to use when interpreting timestamps without a time zone in the CEF message.
   - **Tags**: A list of tags to include in events. Including `forwarded` indicates that the events did not originate on this host and causes `host.name` to not be added to events. Default: `['cef', 'forwarded']`.
   - **Pre-Processors**: Pre-processors are run before the CEF message is decoded. They can be used to correct CEF formatting inconsistencies that may exist from some sources. See [Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details.
   - **Processors**: Processors are used to reduce the number of fields in the exported event or to enhance the event with metadata. This executes in the agent after the logs are parsed. See [Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details.
3. Review any additional settings.
4. Click **Save and deploy** to apply the configuration to your Elastic Agent.

### Collecting application logs from CEF instances (input: udp)
1. Within the integration settings, click **Add input** and select **Collecting application logs from CEF instances (input: udp)**.
2. Configure the following fields:
   - **Syslog Host**: The interface to listen to UDP based syslog traffic. Set to `0.0.0.0` to bind to all available interfaces. Default: `localhost`.
   - **Syslog Port**: The UDP port to listen for syslog traffic. Default: `9003`.
   - **Dataset name**: Dataset to write data to. Changing the dataset will send the data to a different index. You can't use `-` in the name of a dataset and only valid characters for [Elasticsearch index names](https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-index_.html). Default: `cef.log`.
   - **Preserve original event**: Preserves a raw copy of the original event, added to the field `event.original`. Default: `False`.
   - **Ignore Empty Values**: Ignore CEF fields that are empty. The alternative behavior is to treat an empty field as an error. Default: `False`.
   - **CEF Timezone**: IANA time zone or time offset (e.g. `+0200`) to use when interpreting timestamps without a time zone in the CEF message.
   - **Tags**: A list of tags to include in events. Including `forwarded` indicates that the events did not originate on this host and causes `host.name` to not be added to events. Default: `['cef', 'forwarded']`.
   - **Custom UDP Options**: Specify custom configuration options for the UDP input. Default: `#read_buffer: 100MiB\n#max_message_size: 50KiB\n#timeout: 300s\n`.
   - **Pre-Processors**: Pre-processors are run before the CEF message is decoded. They can be used to correct CEF formatting inconsistencies that may exist from some sources. See [Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details.
   - **Processors**: Processors are used to reduce the number of fields in the exported event or to enhance the event with metadata. This executes in the agent after the logs are parsed. See [Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details.
3. Review any additional settings.
4. Click **Save and deploy** to apply the configuration to your Elastic Agent.

### Collecting application logs from CEF instances (input: tcp)
1. Within the integration settings, click **Add input** and select **Collecting application logs from CEF instances (input: tcp)**.
2. Configure the following fields:
   - **Syslog Host**: The interface to listen to TCP based syslog traffic. Set to `0.0.0.0` to bind to all available interfaces. Default: `localhost`.
   - **Syslog Port**: The TCP port to listen for syslog traffic. Default: `9004`.
   - **Dataset name**: Dataset to write data to. Changing the dataset will send the data to a different index. You can't use `-` in the name of a dataset and only valid characters for [Elasticsearch index names](https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-index_.html). Default: `cef.log`.
   - **Preserve original event**: Preserves a raw copy of the original event, added to the field `event.original`. Default: `False`.
   - **Ignore Empty Values**: Ignore CEF fields that are empty. The alternative behavior is to treat an empty field as an error. Default: `False`.
   - **CEF Timezone**: IANA time zone or time offset (e.g. `+0200`) to use when interpreting timestamps without a time zone in the CEF message.
   - **Tags**: A list of tags to include in events. Including `forwarded` indicates that the events did not originate on this host and causes `host.name` to not be added to events. Default: `['cef', 'forwarded']`.
   - **SSL Configuration**: SSL configuration options. See [documentation](https://www.elastic.co/guide/en/beats/filebeat/current/configuration-ssl.html#ssl-common-config) for details. Default: `#certificate: "/etc/server/cert.pem"\n#key: "/etc/server/key.pem"\n`.
   - **Custom TCP Options**: Specify custom configuration options for the TCP input. See [TCP](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-tcp.html) for details. Default: `#max_connections: 1\n#framing: delimiter\n#line_delimiter: "\n"\n`.
   - **Pre-Processors**: Pre-processors are run before the CEF message is decoded. They can be used to correct CEF formatting inconsistencies that may exist from some sources. See [Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details.
   - **Processors**: Processors are used to reduce the number of fields in the exported event or to enhance the event with metadata. This executes in the agent after the logs are parsed. See [Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details.
3. Review any additional settings.
4. Click **Save and deploy** to apply the configuration to your Elastic Agent.

# Validation Steps

After configuration is complete, follow these steps to verify data is flowing correctly from CEF sources to the Elastic Stack.

### 1. Trigger Data Flow on CEF:
-   **For Forcepoint NGFW SMC**: Log in to the SMC, make a small change to a policy or rule (e.g., enable/disable a rule, then re-enable), and install the policy to generate configuration change logs. Alternatively, browse several websites from a client behind the Forcepoint firewall to generate web filtering or connection logs.
-   **For Check Point Devices**: Log in to SmartConsole and install policy on a Gateway. Initiate some network traffic through a Check Point Gateway (e.g., browse to a blocked website to generate a drop log, or an allowed site to generate connection logs) to trigger log generation via Log Exporter.
-   **For Logfile Input**: Manually append a test CEF message to the configured log file path (e.g., `echo "CEF:0|TestVendor|TestProduct|1.0|100|Test Event|1|msg=This is a test event" >> /var/log/cef.log`) to verify file reading.

### 2. Check Data in Kibana:
1.  Navigate to **Analytics > Discover**.
2.  Select the `logs-*` data view or the specific integration data view.
3.  Enter the following KQL filter: `data_stream.dataset : "cef.log"`
4.  Verify logs appear in the results. Expand a log entry and confirm these fields are populated:
    -   `event.dataset` (should be `cef.log`)
    -   `source.ip` and/or `destination.ip` (for network-related events)
    -   `event.action` or `event.outcome` (for security events)
    -   `cef.name` (the name of the CEF event)
    -   `cef.deviceProduct` (the product from which the event originated)
    -   `message` (containing the raw log payload)
5.  Navigate to **Analytics > Dashboards** and search for "CEF" to view pre-built visualizations.

# Troubleshooting

## Common Configuration Issues

-   **Incorrect Syslog Host or Port**:
    -   **Cause**: The Elastic Agent is configured to listen on a different IP address or port than what the vendor device is forwarding logs to.
    -   **Solution**: Double-check the `syslog_host` and `syslog_port` settings in the Elastic Agent's CEF integration configuration. Ensure these match the destination IP and port configured on the vendor device (Forcepoint SMC or Check Point Log Exporter). Use `netstat -tulnp` on the Elastic Agent host to verify the Agent is listening on the expected port.
-   **Network Connectivity Issues**:
    -   **Cause**: Firewall rules on the vendor device, Elastic Agent host, or an intermediate network device are blocking syslog traffic.
    -   **Solution**: Verify network connectivity using `ping` from the vendor device to the Elastic Agent host. Check firewall rules (`firewalld`, `ufw`, `iptables` on Linux, or Windows Firewall) on both ends to ensure the syslog port (e.g., 9003 UDP, 9004 TCP) is open. A `tcpdump` or `wireshark` capture on the Elastic Agent host can confirm if packets are reaching the interface.
-   **CEF Formatting Inconsistencies**:
    -   **Cause**: The vendor device is sending CEF messages that do not strictly adhere to the CEF specification, causing parsing errors.
    -   **Solution**: Inspect the raw `event.original` field in Kibana if `preserve_original_event` is enabled. If the CEF message is malformed, consider using the `preprocessors` option in the Elastic Agent configuration to modify the message before CEF decoding. Refer to vendor documentation for exact CEF output specifications.
-   **Check Point Log Exporter Not Running or Misconfigured**:
    -   **Cause**: The `cp_log_export` instance on the Check Point device is not started, or its configuration parameters (e.g., `target-server`, `target-port`, `protocol`, `format`) are incorrect.
    -   **Solution**: On the Check Point CLI, use `cp_log_export status name <exporter_name>` to check the status. If not running, start it with `cp_log_export start name <exporter_name>`. Verify the configuration with `cp_log_export show name <exporter_name>` and ensure it matches the Elastic Agent's setup.

## Ingestion Errors

-   **CEF Formatting Inconsistencies**:
    -   **Cause**: The incoming CEF messages from the vendor do not strictly adhere to the CEF specification, leading to parsing failures by the `decode_cef` processor. This often occurs with non-standard extensions or malformed fields.
    -   **Solution**: Utilize the `Pre-Processors` option in the Elastic Agent integration configuration. You can apply ingest processors (e.g., `dissect`, `grok`, `gsub`) to modify the `message` field and correct formatting issues before the `decode_cef` processor runs. The original message is preserved in `event.original` for reference.
-   **Empty CEF Fields Causing Errors**:
    -   **Cause**: The `decode_cef` processor might treat empty CEF extension fields as errors if `ignore_empty_values` is set to `False`.
    -   **Solution**: If empty fields are expected and should not cause parsing failures, set the `Ignore Empty Values` option to `True` in the Elastic Agent integration configuration.
-   **Incorrect `@timestamp` Field**:
    -   **Cause**: The `@timestamp` field in Kibana does not reflect the expected event time. This can happen if the integration prioritizes the syslog timestamp over a device receipt timestamp present in the CEF data, or vice-versa, or if timezone handling is incorrect.
    -   **Solution**: Review the raw `message` and `event.original` fields in Discover to identify the timestamps present. Adjust the `CEF Timezone` setting in the integration configuration to correctly interpret timestamps without timezone information.

## Vendor Resources

- Forcepoint SMC Configuration Guide (KB 15002) - Forcepoint knowledge base article offering guidance on configuring the Security Management Center.
- [Log Exporter CEF Field Mappings](https://community.checkpoint.com:443/t5/Management/Log-Exporter-CEF-Field-Mappings/td-p/41060) - Provides detailed field mappings for Check Point's CEF extension fields.

# Documentation sites

Refer to the official vendor website for additional resources.
