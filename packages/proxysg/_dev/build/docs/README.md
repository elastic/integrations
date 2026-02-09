# Broadcom ProxySG Integration for Elastic

> **Note**: This documentation was generated using AI and should be reviewed for accuracy.

## Overview

The Broadcom ProxySG integration for Elastic allows you to ingest and analyze web traffic data from your Broadcom ProxySG (formerly Symantec) appliances. By collecting and centralizing these logs, you gain deep visibility into user activity, security threats, and network performance across your infrastructure.

### Compatibility

This integration is compatible with Broadcom ProxySG and Edge SWG appliances. It has been specifically tested and documented for ProxySG / Edge SWG version 7.3 and later.

The integration currently supports the following log formats as defined in the appliance configuration:
- `main`
- `bcreportermain_v1`
- `bcreporterssl_v1`
- `ssl`

This integration is compatible with Elastic Stack version 8.11.0 or later.

### How it works

This integration collects ProxySG access logs by acting as a receiver for data sent from the appliance or by reading logs from a file. You can deploy an Elastic Agent and configure it to collect data through several methods:
- File collection: Use this method when logs are uploaded from the ProxySG appliance to a central logging server where the Elastic Agent is running.
- TCP: Use this method for reliable real-time log transmissions, ensuring delivery for sensitive security audits.
- UDP: Use this method to capture real-time syslog-style transmissions from the appliance, which is suitable for high-velocity environments, and where possible log message loss is acceptable.

Once the logs are ingested, the integration parses the data into the Elastic Common Schema (ECS), making it ready for analysis in Kibana dashboards or for use with Elastic Security.

## What data does this integration collect?

This integration collects ProxySG access logs, which contain detailed records of web traffic passing through your ProxySG appliance. These logs include:

- **Request and response details**: URLs, HTTP methods, status codes, content types, and bytes transferred.
- **Client information**: Source IP addresses, user identities (when authenticated), and user agent strings.
- **Timing data**: Request timestamps, response times, and connection durations.
- **Security context**: SSL/TLS inspection results, certificate details, and threat categories.
- **Policy decisions**: Actions taken (allowed, denied, or observed), matched policy rules, and URL categories.
- **Caching metrics**: Cache hit or miss status and origin server response information.

### Supported use cases

Integrating your Broadcom ProxySG logs with the Elastic Stack provides several benefits for monitoring and securing your network:
- Security monitoring: You can use the logs to detect unauthorized access attempts or suspicious traffic patterns in real time.
- Network traffic analysis: You'll be able to visualize and analyze your network traffic patterns using Kibana dashboards to identify performance issues or optimize resources.
- Compliance and auditing: You can maintain a searchable history of access logs to meet your organization's regulatory requirements for data retention and auditing.
- Incident response: You'll accelerate your investigations by correlating ProxySG data with other security and observability data sources within Elastic.

## What do I need to use this integration?

### Elastic prerequisites
To use this integration, you need:
- An Elastic Agent installed and enrolled in Fleet on a host that can receive network traffic from your Broadcom ProxySG appliance.
- The required TCP or UDP ports open in the host's local firewall to receive log data, when using the network data collection methods.ß

### Vendor prerequisites
You'll need the following from your Broadcom ProxySG environment:
- Administrative credentials for the ProxySG Management Console with permissions to modify access logging and upload client settings.
- Network connectivity between the ProxySG appliance and the Elastic Agent host on the configured ports.
- A supported log configuration on the appliance.
- Permission to install or modify policies in the Visual Policy Manager (VPM) to ensure traffic is written to the access log.
- A destination server for FTP, SFTP, or SCP that the Elastic Agent can access locally if you're using the file upload method.

## How do I deploy this integration?

### Agent-based deployment

You'll need to install the Elastic Agent on a host that can receive syslog data or access the log files from your Broadcom ProxySG appliance. For detailed instructions, refer to the Elastic Agent [installation guide](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can only install one Elastic Agent per host.

You'll use the Elastic Agent to stream data from your syslog or log file receiver and ship it to Elastic. Once there, the integration's ingest pipelines will process your events.

### Set up steps in Broadcom ProxySG

You'll need to configure your ProxySG appliance to send logs to the host where your Elastic Agent is running. You can choose between syslog collection or file upload.

#### Syslog (TCP/UDP) collection

To send logs via syslog, follow these steps:

1. Log in to your **ProxySG Management Console**.
2. Navigate to **Configuration > Access Logging > Logs > General**.
3. Select the log object you want to collect and ensure the **Log Format** is set to a supported format.
4. Navigate to **Configuration > Access Logging > Logs > Upload Client**.
5. Select the same log object from the list.
6. Change the **Client type** to `Custom Client`.
7. Click **Settings** and configure the following:
    - **Primary Host**: Enter the IP address of your Elastic Agent.
    - **Port**: Enter `514` for UDP or `601` for TCP (replace with your actual port if different).
    - **Protocol**: Select `UDP` or `TCP` depending on your transport preference.
8. Click **OK**, then click **Apply**.
9. Navigate to the **Upload Schedule** tab.
10. Select the log object and set the **Upload type** to `Continuously`.
11. Optionally, set the **Wait time before upload** to `5` seconds for near real-time delivery.
12. Click **Apply**.

#### File upload collection

To upload logs as files, follow these steps:

1. Log in to your **ProxySG Management Console**.
2. Navigate to **Configuration > Access Logging > Logs > Upload Client**.
3. Select the log object you want to collect.
4. Set the **Client type** to `FTP Client`, `SFTP Client`, or `SCP Client` depending on your logging server.
5. Click **Settings** and enter the destination server details where your Elastic Agent can access the files.
6. Under **Save the log file as**, select `text file`.
7. Navigate to the **Upload Schedule** tab and set the **Upload type** to `Periodically` or `Continuously`.
8. Click **Apply**.

#### Enable logging in policy

You'll also need to ensure your policies are configured to log traffic:

1. Launch the **Visual Policy Manager (VPM)** from your ProxySG Console.
2. Create or edit a **Web Access Layer**.
3. Locate or create a rule for the traffic you want to monitor.
4. Right-click the **Action** column and select **Set > New > Modify Access Logging**.
5. Select the log object (for example, `main`) you configured in the previous steps.
6. Click **OK**, then click **Install Policy**.

#### Vendor resources

For more information, refer to these Broadcom resources:

- [Sending Access Logs to a Syslog server - Broadcom Knowledge Base](https://knowledge.broadcom.com/external/article/166529/sending-access-logs-to-a-syslog-server.html)
- [Configure access logging on ProxySG to an FTP server - Broadcom Knowledge Base](https://knowledge.broadcom.com/external/article/165586/configure-access-logging-on-proxysg-or-a.html)

### Set up steps in Kibana

You'll need to add the integration to an Elastic Agent policy in Kibana.

1. In Kibana, navigate to **Management > Integrations**.
2. Search for **Broadcom ProxySG** and select it.
3. Click **Add Broadcom ProxySG**.
4. Configure the integration settings based on the input method you chose in the ProxySG setup.

#### Collecting access logs via logging server file

Use this input if your ProxySG uploads files to a server that the Elastic Agent can access.

| Setting | Description |
|---|---|
| **Paths** | The file pattern matching the location of your log files (for example, `/var/log/proxysg-log.log`). |
| **Preserve original event** | If you want to keep a raw copy of the event in the `event.original` field, toggle this to `true`. |
| **Access Log Format** | The log configuration type. Supported formats include `main`, `ssl`, `bcreportermain_v1`, and `bcreporterssl_v1`. |

Under **Advanced options**, you'll find these settings:

| Setting | Description |
|---|---|
| **Tags** | Custom tags to append to your events (for example, `proxysg-access-log`). |
| **Custom Filestream Options** | Specify custom configuration for the Filestream input. |
| **Processors** | Add processors to reduce or enhance your events before they're parsed. |

#### Collecting logs via UDP

Use this input if you configured ProxySG to send logs via UDP syslog.

| Setting | Description |
|---|---|
| **Listen Address** | The bind address to listen for UDP connections. Use `0.0.0.0` to bind to all available interfaces. |
| **Listen Port** | The UDP port number to listen on (for example, `514`). |
| **Preserve original event** | If you want to keep a raw copy of the event in the `event.original` field, toggle this to `true`. |
| **Access Log Format** | The log configuration type. Supported formats include `main`, `ssl`, `bcreportermain_v1`, and `bcreporterssl_v1`. |

Under **Advanced options**, you'll find these settings:

| Setting | Description |
|---|---|
| **Tags** | Custom tags to append to your events. |
| **Custom UDP Options** | Specify custom configuration like `read_buffer` or `max_message_size`. |
| **Processors** | Add processors to execute in the agent before logs are parsed. |

#### Collecting logs via TCP

Use this input if you configured ProxySG to send logs via TCP syslog.

| Setting | Description |
|---|---|
| **Listen Address** | The bind address to listen for TCP connections. Use `0.0.0.0` to bind to all available interfaces. |
| **Listen Port** | The TCP port number to listen on (for example, `601`). |
| **Preserve original event** | If you want to keep a raw copy of the event in the `event.original` field, toggle this to `true`. |
| **Access Log Format** | The log configuration type. Supported formats include `main`, `ssl`, `bcreportermain_v1`, and `bcreporterssl_v1`. |

Under **Advanced options**, you'll find these settings:

| Setting | Description |
|---|---|
| **Tags** | Custom tags to append to your events. |
| **Custom TCP Options** | Specify custom configuration for the TCP input. |
| **SSL Configuration** | Configure encrypted transmission using `certificate` and `key` paths. |
| **Processors** | Add processors to execute in the agent before logs are parsed. |

After you've finished configuring your input, click **Save and continue** to add the integration to your agent policy.

### Validation

You'll want to verify that your data is flowing correctly from the ProxySG appliance to Elasticsearch.

#### Trigger data flow on ProxySG

You can generate logs by performing these actions:

- **Generate Web Traffic**: Browse several public websites from a workstation using the ProxySG as a gateway.
- **Trigger Policy Events**: Try to access a URL category that's restricted by your policy to generate "denied" or "blocked" entries.
- **Force Log Upload**: In the Management Console, navigate to **Access Logging > Logs > [Your Log] > Upload Now** and click the button to manually trigger a log push.

#### Check data in Kibana

You can verify the incoming data by following these steps:

1. Navigate to **Analytics > Discover**.
2. Select the `logs-*` data view.
3. Enter the KQL filter: `data_stream.dataset : "proxysg.log"`
4. Confirm that logs appear and verify that fields like `event.dataset`, `source.ip`, and `message` are correctly populated.
5. Navigate to **Analytics > Dashboards** and search for "ProxySG" to see if the pre-built dashboards are showing your data.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Common configuration issues

If you encounter issues with the Broadcom ProxySG integration, review these common problems and solutions:

- Log format mismatch: Ensure the ProxySG appliance is explicitly using a format supported by the integration. If a custom format is defined on the appliance, the Elastic Agent will fail to parse the fields correctly. Check the settings in **Configuration > Access Logging > Logs > General**.
- Upload schedule delay: If data appears delayed, check the **Upload Schedule** on the ProxySG. Ensure it's set to `Continuously` rather than `Periodically` or `On-Demand`.
- Custom client port conflict: If you're using the syslog method, ensure no other service on the Elastic Agent host is using the configured TCP or UDP port. You can use `netstat -ano` or `ss -tuln` to verify port availability.
- VPM policy not applied: If no logs are appearing, verify that the **Modify Access Logging** action is correctly applied to the relevant rules in the Visual Policy Manager and that the policy has been successfully installed.
- Parsing failures: If logs appear in Kibana but contain a `_grokparsefailure` or `_jsonparseerror` tag, verify that the raw message in the `event.original` field matches the expected structure of the configured ProxySG format.
- Timezone mismatch: If logs appear to be delayed or from the future, check that the ProxySG appliance and the Elastic Agent host are synchronized via NTP and that timezone offsets are correctly handled in the integration settings.

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

To ensure optimal performance in high-volume environments, consider the following:
- Transport and collection: For real-time requirements, TCP is the recommended transport protocol to ensure delivery reliability via the `ProxySG logs (via TCP)` input. You can use UDP for high-velocity environments where occasional packet loss is acceptable for reduced overhead. When you use the `ProxySG Access logs` (`filestream`) method, make sure the disk I/O on the logging server can handle the write and read operations of the incoming log files.
- Data volume management: In high-traffic environments, you should use the ProxySG's Web Access Policy to filter out unnecessary logs—such as specific health checks or trusted internal traffic—at the source before you send them to the Elastic Agent. This significantly reduces the processing load on both the appliance and the Elastic Stack ingest pipelines.
- Elastic Agent scaling: If you're working in high-throughput environments exceeding 10,000 events per second, deploy multiple Elastic Agents behind a network load balancer to distribute the Syslog (TCP/UDP) ingestion load. Make sure the host machine for the Agent has enough CPU resources to handle the concurrent parsing of the ProxySG logs across multiple data streams.

## Reference

This reference section provides technical details about the inputs and data streams used by this integration.

### Inputs used

{{ inputDocs }}

### Vendor documentation links

The following resources provide additional information about Broadcom ProxySG log formats and configuration:
* [Sending Access Logs to a Syslog server - Broadcom Knowledge Base](https://knowledge.broadcom.com/external/article/166529/sending-access-logs-to-a-syslog-server.html)
* [Configure access logging on ProxySG to an FTP server - Broadcom Knowledge Base](https://knowledge.broadcom.com/external/article/165586/configure-access-logging-on-proxysg-or-a.html)
* [Broadcom ProxySG Log Formats Documentation](https://techdocs.broadcom.com/us/en/symantec-security-software/web-and-network-security/edge-swg/7-3/getting-started/page-help-administration/page-help-logging/log-formats/default-formats.html)

### Data streams

The Broadcom ProxySG integration collects the following data stream:

#### log

The `log` data stream provides events from Broadcom ProxySG of the following types: access logs, SSL session logs, and security policy events. It supports logs in the `main`, `ssl`, `bcreportermain_v1`, and `bcreporterssl_v1` formats.

##### log fields

{{ fields "log" }}

##### log sample event

{{ event "log" }}


