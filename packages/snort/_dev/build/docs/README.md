# Snort Integration for Elastic

> **Note**: This documentation was generated using AI and should be reviewed for accuracy.

## Overview

The Snort integration for Elastic enables you to collect logs from Snort, a leading open-source Intrusion Prevention System (IPS). You can monitor network traffic in real-time to detect security threats, policy violations, and unauthorized access attempts. By ingesting Snort logs, you'll gain visibility into network activity, audit security events, and troubleshoot network issues.

### Compatibility

This integration has been developed and tested against Snort versions 2.9 and 3.0. It's expected to work with other versions that utilize the supported output formats.

This integration is compatible with Elastic Stack version 8.11.0 or higher.

### How it works

The integration collects logs from your Snort instances by deploying an Elastic Agent on a host that has access to the log data. Once you've configured the agent, it forwards the logs to your Elastic deployment, where they're parsed and enriched with relevant metadata before being indexed for analysis in the `log` data stream.

You can configure the agent to receive data in two ways:
- Log file monitoring: You configure the Elastic Agent to read logs directly from Snort's output log files on the local filesystem.
- Syslog: You configure Snort to send logs to a syslog server, and the Elastic Agent listens for these logs on a specified UDP port.

## What data does this integration collect?

The Snort integration collects log messages containing information about network traffic and security events. You can ingest data from various versions of Snort and specific environments like pfSense.

The Snort integration collects log messages of the following types:
* Intrusion detection logs: High-priority alerts generated when network traffic matches Snort's rule definitions.
* Network metadata: Protocol information, source and destination IP addresses, and port numbers associated with security events.
* Alert formats: Support for JSON (Snort 3), CSV (pfSense), and Alert Fast (legacy Snort) formats.
* Network packets: Captured packet data for deep inspection and analysis.
* Protocol analysis data: Detailed information about network protocols and session states.

This data is collected and processed into the `log` data stream.

### Supported use cases

Integrating Snort logs with the Elastic Stack provides visibility into your network security posture. You can use this integration for the following use cases:
* Intrusion detection: Monitor network traffic in real-time to detect unauthorized access attempts, policy violations, and other security threats.
* Network traffic analysis: Identify malicious patterns and anomalies by visualizing network traffic and security alerts in Kibana.
* Incident response: Accelerate incident investigation by correlating Snort alerts with other security and observability data sources within the Elastic Stack.
* Compliance monitoring: Ensure adherence to security policies and regulatory requirements by logging and auditing security violations.

## What do I need to use this integration?

To use this integration, you'll need the following:
- An active installation of Snort `v2.9`, `v3.0`, or newer.
- Root or `sudo` privileges on the Snort host to modify configuration files and restart the service.
- Read permissions for the Elastic Agent to access the Snort log directory, for example, `/var/log/snort/`.
- Network connectivity that allows the Snort host to reach the Elastic Agent over the configured UDP port (the default is `9514`) if you're using the UDP/Syslog method.
- Connectivity between the Elastic Agent and the Elasticsearch cluster to ship collected data.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the syslog or log file receiver and ship the data to Elastic, where the events will then be processed using the integration's ingest pipelines.

### Set up steps in Snort

You'll need to configure Snort to output logs in a format that the agent can read. We recommend using JSON for Snort 3.

#### For Snort 3 (Lua configuration)

Follow these steps to configure Snort 3 using Lua:
1. Open the `snort.lua` configuration file, typically located at `/usr/local/etc/snort/snort.lua` or `/etc/snort/snort.lua`.
2. To output high-fidelity logs for the Elastic Agent, add the following JSON logging block:
   ```lua
   alert_json = {
       file = true,
       fields = 'timestamp pkt_num proto pkt_gen pkt_len dir src_addr src_port dst_addr dst_port service rule action class b64_data',
       limit = 100
   }
   ```
3. Alternatively, for the Alert Fast format, add this block:
   ```lua
   alert_fast = {
       file = true,
       packet = false,
       limit = 100
   }
   ```
4. If you're forwarding using UDP, add this syslog block:
   ```lua
   alert_syslog = {
       facility = 'local5',
       level = 'alert'
   }
   ```
5. Validate the configuration by running `snort -c /usr/local/etc/snort/snort.lua -T`. If it's successful, restart Snort using `sudo systemctl restart snort`.

#### For Snort 2.9 (Classic configuration)

Follow these steps to configure Snort 2.9:
1. Open the `snort.conf` file, usually found at `/etc/snort/snort.conf`.
2. Locate the output section and uncomment or add the following line to enable Alert Fast:
   ```conf
   output alert_fast: alert.fast
   ```
3. To send alerts to a local syslog facility for forwarding, add this line:
   ```conf
   output alert_syslog: LOG_LOCAL5 LOG_ALERT
   ```
4. Apply the changes by running `sudo service snort restart` or `sudo systemctl restart snort`.

#### For syslog forwarding (UDP)

If you're using the UDP input, follow these steps to forward logs using Rsyslog:
1. Create a configuration file at `/etc/rsyslog.d/50-snort.conf`.
2. Add the following line to forward the `local5` facility to the Elastic Agent (replace `<ELASTIC_AGENT_IP_ADDRESS>` with your actual value):
   ```text
   local5.* @<ELASTIC_AGENT_IP_ADDRESS>:9514
   ```
3. Restart the rsyslog daemon to apply the forwarding rule: `sudo systemctl restart rsyslog`.

#### Vendor resources

You can find more details in the official documentation:
- [Alert Logging - Snort 3 Rule Writing Guide](https://docs.snort.org/start/alert_logging)
- [Configuration - Snort 3 Rule Writing Guide](https://docs.snort.org/start/configuration)

### Set up steps in Kibana

Follow these steps to set up the integration in Kibana:
1. In Kibana, navigate to **Management > Integrations**.
2. Search for "Snort" and select the integration.
3. Click **Add Snort**.
4. Configure the integration by selecting an input type and providing the necessary settings.

#### Collect Snort logs (input: logfile)

This input collects logs directly from file paths on your host. Configure the following settings:
- `paths`: The list of paths to Snort log files (for example, `['/var/log/snort/alert.log']`).
- `multiline_full`: Set to `true` if you're reading the Snort "Alert Full" log format which spans multiple lines. Default is `false`.
- `internal_networks`: Specify the internal IP subnet(s) of your network (for example, `['10.0.0.0/8']`). Default is `['private']`.
- `tz_offset`: Set the timezone offset (for example, `"Europe/Amsterdam"`, `"EST"`, or `"-05:00"`) if logs are from a different timezone than the host. Default is `local`.
- `preserve_original_event`: If enabled, the raw copy of the original event's added to the field `event.original`. Default is `false`.
- `tags`: Custom tags to add to the events. Default is `['forwarded', 'snort.log']`.
- `processors`: Add optional processors to filter or enhance data before it leaves the agent.

#### Collect Snort logs (input: udp)

This input collects logs sent over the network using UDP. Configure the following settings:
- `syslog_host`: The interface address to listen on for UDP traffic (for example, `localhost`).
- `syslog_port`: The UDP port to listen on (for example, `9514`).
- `internal_networks`: Specify the internal IP subnet(s) of your network. Default is `['private']`.
- `tz_offset`: Set the timezone offset for correct datetime parsing. Default is `local`.
- `preserve_original_event`: If enabled, preserves the raw original event in `event.original`. Default is `false`.
- `tags`: Custom tags to add to the events. Default is `['forwarded', 'snort.log']`.
- `udp_options`: Specify custom configuration options like `read_buffer`, `max_message_size`, or `timeout`.
- `processors`: Add optional processors to enhance or reduce fields in the exported event.

After configuring the input, click **Save and continue** to deploy the integration to your Elastic Agent policy.

### Validation

Follow these steps to verify that data's flowing correctly:

1. Trigger data flow on Snort using one of these methods:
   - **Generate Test Alert**: Use a tool like `curl` to access a known malicious URI if you've rules for it, or use `nmap` to perform a basic scan against the interface Snort's monitoring.
   - **Trigger ICMP Alert**: If ICMP rules are active, perform a ping sweep or a large packet ping: `ping -s 1500 <target_ip>`.
   - **Manual Log Entry**: For testing the logfile input, append a test entry to the monitored file:
     ```bash
     echo "01/01-12:00:00.000000 [**] [1:1000001:1] TEST ALERT [**] [Priority: 0] {TCP} 192.168.1.1:12345 -> 192.168.1.2:80" >> /var/log/snort/alert.log
     ```

2. Check for data in Kibana:
   1. Navigate to **Analytics > Discover**.
   2. Select the `logs-*` data view.
   3. Enter the KQL filter: `data_stream.dataset : "snort.log"`.
   4. Verify logs appear. Expand a log entry and confirm these fields:
      - `event.dataset` (should be `snort.log`)
      - `source.ip` and/or `destination.ip`
      - `event.action`, `event.outcome`, or `event.type`

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Common configuration issues

The following issues are commonly encountered when configuring or running the Snort integration:

- Snort fails to start due to configuration errors:
    * Run Snort in test mode to identify and resolve issues:
      ```bash
      # Replace /path/to/snort.conf with your actual configuration file path
      snort -T -c /path/to/snort.conf
      ```
- No alerts are being generated:
    * Verify that Snort is monitoring the correct network interface.
    * Ensure the relevant rules are enabled in your `snort.conf` or `snort.lua` file.
- Logs are not appearing when using the logfile input:
    * Ensure the Elastic Agent user has read access to the Snort log directory (for example, `/var/log/snort/`). You can grant permissions with the following command:
      ```bash
      sudo chmod -R +r /var/log/snort/
      ```
- UDP input port binding conflicts:
    * If the Elastic Agent fails to start when using the UDP input, check if another service is already using port 9514:
      ```bash
      # Check for services listening on port 9514
      netstat -tulpn | grep 9514
      ```
- Snort output is disabled:
    * Confirm that the `output` directive in `snort.conf` or the `alert_` module in `snort.lua` is correctly configured and not commented out, as some installations do not enable disk logging by default.
- Logs appear in Kibana but are not parsed correctly:
    * Check for the `tags: _grokparsefailure` tag in Discover.
    * Verify that the Snort log format (such as Alert Fast or JSON) matches the configuration you selected in the integration settings.
- Events display incorrect timestamps:
    * Verify the `tz_offset` setting in your integration configuration. This is often necessary if the Snort sensor is in a different timezone than the host or the Elastic Stack.

## Performance and scaling

To ensure optimal performance in high-volume environments, consider the following:

- For network-based collection using the `udp` input, ensure the network path between Snort and the Elastic Agent has sufficient bandwidth and low latency. While UDP offers high performance for syslog transmission, it doesn't guarantee delivery. In environments where log reliability is critical, it's recommended to use the `logfile` input with an Elastic Agent installed locally on the Snort host to read directly from the disk.
- To manage high volumes of log data and reduce processing overhead, use Snort's internal `threshold` and `suppression` configuration to limit the number of alerts generated by noisy rules. Additionally, ensure that only necessary log formats (for example, `JSON` or `Fast`) are enabled at the source to prevent redundant data ingestion and storage.

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Inputs used

{{inputDocs}}

### Vendor documentation links

The following external resources provide more information about Snort:
- [Official Snort Documentation](https://docs.snort.org/welcome)
- [Snort FAQ](https://snort.org/faq)
- [Alert Logging - Snort 3 Rule Writing Guide](https://docs.snort.org/start/alert_logging)
- [Configuration - Snort 3 Rule Writing Guide](https://docs.snort.org/start/configuration)

### Data streams

#### log

The `log` data stream collects all log types from Snort. This includes intrusion detection logs, network metadata, and various alert formats such as JSON, CSV, and Alert Fast.

##### log fields

{{fields "log"}}

##### log sample event

{{event "log"}}
