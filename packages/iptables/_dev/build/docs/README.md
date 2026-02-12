# Iptables Integration for Elastic

## Overview
The Iptables integration for Elastic enables you to collect and analyze logs from `iptables` and `ip6tables` running on Linux distributions and Ubiquiti networking equipment. It's designed to provide deep visibility into network traffic filtered by kernel firewalls, which helps you monitor allowed and denied connections across your infrastructure.

### Compatibility
The `iptables` integration is compatible with the following:
- `iptables` and `ip6tables` logs from Linux distributions.
- Ubiquiti firewalls that support remote syslog forwarding.
- `systemd` `journald` for local log collection.

This integration requires Kibana version 8.11.0 or higher.

### How it works
This integration collects logs from your firewall using three primary methods:
- It can receive `iptables` logs over the network using the `udp` input, which is intended for logs forwarded from remote Linux hosts or Ubiquiti devices.
- It can read logs directly from the local filesystem using the `logfile` input, typically from paths like `/var/log/iptables.log` on the host where the firewall rules are active.
- It can query the local systemd journal for firewall-related events using the `journald` input.

Once you've deployed an Elastic Agent on a host with access to these log sources, it'll forward the parsed events to your Elastic deployment, where they're available for monitoring and analysis.

## What data does this integration collect?

The Iptables integration collects log messages from:
*   Local log files: Records read from the host filesystem using the `log` data stream.
*   Syslog network logs: Firewall events forwarded over the network via UDP using the `udp` data stream.
*   Systemd journal events: Log messages retrieved directly from the systemd journal using the `journald` data stream.

### Supported use cases

Integrating Iptables logs with the Elastic Stack provides visibility into your network security and host-level traffic filtering. You'll find this integration useful for the following use cases:
*   Security monitoring: You can track dropped or rejected connection attempts to identify potential scanning activity, brute-force attacks, or unauthorized access attempts.
*   Network auditing: You can analyze allowed traffic patterns to verify that your firewall policies align with security requirements and to identify unexpected network behavior.
*   Compliance: You can maintain a searchable history of firewall activity to meet regulatory requirements for network logging and auditing.
*   Incident response: You'll be able to correlate firewall events with other security data in Elastic to investigate the source and scope of network-based threats.
*   Connectivity troubleshooting: You can identify if specific firewall rules are blocking legitimate application traffic, helping you tune your rulesets without compromising security.

## What do I need to use this integration?

To use the Iptables integration, you must ensure your environment meets the following vendor and Elastic prerequisites.

### Vendor prerequisites

Before you install the integration, ensure your environment is configured correctly:
- Root or sudo permissions are required on the Linux host to modify `iptables` rules and `rsyslog` configurations.
- The `LOG` target must be added to `iptables` chains to enable logging.
- SSH or console access to the Ubiquiti device is required to configure remote syslog destinations.
- The `journalctl` binary must be available on the host if you're using the Journald input method.

### Elastic prerequisites

Your Elastic Stack environment must meet these requirements:
- An active Elastic Agent must be enrolled in Fleet and running on a supported Linux host or container.
- If you're running the Agent in a container and using the Journald input, you must use the `elastic-agent-complete` image variant to provide the necessary `journalctl` dependencies.
- The Agent must have outbound connectivity to Elasticsearch and Kibana for data delivery and management.

## How do I deploy this integration?

### Agent-based deployment

You must install the Elastic Agent on a host that can receive the syslog data or has access to the log files from the `iptables` instance. You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the syslog or log file receiver and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Set up steps in Iptables

You can configure `iptables` to send logs to the Elastic Agent using the following methods.

#### Standard Linux iptables (syslog forwarding)

To forward logs using `rsyslog`, follow these steps:

1. Add logging rules: Identify the chain you want to monitor and append a rule with the `LOG` target. Ensure this rule is positioned before any `DROP` or `REJECT` rules.
   ```bash
   sudo iptables -I INPUT -j LOG --log-prefix "IPTABLES: "
   ```
2. Configure `rsyslog`: Create a new configuration file in `/etc/rsyslog.d/` (for example, `10-iptables.conf`).
3. Define filter and destination: Add the following line to forward logs to the Elastic Agent (replace `<ELASTIC_AGENT_IP>` with your actual IP address):
   ```text
   :msg, startswith, "IPTABLES" @<ELASTIC_AGENT_IP>:9001
   ```
4. Optional log suppression: To prevent these logs from filling local system logs, add a stop directive on the next line. The syntax varies by `rsyslog` version.
5. Restart service: Apply changes by restarting `rsyslog`:
   ```bash
   sudo systemctl restart rsyslog
   ```

#### Ubiquiti EdgeOS

To configure a Ubiquiti device, follow these steps:

1. Access CLI: Connect to your Ubiquiti device via SSH.
2. Enter config mode: Type `configure`.
3. Set syslog host: Direct logs to the Elastic Agent host on port `9001` (replace `<ELASTIC_AGENT_IP>` with your actual IP address).
   ```bash
   set system syslog host <ELASTIC_AGENT_IP> port 9001
   ```
4. Enable rule logging: Enable logging on the specific firewall rules you want to monitor.
   ```bash
   set firewall name <RULESET_NAME> rule <RULE_NUMBER> log enable
   ```
5. Commit changes: Type `commit` then `save` to persist the configuration.

### Set up steps in Kibana

To set up the integration in Kibana, follow these steps:

1. In Kibana, navigate to **Management > Integrations** and search for **Iptables**.
2. Click **Add Iptables**.
3. Configure the integration by selecting one or more of the supported input types below.

#### Collecting application logs from iptables instances (input: udp)

This input collects logs over a UDP socket. Configure the following settings:

- Syslog host (`syslog_host`): The interface to listen to UDP based syslog traffic. Default is `localhost`. Set this to `0.0.0.0` to bind to all available interfaces.
- Syslog port (`syslog_port`): The UDP port to listen for syslog traffic. Default is `9001`.
- Preserve original event (`preserve_original_event`): If enabled, a raw copy of the original event is added to the field `event.original`. Default is `False`.
- Tags (`tags`): List of tags to append to the event. Default is `['iptables-log', 'forwarded']`.
- Custom UDP options (`udp_options`): Specify custom configuration such as `read_buffer` or `max_message_size`.
- Processors (`processors`): Add custom processors to reduce fields or enhance metadata before the logs are parsed.

#### Collecting application logs from iptables instances (input: logfile)

This input collects logs directly from log files. Configure the following settings:

- Paths (`paths`): Provide a list of paths to the `iptables` log files. Default is `['/var/log/iptables.log']`.
- Preserve original event (`preserve_original_event`): If enabled, preserves a raw copy of the original event in `event.original`. Default is `False`.
- Tags (`tags`): List of tags to append to the log events. Default is `['iptables-log', 'forwarded']`.
- Processors (`processors`): Define optional processors for filtering or data enhancement.

#### Collecting application logs from iptables instances (input: journald)

This input collects logs from the system journal. Configure the following settings:

- Journal paths (`paths`): List of journal directories or files to read from. Defaults to the system journal if you leave it empty.
- Tags (`tags`): List of tags to append to the journal logs. Default is `['iptables-log']`.
- Processors (`processors`): Define optional processors for metadata enrichment.

After you have configured the inputs, save the integration to an Elastic Agent policy.

### Validation

To verify that data is flowing correctly, follow these steps.

#### 1. Trigger data flow on Iptables

Perform these actions to generate test data:

- Add a test rule: On the Linux host, add a temporary rule to log ICMP traffic: `sudo iptables -I INPUT -p icmp -j LOG --log-prefix "IPTABLES_TEST: "`
- Generate traffic: From another machine, ping the Linux host to trigger the logging rule.
- Check local logs: Verify the log exists locally by running `dmesg | grep IPTABLES_TEST` or checking the log file specified in your configuration.
- Remove the test rule: Once verified, remove the test rule using: `sudo iptables -D INPUT -p icmp -j LOG --log-prefix "IPTABLES_TEST: "`

#### 2. Check data in Kibana

Verify the data in Kibana by following these steps:

1. Navigate to **Discover**.
2. Select the `logs-*` data view.
3. Enter the KQL filter: `data_stream.dataset : "iptables.log"`
4. Verify that logs appear. Expand a log entry and confirm fields are populated such as:
   - `event.dataset`
   - `source.ip`
   - `event.action`
   - `message`
5. Navigate to **Dashboards** and search for "Iptables" to view pre-built visualizations.

## Troubleshooting

If you're having trouble collecting logs from your iptables firewall or Ubiquiti device, you can use the following troubleshooting steps to identify and resolve common problems.

### Common configuration issues

If you're not seeing logs in Kibana or the integration isn't starting correctly, check these common issues:
- No data is being collected: Verify that the `LOG` target is added to your iptables chains using rules like `sudo iptables -I INPUT -j LOG --log-prefix "IPTABLES: "`.
- Port conflict: If the UDP input fails to start, check that port `9001` isn't already in use. You can use commands like `ss -lnup | grep 9001` or `netstat -an` to check port usage.
- Rsyslog filter mismatch: Ensure that the `--log-prefix` string in your iptables rules (for example, `IPTABLES: `) matches the filter string in your rsyslog configuration.
- Network reachability: If forwarding logs from a Ubiquiti device, confirm it can reach the Elastic Agent host and that UDP traffic on port `9001` is not blocked.
- Journald compatibility: When running the agent in a Docker container, use the `elastic-agent-complete` image variant which includes the `journalctl` binary.
- Permission denied: For log file collection, verify that the Elastic Agent user has read permissions for the specified file paths.
- Unparsed log messages: If logs appear in Discover but aren't parsed into fields like `source.ip` or `event.action`, check the `error.message` field for parsing failure details.
- UDP data loss: In high-volume environments, you might experience dropped UDP packets. Consider adjusting Custom UDP Options such as increasing the `read_buffer`.

## Performance and scaling

To ensure you get the best performance from your Iptables integration in high-volume environments, consider the following strategies:

- Transport and collection: The `udp` input does not guarantee delivery. For critical environments, consider using the `logfile` input or the `journald` input. If using UDP, you can adjust options like `read_buffer` and `max_message_size` to handle traffic spikes.
- Data volume management: Configure your `iptables` rules to forward only the events you need. Use the `--limit` flag in `iptables` to throttle log generation for noisy rules.
- Elastic Agent scaling: For high-throughput environments, you can deploy multiple Elastic Agents behind a network load balancer to distribute UDP syslog traffic.

## Reference

### Inputs used

{{ inputDocs }}

### Data streams

#### log

The `log` data stream provides events from Iptables of the following types: packet filter logs containing information about network traffic processed by the firewall.

##### log fields

{{ fields "log" }}

##### log sample event

{{ event "log" }}

### Vendor documentation links

You can find more information about Iptables in the following resources:
* [Iptables project documentation](https://www.netfilter.org/documentation/index.html)
* [Rsyslog documentation](https://www.rsyslog.com/doc/index.html)
