# Cisco ASA Integration for Elastic

> **Note**: This documentation was generated using AI and should be reviewed for accuracy.

## Overview

The Cisco ASA integration for Elastic enables you to collect logs from Cisco Adaptive Security Appliance (ASA) hardware and virtual appliances. By ingesting these logs into the Elastic Stack, you can gain visibility into network traffic, monitor security events, and audit administrative actions.

This integration facilitates:
- Security monitoring and threat detection: You can monitor firewall logs to identify denied connection attempts, potential scanning activity, and known attack patterns.
- Compliance auditing: You'll maintain a historical record of administrative access, configuration changes, and security policy enforcement for regulatory requirements.
- Network troubleshooting: You can use detailed connection logs to diagnose connectivity issues, verify NAT translations, and analyze traffic flow patterns across different security zones.
- Operational visibility: You'll track VPN session activity, including user logins and session durations, to monitor remote access usage and performance.

### Compatibility

This integration is compatible with Cisco ASA hardware and virtual appliances. It supports logs delivered using syslog (RFC 3164 or RFC 5424) or read from local files. It works with standard Cisco ASA syslog formats as documented in the 9.x configuration guides.

This integration is compatible with Elastic Stack version 8.11.0 or higher.

### How it works

This integration collects data from Cisco ASA devices by receiving syslog messages over the network using `tcp` or `udp`, or by reading from local log files. You deploy an Elastic Agent on a host that is configured as a syslog receiver or has access to the log files. The agent processes the incoming logs, parses them into ECS-compatible fields using the `log` data stream, and sends them to your Elastic deployment where you can monitor or analyze them.

## What data does this integration collect?

The Cisco ASA integration collects several categories of security and operational data from Cisco ASA devices through the `log` data stream. You can collect these logs using network protocols like TCP or UDP, or by reading them from local files.

The integration collects the following types of logs:
- Firewall logs: Connection establishment and teardown events, access-list (ACL) hits, and protocol-specific inspection logs.
- Security events: Threat detection events as well as authentication successes and failures.
- System logs: Resource utilization, configuration changes, and hardware health status.
- VPN logs: Remote access and site-to-site VPN connection details, including user authentication and tunnel duration.

### Supported use cases

Integrating Cisco ASA logs with Elastic provides enhanced visibility into your network security posture and operational health. You can use this integration for several key use cases:
- Security monitoring: Monitor firewall activity to detect unauthorized access attempts or suspicious traffic patterns.
- Threat detection: Leverage Elastic Security to identify potential threats based on Cisco ASA security events and threat detection logs.
- VPN auditing: Analyze VPN logs to track user access and session duration, and to troubleshoot connectivity issues for remote workers.
- Compliance and auditing: Maintain a searchable, long-term archive of firewall logs to meet regulatory compliance requirements and support security audits.
- Operational health: Track system resources and hardware status to proactively manage your Cisco ASA infrastructure.

## What do I need to use this integration?

To use this integration, you must have the following Cisco ASA prerequisites:
- High-level administrative access (Enable mode or Level 15) to the Cisco ASA CLI or ASDM GUI to configure logging settings.
- Unrestricted network paths between the Cisco ASA and the Elastic Agent host over the chosen protocol (UDP or TCP) and port (the default is `9001`).
- Identification of the specific ASA interface, such as `inside`, `management`, or `outside`, that you'll use to route syslog traffic to the Elastic Agent.
- Sufficient CPU and memory resources on the ASA device to handle additional logging overhead during peak traffic periods.

You also need to meet these Elastic prerequisites:
- An Elastic Agent must be installed on a host and enrolled in a policy using Fleet.
- Access to Kibana's Fleet and Integrations UI to configure the Cisco ASA integration settings.
- Connectivity ensuring the Elastic Agent host is listening on the configured port and is reachable by the Cisco ASA's logging interface.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the syslog or log file receiver and ship the data to Elastic, where the events will then be processed using the integration's ingest pipelines.

### Set up steps in Cisco ASA

You can configure Cisco ASA to send logs to the Elastic Agent using either the ASDM (GUI) or the CLI.

#### For syslog collection via ASDM (GUI)

1. Log in to the Cisco ASDM console for your ASA device.
2. Navigate to `Configuration > Device Management > Logging > Logging Setup`.
3. Check the box for `Enable logging` and click `Apply`.
4. Navigate to `Configuration > Device Management > Logging > Syslog Server`.
5. Click `Add` to configure the Elastic Agent as a destination:
    - `Interface`: Select the interface that can reach the Elastic Agent (for example, `inside`).
    - `IP Address`: Enter the IP address of the host where the Elastic Agent is installed.
    - `Protocol`: Select `UDP` or `TCP` to match your integration input.
    - `Port`: Enter the port number (for example, `9001`) (replace with your actual value).
    - Click `OK`.
6. Navigate to `Configuration > Device Management > Logging > Logging Filters`.
7. Select `Syslog Servers` and click `Edit`. Select `Filter on severity` and choose `Informational` (or your preferred level).
8. Click `OK` and then `Apply` to save the changes to the running configuration.

#### For syslog collection via CLI

1. Log in to the Cisco ASA using SSH or a console cable.
2. Enter global configuration mode:
   ```bash
   conf t
   ```
3. Enable the logging subsystem:
   ```bash
   logging enable
   ```
4. Define the Elastic Agent host destination (for example, using UDP on port 9001):
   ```bash
   logging host inside 192.168.1.50 udp/9001
   ```
   (replace `192.168.1.50` and `9001` with your actual value)
5. Set the severity level for logs sent to the agent:
   ```bash
   logging trap informational
   ```
6. (Optional) Enable timestamps for better event correlation:
   ```bash
   logging timestamp
   ```
7. Exit and save the configuration:
   ```bash
   write mem
   ```

#### Vendor resources

This section provides links to official Cisco documentation for further reference:
- [Cisco ASA 9.23 CLI Configuration Guide - Logging](https://www.cisco.com/c/en/us/td/docs/security/asa/asa923/configuration/general/asa-923-general-config/monitor-syslog.html)
- [Cisco ASA ASDM 7.20 Configuration Guide - Logging](https://www.cisco.com/c/en/us/td/docs/security/asa/asa920/asdm720/general/asdm-720-general-config/monitor-syslog.html)

### Set up steps in Kibana

To set up the integration in Kibana, perform the following:
1. In Kibana, navigate to `Management > Integrations`.
2. Search for `Cisco ASA` and select the integration.
3. Click `Add Cisco ASA`.
4. Configure the integration by selecting an input type and providing the necessary settings. This integration supports `TCP`, `UDP`, and `Log file` inputs.

Choose the setup instructions below that match your configuration.

#### Collecting logs from Cisco ASA via TCP

This input collects logs over a TCP socket.
1. Select the `Collecting logs from Cisco ASA via TCP` input type.
2. Configure the following fields:
    - `Listen Address` (`tcp_host`): The bind address to listen for TCP connections. Set to `0.0.0.0` (replace with your actual value) to bind to all available interfaces. Default: `localhost`.
    - `Listen Port` (`tcp_port`): The TCP port number to listen on. Default: `9001`.
    - `Preserve original event` (`preserve_original_event`): Preserves a raw copy of the original event, added to the field `event.original`. Default: `false`.
    - `Preserve searchable message text` (`keep_message`): Preserves the log message in a searchable field, `cisco.asa.full_message`. Default: `false`.
    - `Tags` (`tags`): Custom tags for the events. Default: `['cisco-asa', 'forwarded']`.
    - `Internal Zones` (`internal_zones`): Define internal network zones.
    - `External Zones` (`external_zones`): Define external network zones.
    - `Processors` (`processors`): Add custom processors to enhance or reduce event fields. This executes in the agent before the logs are parsed.
    - `SSL Configuration` (`ssl`): Configure SSL options for encrypted communication. See the [SSL documentation](https://www.elastic.co/guide/en/beats/filebeat/current/configuration-ssl.html#ssl-common-config) for details.
    - `Custom TCP Options` (`tcp_options`): Specify custom configuration options like `max_connections` or `line_delimiter`.
    - `Default Time Zone` (`tz_offset`): IANA time zone or time offset (for example `+0200`) (replace with your actual value) to use when interpreting syslog timestamps without a time zone. Default: `UTC`.
    - `Time Zone Map` (`tz_map`): A mapping of time zones as they appear in the Cisco ASA log mapped to a proper IANA time zone or offset.
3. Save the integration and add it to an agent policy.

#### Collecting logs from Cisco ASA via UDP

This input collects logs over a UDP socket.
1. Select the `Collecting logs from Cisco ASA via UDP` input type.
2. Configure the following fields:
    - `Listen Address` (`udp_host`): The bind address to listen for UDP connections. Set to `0.0.0.0` (replace with your actual value) to bind to all available interfaces. Default: `localhost`.
    - `Listen Port` (`udp_port`): The UDP port number to listen on. Default: `9001`.
    - `Preserve original event` (`preserve_original_event`): Preserves a raw copy of the original event in the field `event.original`. Default: `false`.
    - `Preserve searchable message text` (`keep_message`): Preserves the log message in a searchable field, `cisco.asa.full_message`. Default: `false`.
    - `Tags` (`tags`): Custom tags for filtering. Default: `['cisco-asa', 'forwarded']`.
    - `Internal Zones` (`internal_zones`): Specify internal interface names.
    - `External Zones` (`external_zones`): Specify external interface names.
    - `Custom UDP Options` (`udp_options`): Specify custom configuration options like `read_buffer`, `max_message_size`, or `timeout`.
    - `Processors` (`processors`): Metadata enhancement options that execute in the agent before parsing.
    - `Default Time Zone` (`tz_offset`): IANA time zone for timestamp interpretation. Default: `UTC`.
    - `Time Zone Map` (`tz_map`): Mapping for custom time zone strings as they appear in the ASA log.
3. Save the integration and add it to an agent policy.

#### Collecting logs from Cisco ASA via file

This input collects logs directly from log files on the host where the Elastic Agent is running.
1. Select the `Collecting logs from Cisco ASA via file` input type.
2. Configure the following fields:
    - `Paths` (`paths`): List of specific file paths to monitor (for example, `/var/log/cisco-asa.log`).
    - `Preserve original event` (`preserve_original_event`): Includes `event.original` in the output. Default: `false`.
    - `Preserve searchable message text` (`keep_message`): Preserves the log message in a searchable field, `cisco.asa.full_message`. Default: `false`.
    - `Internal Zones` (`internal_zones`): List of trusted zones. Default: `['trust']`.
    - `External Zones` (`external_zones`): List of untrusted zones. Default: `['untrust']`.
    - `Tags` (`tags`): Identification tags. Default: `['cisco-asa', 'forwarded']`.
    - `Processors` (`processors`): Agent-side processing rules for metadata.
    - `Default Time Zone` (`tz_offset`): IANA time zone or offset. Default: `UTC`.
    - `Time Zone Map` (`tz_map`): Mapping for ASA-specific time zone abbreviations.
3. Save the integration and add it to an agent policy.

### Validation

Follow these steps to verify that the integration is working properly and data is flowing into Elasticsearch:

1. Verify the status of the Elastic Agent:
    - Navigate to `Management > Fleet > Agents`.
    - Ensure the Elastic Agent assigned to the Cisco ASA policy is in a `Healthy` status.
2. Trigger data flow on the Cisco ASA device:
    - `Configuration change`: Enter and exit config mode on the ASA CLI using `conf t` then `exit`. This generates a configuration change event.
    - `Authentication event`: Log out and log back into the ASDM GUI or SSH session to trigger authentication logs.
    - `Security event`: Attempt to reach a service blocked by an Access Control List (ACL) to generate a "Deny" syslog message.
3. Check the data in Kibana:
    - Navigate to `Discover`.
    - Select the `logs-*` data view.
    - Enter the KQL filter: `data_stream.dataset : "cisco_asa.log"`.
    - Verify that logs appear in the timeline with recent timestamps.
    - Expand a log entry and confirm that fields like `event.dataset`, `source.ip`, `destination.ip`, and `message` are present and accurate.
4. View the dashboard:
    - Navigate to `Management > Dashboards`.
    - Search for `Cisco ASA` and select the overview dashboard to verify that visualizations are populated with data.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Common configuration issues

You can resolve common configuration and ingestion issues by checking the following:

- Port binding conflicts: If the Elastic Agent fails to start the input, check if another process is already using the configured port, such as `9001` (replace with your actual port). You can identify port usage on Linux by running `netstat -tulpn`.
- Network firewalls: Ensure that any intermediate firewalls or host-based firewalls, like `iptables` or `firewalld`, are configured to allow traffic from the Cisco ASA's IP to the Elastic Agent's port and protocol.
- Incorrect interface routing: On the Cisco ASA, verify that the `logging host` command specifies the correct interface that has a route to the Elastic Agent. The ASA can't send logs if it can't reach the destination IP via the specified interface.
- Logging level too low: If you aren't seeing expected events, verify that `logging trap` is set to at least `informational` (level 6). If it's set to `emergencies` or `critical`, most traffic logs will be ignored.
- Timestamp parsing failures: If logs appear with the wrong time, verify the `tz_offset` and `tz_map` settings in the integration. Cisco ASA logs often omit time zone offsets, leading to UTC interpretation by default.
- Message format mismatches: Ensure you've enabled `logging timestamp` on the ASA. Without timestamps, the integration may struggle to parse the start of the syslog header correctly.
- Field mapping issues: Check the `error.message` field in Discover. If the ASA is sending non-standard or highly customized syslog formats, the agent might fail to map specific fields, resulting in tags like `_grokparsefailure`.

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

To ensure you get the best performance in high-volume environments, consider the following:

- Transport considerations: For high-volume environments, you'll want to use `TCP` to ensure reliable delivery of log events. `UDP` offers lower overhead and is suitable for environments where occasional log loss is acceptable in exchange for higher performance and reduced state tracking on the firewall.
- Data volume management: To manage the volume of data sent to the Elastic Agent, you'll configure the `logging trap` level on the Cisco ASA. Setting the level to `informational` (level 6) captures most relevant connection data, while setting it to `notice` or `warning` can significantly reduce volume by filtering out routine connection build/teardown events.
- Elastic Agent scaling: For high-throughput environments, you can deploy multiple Elastic Agents behind a network load balancer to distribute traffic evenly. You'll want to place agents close to the data source to minimize latency. A single Elastic Agent can handle several thousand events per second depending on your hardware.

## Reference

### Inputs used

{{ inputDocs }}


### Vendor documentation links

You can refer to the following official resource for more information about your device's logging capabilities:
- [Cisco ASA Official Support Documentation](https://www.cisco.com/c/en/us/support/security/adaptive-security-appliance-asa-software/series.html)

### Data streams

#### log

The `log` data stream provides events from your Cisco ASA devices. It'll collect and process logs of the following types:
- System messages
- Connection and traffic logs
- Security and firewall events

##### log fields

{{ fields "log" }}

##### log sample event

{{ event "log" }}