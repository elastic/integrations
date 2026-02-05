# Service Info

The Juniper SRX integration allows you to ingest logs from Juniper Networks SRX Series Firewalls into the Elastic Stack. This integration provides visibility into network traffic, security events, and system performance by parsing JunOS structured-data logs.

## Common use cases

The Juniper SRX integration is designed to provide comprehensive visibility into the security and operational status of Juniper SRX Series Firewalls by ingesting various log types into the Elastic Stack.
- **Security Monitoring and Threat Detection:** Monitor `RT_IDS` and `RT_IDP` logs to identify and respond to network-based attacks, including TCP, UDP, ICMP, and IP-based screen events or sophisticated intrusion attempts.
- **Traffic Analysis and Session Tracking:** Utilize `RT_FLOW` and `AppTrack` logs to gain deep insights into network traffic patterns, session creations, closures, and denied attempts for audit and capacity planning.
- **Web and Content Security:** Track user activity and security efficacy using `RT_UTM` and `RT_AAMW` logs, which capture web filtering results, antivirus detections, and advanced anti-malware actions like infected host identification.
- **Security Intelligence Orchestration:** Monitor `RT_SECINTEL` logs to verify the effectiveness of automated security intelligence feeds and the specific actions taken against malicious IP addresses or domains.

## Data types collected

This integration can collect the following types of data:
- **Firewall Session Logs:** Information on session creation, closing, and denials (`RT_FLOW`).
- **Intrusion Detection/Prevention Logs:** Security screen events and attack log events (`RT_IDS`, `RT_IDP`).
- **Unified Threat Management (UTM) Logs:** Web filtering, Antivirus, and Antispam detection events (`RT_UTM`).
- **Advanced Anti-Malware Logs:** Malware action logs and host infection events (`RT_AAMW`).
- **Security Intelligence Logs:** Logs related to security intelligence actions (`RT_SECINTEL`).
- **Juniper SRX logs (logs):** Captures all the security and system processes mentioned above in structured-data format.

## Compatibility

This integration is compatible with **Juniper SRX Series Firewalls** running JunOS versions that support structured-data logging. The device must be capable of generating syslog messages in the `structured-data` + `brief` format for successful parsing.

## Scaling and Performance

To ensure optimal performance in high-volume environments, consider the following:
- **Data Volume Management:** Configure the Juniper SRX appliance to forward only necessary events (e.g., RT_FLOW or RT_IDS) using JunOS syslog facility and severity filters. Avoid forwarding excessive debug-level logs at the source to prevent overwhelming the ingest pipeline.
- **Elastic Agent Scaling:** For high-throughput environments, deploy multiple Elastic Agents behind a network load balancer to distribute the ingestion load. Placing Agents in close network proximity to the SRX devices reduces latency and minimizes the impact of network congestion on log delivery.

# Set Up Instructions

## Vendor prerequisites

- Administrative access to the Juniper SRX CLI (SSH or console) to perform configuration changes.
- Network connectivity between the Juniper SRX management or data interfaces and the Elastic Agent host.
- Proper firewall rules in place to allow traffic on the configured syslog port (default is `9006` for this integration).
- The SRX device must be running a JunOS version that supports `structured-data` syslog formatting.

## Elastic prerequisites

- Elastic Agent must be installed and enrolled in Fleet or running in standalone mode.
- The Juniper SRX integration package (version 1.26.0 or higher) must be installed in Kibana.
- Network access must be available for the Agent to receive inbound syslog traffic on the specified port.

## Vendor set up steps

### For Syslog (UDP or TCP) Collection:
1. Log in to the Juniper SRX device via SSH or the console port.
2. Enter configuration mode by typing `configure`.
3. Set the remote syslog destination to the IP address of your Elastic Agent. Replace `<AGENT_IP>` with your agent's IP and `<PORT>` with your configured port (e.g., `9006`).
   ```bash
   set system syslog host <AGENT_IP> any any
   set system syslog host <AGENT_IP> port 9006
   ```
4. **Critical Step:** Configure the mandatory log format. This integration only supports the `structured-data` format with the `brief` option.
   ```bash
   set system syslog host <AGENT_IP> structured-data brief
   ```
5. Configure the security logging mode to `event` to ensure security logs are generated and sent to the syslog process.
   ```bash
   set security log mode event
   set security log format syslog
   ```
6. Verify the configuration by running `show system syslog`. Ensure the host entry includes the `structured-data { brief; }` block.
7. Commit the configuration changes by typing `commit`.

### For Logfile (Filestream) Collection:
1. Log in to the Juniper SRX device or the intermediate log host where logs are stored.
2. Configure the Juniper SRX to write logs to a file using the structured format:
   ```bash
   set system syslog file juniper-srx.log any any
   set system syslog file juniper-srx.log structured-data brief
   ```
3. Ensure the Elastic Agent has read permissions for the file (default path is `/var/log/juniper-srx.log`).
4. Commit the changes on the SRX device.

### Vendor Set up Resources
-[Junos CLI reference | structured-data](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/structured-data-edit-system.html)
- [Juniper Module | Filebeat Reference - Elastic](https://www.elastic.co/guide/en/beats/filebeat/8.19/filebeat-module-juniper.html)
- [Direct System Log Messages to a Remote Destination - Juniper Networks](https://www.juniper.net/documentation/us/en/software/junos/network-mgmt/topics/topic-map/directing-system-log-messages-to-a-remote-destination.html)
- [Example: Forward structured system syslog messages from SRX - Juniper Support](https://supportportal.juniper.net/s/article/JSA-STRM-SRX-Example-How-to-forward-structured-system-syslog-messages-from-SRX-to-JSA)

## Kibana set up steps

Enable and configure the input method which matches your Juniper configuration. Disable input types which will not be used.

### Collecting syslog from Juniper SRX via UDP.
1. In Kibana, navigate to **Integrations** and search for **Juniper SRX**.
2. Click **Add Juniper SRX**.
3. Locate the **Collecting syslog from Juniper SRX via UDP** input and configure the following variables:
   - **Syslog Host** (`syslog_host`): The address the agent listens on. Default: `localhost`.
   - **Syslog Port** (`syslog_port`): The UDP port to receive logs. Default: `9006`.
   - **Preserve original event** (`preserve_original_event`): If enabled, preserves a raw copy of the original event in `event.original`. Default: `False`.
   - **Tags** (`tags`): Custom tags to add to the events. Default: `['juniper-srx', 'forwarded']`.
   - **Custom UDP Options** (`udp_options`): Specify custom configuration options such as `read_buffer` (default `100MiB`), `max_message_size` (default `50KiB`), or `timeout` (default `300s`).
   - **Processors** (`processors`): Add processors to reduce fields or enhance metadata before parsing.
4. Save the integration to a new or existing Agent policy.

### Collecting syslog from Juniper SRX via TCP.
1. In Kibana, navigate to **Integrations** and search for **Juniper SRX**.
2. Click **Add Juniper SRX**.
3. Locate the **Collecting syslog from Juniper SRX via TCP** input and configure the following variables:
   - **Syslog Host** (`syslog_host`): The address the agent listens on. Default: `localhost`.
   - **Syslog Port** (`syslog_port`): The TCP port to receive logs. Default: `9006`.
   - **Preserve original event** (`preserve_original_event`): Preserves a raw copy of the original event in `event.original`. Default: `False`.
   - **Tags** (`tags`): Custom tags to categorize the data. Default: `['juniper-srx', 'forwarded']`.
   - **Processors** (`processors`): Define processors to enhance or filter events in the agent.
   - **SSL Configuration** (`ssl`): Configure SSL options such as `certificate` and `key`.
   - **Custom TCP Options** (`tcp_options`): Specify options like `max_connections` (default `1`), `framing` (default `delimiter`), or `line_delimiter` (default `\n`).
4. Save the integration to a new or existing Agent policy.

### Collecting syslog from Juniper SRX via file.
1. In Kibana, navigate to **Integrations** and search for **Juniper SRX**.
2. Click **Add Juniper SRX**.
3. Locate the **Collecting syslog from Juniper SRX via file** input and configure the following variables:
   - **Paths** (`paths`): The absolute paths to the log files. Default: `['/var/log/juniper-srx.log']`.
   - **Preserve original event** (`preserve_original_event`): Preserves a raw copy of the original event in `event.original`. Default: `False`.
   - **Tags** (`tags`): Custom tags to categorize the data. Default: `['juniper-srx', 'forwarded']`.
   - **Processors** (`processors`): Define processors to filter or enhance logs at the source.
4. Save the integration to a new or existing Agent policy.

# Validation Steps

After configuration is complete, verify that data is flowing correctly.

### 1. Trigger Data Flow on Juniper SRX:
- **Generate traffic events:** From a device behind the SRX firewall, attempt to browse a website or ping an external IP address that matches a security policy with logging enabled.
- **Generate configuration events:** Log into the SRX CLI, enter configuration mode using `configure`, make a small change (like adding a description to an interface), and run `commit`.
- **Generate authentication events:** Log out of the SRX CLI or J-Web interface and log back in to trigger authentication and system logs.

### 2. Check Data in Kibana:
1. Navigate to **Analytics > Discover**.
2. Select the `logs-*` data view.
3. Enter the KQL filter: `data_stream.dataset : "juniper_srx.log"`
4. Verify logs appear in the results. Expand a log entry and confirm these fields:
   - `event.dataset` (should match `juniper_srx.log`)
   - `source.ip` and/or `destination.ip`
   - `event.action` (e.g., `session-close` or `session-deny`)
   - `event.outcome`
5. Navigate to **Analytics > Dashboards** and search for "Juniper SRX" to view pre-built visualizations.

# Troubleshooting

## Common Configuration Issues

- **Missing Structured Data Format**: If logs are appearing in Kibana but are not being parsed correctly (remaining as a raw string in `message`), ensure that the `set system syslog host <IP> structured-data brief` command was committed. Without `structured-data`, the integration cannot identify the different log fields.
- **Security Logs Not Sent**: If system logs arrive but traffic/IDP logs (RT_FLOW, RT_IDS) are missing, verify that `set security log mode event` is configured. By default, SRX devices may try to send security logs via the data plane, which bypasses the system syslog settings.
- **Port Mismatch**: Ensure the port configured in the JunOS CLI (`set system syslog host <IP> port <PORT>`) matches the `syslog_port` defined in the Kibana integration settings.
- **Network Firewalls**: If no data is received, check for intermediate firewalls or Access Control Lists (ACLs) that may be blocking UDP/TCP port 9006 between the SRX management interface and the Elastic Agent.

## Ingestion Errors
- **Parsing Failures**: Check the `error.message` field in Kibana. If it contains "Provided Grok expressions do not match", it typically indicates the log is in a standard syslog format rather than the required `structured-data` format.
- **Incomplete Logs**: If logs are truncated, check the `max_message_size` in the UDP/TCP options. The default syslog size may need to be increased if the SRX is sending very large structured-data payloads.

## Vendor Resources
- [Juniper SRX Product Page](https://www.juniper.net/documentation/en_US/release-independent/junos/information-products/pathway-pages/srx-series/product/)
- [JunOS Documentation on Structured Data](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/structured-data-edit-system.html)
- [KB16502 - Configure System Logging](https://supportportal.juniper.net/s/article/SRX-Getting-Started-Configure-System-Logging)

# Documentation sites

- [Juniper SRX integration | Elastic integrations](https://www.elastic.co/docs/reference/integrations/juniper_srx) - Official Elastic documentation for this integration.
- [Juniper SRX Product Page](https://www.juniper.net/documentation/en_US/release-independent/junos/information-products/pathway-pages/srx-series/product/) - Juniper SRX Series information hub.
