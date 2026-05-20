# Service Info

The Cisco ASA (Adaptive Security Appliance) integration allows you to ingest firewall and security logs into the Elastic Stack. This provides centralized visibility into network traffic, security threats, and administrative actions across your Cisco ASA infrastructure.

## Common use cases

- **Security Monitoring and Threat Detection:** Monitor firewall logs to identify denied connection attempts, potential scanning activity, and known attack patterns.
- **Compliance Auditing:** Maintain a historical record of administrative access, configuration changes, and security policy enforcement for regulatory requirements.
- **Network Troubleshooting:** Use detailed connection logs to diagnose connectivity issues, verify NAT translations, and analyze traffic flow patterns across different security zones.
- **Operational Visibility:** Track VPN session activity, including user logins and session durations, to monitor remote access usage and performance.

## Data types collected

This integration collects several categories of security and operational data from Cisco ASA devices:

- **Cisco ASA logs (log):** This data stream collects Cisco ASA logs via network protocols (TCP/UDP) or from local files. It includes:
    - **Firewall Logs:** Connection establishment and teardown events, access-list (ACL) hits, and protocol-specific inspection logs.
    - **Security Events:** Threat detection events and authentication successes and failures.
    - **System Logs:** Resource utilization, configuration changes, and hardware health status.
    - **VPN Logs:** Remote access and site-to-site VPN connection details, including user authentication and tunnel duration.

## Compatibility
The **Cisco ASA** integration is compatible with:
- **Cisco ASA** hardware and virtual appliances.
- Supported for logs delivered via Syslog (RFC 3164/5424) or read from local files.
- Works with standard Cisco ASA syslog formats as documented in the 9.x configuration guides.

## Scaling and Performance

To ensure optimal performance in high-volume environments, consider the following:

- **Transport/Collection Considerations:** For high-volume environments, using **TCP** is recommended to ensure reliable delivery of log events. **UDP** offers lower overhead and is suitable for environments where occasional log loss is acceptable in exchange for higher performance and reduced state tracking on the firewall.
- **Data Volume Management:** To manage the volume of data sent to the Elastic Agent, configure the `logging trap` level on the Cisco ASA. Setting the level to `informational` (level 6) captures most relevant connection data, while setting it to `notice` or `warning` can significantly reduce volume by filtering out routine connection build/teardown events.
- **Elastic Agent Scaling:** For high-throughput environments, deploy multiple Elastic Agents behind a network load balancer to distribute traffic evenly. Place Agents close to the data source to minimize latency. A single Elastic Agent can handle several thousand events per second depending on the hardware provided.

# Set Up Instructions

## Vendor prerequisites

- **Administrative Access:** High-level administrative access (Enable mode or Level 15) to the Cisco ASA CLI or ASDM GUI is required to configure logging settings.
- **Network Connectivity:** Unrestricted network paths must exist between the Cisco ASA and the Elastic Agent host over the chosen protocol (UDP or TCP) and port (default 9001).
- **Interface Knowledge:** Identification of the specific ASA interface (e.g., `inside`, `management`, or `outside`) that will be used to route syslog traffic to the Elastic Agent.
- **Logging Capacity:** Ensure the ASA device has sufficient CPU and memory resources to handle additional logging overhead during peak traffic periods.

## Elastic prerequisites

- **Elastic Agent Installation:** An Elastic Agent must be installed on a host and enrolled in a policy via Fleet.
- **Policy Management:** Access to Kibana's Fleet and Integrations UI to configure the Cisco ASA integration settings.
- **Connectivity:** The Elastic Agent host must be listening on the configured port and reachable by the Cisco ASA's logging interface.

## Vendor set up steps

### For Syslog Collection via ASDM (GUI):
1. Log in to the Cisco ASDM console for your ASA device.
2. Navigate to **Configuration > Device Management > Logging > Logging Setup**.
3. Check the box for **Enable logging** and click **Apply**.
4. Navigate to **Configuration > Device Management > Logging > Syslog Server**.
5. Click **Add** to configure the Elastic Agent as a destination:
    - **Interface**: Select the interface that can reach the Elastic Agent (e.g., `inside`).
    - **IP Address**: Enter the IP address of the Elastic Agent host.
    - **Protocol**: Select **UDP** or **TCP** to match your integration input.
    - **Port**: Enter the port number (e.g., `9001`).
    - Click **OK**.
6. Navigate to **Configuration > Device Management > Logging > Logging Filters**.
7. Select **Syslog Servers** and click **Edit**. Select **Filter on severity** and choose **Informational** (or your preferred level).
8. Click **OK** and then **Apply** to save the changes to the running configuration.

### For Syslog Collection via CLI:
1. Log in to the Cisco ASA via SSH or a console cable.
2. Enter global configuration mode:
   ```
   conf t
   ```
3. Enable the logging subsystem:
   ```
   logging enable
   ```
4. Define the Elastic Agent host destination (e.g., using UDP on port 9001):
   ```
   logging host inside 192.168.1.50 udp/9001
   ```
5. Set the severity level for logs sent to the agent:
   ```
   logging trap informational
   ```
6. (Optional) Enable timestamps for better event correlation:
   ```
   logging timestamp
   ```
7. Exit and save the configuration:
   ```
   write mem
   ```

### Vendor Set up Resources
- [Cisco ASA 9.23 CLI Configuration Guide - Logging](https://www.cisco.com/c/en/us/td/docs/security/asa/asa923/configuration/general/asa-923-general-config/monitor-syslog.html) - Official guide for CLI logging configuration.
- [Cisco ASA ASDM 7.20 Configuration Guide - Logging](https://www.cisco.com/c/en/us/td/docs/security/asa/asa920/asdm720/general/asdm-720-general-config/monitor-syslog.html) - Official guide for GUI-based logging configuration.

## Kibana set up steps

### Collecting logs from Cisco ASA via TCP
1. In Kibana, navigate to **Integrations** and search for **Cisco ASA**.
2. Click **Add Cisco ASA** and select the **Collecting logs from Cisco ASA via TCP** input type.
3. Configure the following fields:
   - **Listen Address** (`tcp_host`): The bind address to listen for TCP connections. Set to `0.0.0.0` to bind to all available interfaces. Default: `localhost`.
   - **Listen Port** (`tcp_port`): The TCP port number to listen on. Default: `9001`.
   - **Preserve original event** (`preserve_original_event`): Preserves a raw copy of the original event, added to the field `event.original`. Default: `False`.
   - **Preserve searchable message text.** (`keep_message`): Preserves the log message in a searchable field, `cisco.asa.full_message`. Default: `False`.
   - **Tags** (`tags`): Custom tags for the events. Default: `['cisco-asa', 'forwarded']`.
   - **Internal Zones** (`internal_zones`): Define internal network zones.
   - **External Zones** (`external_zones`): Define external network zones.
   - **Processors** (`processors`): Processors are used to reduce the number of fields in the exported event or to enhance the event with metadata. This executes in the agent before the logs are parsed.
   - **SSL Configuration** (`ssl`): SSL configuration options including certificates and keys.
   - **Custom TCP Options** (`tcp_options`): Specify custom configuration options like `max_connections` or `line_delimiter`.
   - **Default Time Zone** (`tz_offset`): IANA time zone or time offset (e.g. `+0200`) to use when interpreting syslog timestamps without a time zone. Default: `UTC`.
   - **Time Zone Map** (`tz_map`): A combination of time zones as they appear in the Cisco ASA log mapped to a proper IANA time zone or offset.
4. Save the integration and add to a new or existing agent policy.

### Collecting logs from Cisco ASA via UDP
1. In Kibana, navigate to **Integrations** and search for **Cisco ASA**.
2. Click **Add Cisco ASA** and select the **Collecting logs from Cisco ASA via UDP** input type.
3. Configure the following fields:
   - **Listen Address** (`udp_host`): The bind address to listen for UDP connections. Set to `0.0.0.0` to bind to all available interfaces. Default: `localhost`.
   - **Listen Port** (`udp_port`): The UDP port number to listen on. Default: `9001`.
   - **Preserve original event** (`preserve_original_event`): Preserves a raw copy of the original event, added to the field `event.original`. Default: `False`.
   - **Preserve searchable message text.** (`keep_message`): Preserves the log message in a searchable field, `cisco.asa.full_message`. Default: `False`.
   - **Tags** (`tags`): Custom tags for filtering. Default: `['cisco-asa', 'forwarded']`.
   - **Internal Zones** (`internal_zones`): Specify internal interface names.
   - **External Zones** (`external_zones`): Specify external interface names.
   - **Custom UDP Options** (`udp_options`): Specify custom configuration options like `read_buffer`, `max_message_size`, or `timeout`.
   - **Processors** (`processors`): Metadata enhancement options that execute in the agent before parsing.
   - **Default Time Zone** (`tz_offset`): IANA time zone for timestamp interpretation. Default: `UTC`.
   - **Time Zone Map** (`tz_map`): Mapping for custom time zone strings as they appear in the ASA log.
4. Save the integration and add to a new or existing agent policy.

### Collecting logs from Cisco ASA via file
1. In Kibana, navigate to **Integrations** and search for **Cisco ASA**.
2. Click **Add Cisco ASA** and select the **Collecting logs from Cisco ASA via file** input type.
3. Configure the following fields:
   - **Paths** (`paths`): List of specific file paths to monitor. Default: `['/var/log/cisco-asa.log']`.
   - **Preserve original event** (`preserve_original_event`): Includes `event.original` in the output. Default: `False`.
   - **Preserve searchable message text.** (`keep_message`): Preserves the log message in a searchable field, `cisco.asa.full_message`. Default: `False`.
   - **Internal Zones** (`internal_zones`): List of trusted zones. Default: `['trust']`.
   - **External Zones** (`external_zones`): List of untrusted zones. Default: `['untrust']`.
   - **Tags** (`tags`): Identification tags. Default: `['cisco-asa', 'forwarded']`.
   - **Processors** (`processors`): Agent-side processing rules for metadata.
   - **Default Time Zone** (`tz_offset`): IANA time zone or offset. Default: `UTC`.
   - **Time Zone Map** (`tz_map`): Mapping for ASA-specific time zone abbreviations.
4. Save the integration and add to a new or existing agent policy.

# Validation Steps

After configuration is complete, verify that data is flowing correctly.

### 1. Trigger Data Flow on Cisco ASA:
- **Configuration change:** Enter and exit config mode on the ASA CLI: `conf t` then `exit`. This generates a configuration change event.
- **Authentication event:** Log out and log back into the ASDM GUI or SSH session to trigger authentication logs.
- **Security event:** Attempt to reach a service blocked by an Access Control List (ACL) to generate a "Deny" syslog message.

### 2. Check Data in Kibana:
1. Navigate to **Discover**.
2. Select the `logs-*` data view.
3. Enter the KQL filter: `data_stream.dataset : "cisco_asa.log"`
4. Verify logs appear in the timeline. Expand a log entry and confirm these fields are present and accurate:
   - `event.dataset` (should be `cisco_asa.log`)
   - `source.ip` and/or `destination.ip`
   - `event.action` or `event.outcome`
   - `message` (the raw log payload)
5. Navigate to **Dashboards** and search for "Cisco ASA" to view the pre-built overview dashboard.

# Troubleshooting

## Common Configuration Issues

- **Port Binding Conflicts**: If the Elastic Agent fails to start the input, check if another process is already using the configured port (e.g., port 9001). Use `netstat -tulpn` on Linux to identify port usage.
- **Network Firewalls**: Ensure that any intermediate firewalls or host-based firewalls (like `iptables` or `firewalld`) are configured to allow traffic from the Cisco ASA's IP to the Elastic Agent's port and protocol.
- **Incorrect Interface Routing**: On the Cisco ASA, ensure the `logging host` command specifies the correct interface that has a route to the Elastic Agent. Logs will not be sent if the ASA cannot reach the destination IP via the specified interface.
- **Logging Level Too Low**: If events are missing, verify that `logging trap` is set to at least `informational` (6). If it is set to `emergencies` or `critical`, most traffic logs will be ignored.

## Ingestion Errors

- **Timestamp Parsing Failures**: If logs appear with the wrong time, verify the `tz_offset` and `tz_map` settings in the integration. Cisco ASA logs often omit time zone offsets, leading to UTC interpretation by default.
- **Message Format Mismatches**: Ensure that `logging timestamp` is enabled on the ASA. Without timestamps, the integration may struggle to parse the start of the syslog header correctly.
- **Field Mapping Issues**: Check the `error.message` field in Kibana Discover. If the ASA is sending non-standard or highly customized syslog formats, the agent might fail to map specific fields, resulting in tags like `_grokparsefailure`.

## Vendor Resources
- [Cisco ASA Official Support Documentation](https://www.cisco.com/c/en/us/support/security/adaptive-security-appliance-asa-software/series.html) - General product support and series documentation.

