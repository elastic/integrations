# Service Info

## Common use cases

The Cisco Nexus integration is designed to ingest and parse system messages and error logs from Cisco Nexus series switches running NX-OS. This integration provides visibility into the operational health and security status of data center networking infrastructure.

- **Infrastructure Health Monitoring:** Monitor system-level events such as hardware failures, environmental alarms (temperature, power), and module status changes to ensure high availability.
- **Network Troubleshooting:** Analyze interface flaps, spanning tree (STP) changes, and routing protocol updates to identify and resolve connectivity issues quickly within the fabric.
- **Security Auditing and Compliance:** Track user authentication attempts, configuration changes (via "configure terminal" events), and access control list (ACL) hits for security auditing.
- **Performance Analysis:** Review system resource warnings and buffer utilization logs to proactively address potential bottlenecks before they impact network performance.

## Data types collected

This integration collects several categories of logs from Cisco Nexus devices. Each data type is handled by a specific data stream:

- **System Messages:** High-level operational logs including system boot information, module status, and process events.
- **Error Logs:** Detailed error messages categorized by severity levels (0-7), covering everything from emergency system failures to informational debugging data.
- **Configuration Events:** Logs capturing when users enter configuration mode and specific changes made to the switch running configuration.
- **Data Formats:** Logs are primarily collected in Syslog format (RFC 3164 or RFC 5424).

## Compatibility

This integration is compatible with the following **Cisco Nexus** products and operating systems:
- **Cisco Nexus Series Switches:** Tested against 9000 Series, 3172T, and 3048 models.
- **Cisco NX-OS:** Specifically verified against NX-OS Release 6.x, but should work with later versions.
- **Virtual Routing and Forwarding (VRF):** Supports management and default VRF instances for log forwarding.

## Scaling and Performance

To ensure optimal performance in high-volume data center environments, consider the following:
- **Transport/Collection Considerations:** While UDP is faster for syslog transmission, TCP is recommended for Cisco Nexus logs in environments where delivery guarantees are required. TCP ensures no log messages are lost due to network congestion, though it introduces slightly higher overhead on the switch's control plane.
- **Data Volume Management:** Configure the Cisco Nexus appliance to forward only necessary events by setting the `logging level` at the source. It is recommended to use level 5 (Notifications) or level 6 (Informational) for production monitoring. Avoid forwarding debug-level logs (level 7) unless troubleshooting specific issues, as they can significantly increase CPU load on the switch and ingest volume in the Elastic Stack.
- **Elastic Agent Scaling:** For high-throughput environments with hundreds of switches, deploy multiple Elastic Agents behind a network load balancer to distribute the Syslog traffic evenly across instances. Place Agents close to the data source within the same management VRF to minimize latency and potential packet loss.

# Set Up Instructions

## Vendor prerequisites

- **Administrative Access:** You must have `network-admin` or equivalent CLI access to the Cisco Nexus switch via SSH or console.
- **Network Connectivity:** The switch must have a network path to the Elastic Agent. If using the management VRF, ensure routing is correctly configured.
- **Port Requirements:** Ensure firewalls permit traffic on the configured port (default is **9506**).
- **Timezone Awareness:** Synchronize switch clocks via NTP to ensure log timestamps are accurate for correlation in Kibana.
- **Feature License:** Ensure the basic system management features are available (included in standard NX-OS images).

## Elastic prerequisites
- **Elastic Agent:** An active Elastic Agent must be installed and enrolled in Fleet.
- **Kibana Version:** The Elastic Stack must be running Kibana version 8.11.0 or higher.
- **Connectivity:** The Elastic Agent must be reachable by the Cisco Nexus switch over the designated syslog port (TCP or UDP).

## Vendor set up steps

### For Syslog (UDP or TCP) Collection:
1. Log in to the Cisco Nexus switch CLI via SSH or console.
2. Enter global configuration mode:
```bash
switch# configure terminal
```
3. Set the timestamp granularity to milliseconds:
```bash
switch(config)# logging timestamp milliseconds
```
4. Configure the remote logging server pointing to the Elastic Agent IP:
   - **For UDP (Standard):**
     ```bash
     switch(config)# logging server <ELASTIC_AGENT_IP> 6 use-vrf <vrf_name>
     ```
   - **For Secure TCP/TLS (NX-OS 9.2(1) and later):**
     ```bash
     switch(config)# logging server <ELASTIC_AGENT_IP> 6 port 6514 secure use-vrf <vrf_name>
     ```
     > **Note:** NX-OS does not support standard (unencrypted) TCP syslog. The `secure` keyword enables TLS-encrypted syslog on port **6514**. Ensure SSL is configured on the Elastic Agent TCP input to accept TLS connections, and update the integration's listen port to `6514` accordingly.
5. Specify the source interface for syslog traffic:
```bash
switch(config)# logging source-interface loopback 0
```
6. Verify the logging configuration:
```bash
switch(config)# show logging server
```
7. Save the configuration:
```bash
switch(config)# copy running-config startup-config
```

### For Logfile Collection:
1. Log in to the Cisco Nexus switch CLI.
2. Configure the switch to write system messages to a local file:
```bash
switch# configure terminal
switch(config)# logging logfile <FILENAME> <SEVERITY_LEVEL>
```
3. Ensure the Elastic Agent has file system access to the directory where the log file is stored.

### Vendor Set up Resources
- [Cisco Nexus 9000 Series NX-OS System Management Configuration Guide - Configuring System Message Logging](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/6-x/system_management/configuration/guide/b_Cisco_Nexus_9000_Series_NX-OS_System_Management_Configuration_Guide/sm_5syslog.html)

## Kibana set up steps

1. In Kibana, navigate to **Management > Integrations**.
2. Search for **Cisco Nexus** and select it.
3. Click **Add Cisco Nexus**.
4. Follow the prompts to add the integration to an Elastic Agent policy.
5. Configure the inputs as required by your environment:

### Collecting logs from Cisco Nexus via TCP.
This input collects Cisco Nexus logs via TCP input.
- **Listen Address** (`listen_address`): The bind address to listen for TCP connections. Set to `0.0.0.0` to bind to all available interfaces. Default: `localhost`.
- **Listen Port** (`listen_port`): The TCP port number to listen on. Default: `9506`.
- **Timezone Map** (`tz_map`): A collection of timezones found in Cisco Nexus logs (as defined in each `tz_short`), and the replacement value (as defined in each `tz_long`) which should be the full proper IANA Timezone format. This is used to override vendor provided timezone formats that is not supported by Elasticsearch [Date Processors](https://www.elastic.co/docs/reference/enrich-processor/date-processor#date-processor-timezones).
- **Timezone Offset** (`tz_offset`): When interpreting syslog timestamps without a time zone, use this timezone offset. Datetimes recorded in logs are by default interpreted in relation to the timezone set up on the host where the agent is operating.
- **Preserve original event** (`preserve_original_event`): Preserves a raw copy of the original event, added to the field `event.original`. Default: `False`.
- **Custom TCP Options** (`tcp_options`): Specify custom configuration options for the TCP input, such as `framing`, `max_message_size`, or `max_connections`.
- **SSL Configuration** (`ssl`): SSL configuration options for secure transmission. See [documentation](https://www.elastic.co/guide/en/beats/filebeat/current/configuration-ssl.html#ssl-common-config) for details.
- **Tags** (`tags`): Custom tags to add to the events. Default: `['forwarded', 'cisco_nexus-log']`.
- **Preserve duplicate custom fields** (`preserve_duplicate_custom_fields`): Preserve `cisco_nexus.log` fields that were copied to Elastic Common Schema (ECS) fields. Default: `False`.
- **Processors** (`processors`): Processors are used to reduce the number of fields in the exported event or to enhance the event with metadata. See [Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details.

### Collecting logs from Cisco Nexus via UDP.
This input collects Cisco Nexus logs via UDP input.
- **Listen Address** (`listen_address`): The bind address to listen for UDP connections. Set to `0.0.0.0` to bind to all available interfaces. Default: `localhost`.
- **Listen Port** (`listen_port`): The UDP port number to listen on. Default: `9506`.
- **Timezone Map** (`tz_map`): A collection of timezones found in Cisco Nexus logs (as defined in each `tz_short`), and the replacement value (as defined in each `tz_long`) which should be the full proper IANA Timezone format. This is used to override vendor provided timezone formats that is not supported by Elasticsearch [Date Processors](https://www.elastic.co/docs/reference/enrich-processor/date-processor#date-processor-timezones).
- **Timezone Offset** (`tz_offset`): When interpreting syslog timestamps without a time zone, use this timezone offset. 
- **Preserve original event** (`preserve_original_event`): Preserves a raw copy of the original event, added to the field `event.original`. Default: `False`.
- **Custom UDP Options** (`udp_options`): Specify custom configuration options for the UDP input, such as `max_message_size` and `timeout`.
- **Tags** (`tags`): Custom tags to add to the events. Default: `['forwarded', 'cisco_nexus-log']`.
- **Preserve duplicate custom fields** (`preserve_duplicate_custom_fields`): Preserve `cisco_nexus.log` fields that were copied to Elastic Common Schema (ECS) fields. Default: `False`.
- **Processors** (`processors`): Processors used for agent-side filtering and metadata enhancement. See [Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details.

### Collecting logs from Cisco Nexus via file.
This input collects Cisco Nexus logs via Filestream input from local or shared file paths.
- **Paths** (`paths`): A list of glob-based paths that will be crawled and fetched.
- **Timezone Map** (`tz_map`): A collection of timezones found in Cisco Nexus logs (as defined in each `tz_short`), and the replacement value (as defined in each `tz_long`) which should be the full proper IANA Timezone format. This is used to override vendor provided timezone formats that is not supported by Elasticsearch [Date Processors](https://www.elastic.co/docs/reference/enrich-processor/date-processor#date-processor-timezones).
- **Timezone Offset** (`tz_offset`): When interpreting syslog timestamps without a time zone, use this timezone offset.
- **Preserve original event** (`preserve_original_event`): Preserves a raw copy of the original event, added to the field `event.original`. Default: `False`.
- **Tags** (`tags`): Custom tags to add to the events. Default: `['forwarded', 'cisco_nexus-log']`.
- **Preserve duplicate custom fields** (`preserve_duplicate_custom_fields`): Preserve `cisco_nexus.log` fields that were copied to Elastic Common Schema (ECS) fields. Default: `False`.
- **Processors** (`processors`): Define agent-side processing rules. See [Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details.

6. Save and deploy the integration.

# Validation Steps

After configuration is complete, verify that data is flowing correctly.

### 1. Trigger Data Flow on Cisco Nexus:
- **Configuration event:** Enter and exit global configuration mode by running `configure terminal` followed by `exit` to generate a `SYS-5-CONFIG_I` log message.
- **Interface event:** Perform a `shutdown` and `no shutdown` command on a test interface (e.g., `interface Ethernet1/1`) to generate interface status change logs.
- **Authentication event:** Log out of the current SSH session and log back in to generate an AAA/User login message.

### 2. Check Data in Kibana:
1. Navigate to **Analytics > Discover**.
2. Select the `logs-*` data view.
3. Enter the KQL filter: `data_stream.dataset : "cisco_nexus.log"`
4. Verify logs appear in the results. Expand a log entry and confirm the presence of these fields:
   - `event.dataset` (should be `cisco_nexus.log`)
   - `source.ip` (should match the management IP of the Nexus switch)
   - `event.code` (the NX-OS mnemonic, e.g., `VSHD_SYSLOG_CONFIG_I` or `IF_UP`)
   - `message` (the raw log payload)
5. Navigate to **Analytics > Dashboards** and search for "Cisco Nexus" to view the pre-built dashboards and confirm visualization of the events.

# Troubleshooting

## Common Configuration Issues

- **Port Conflicts**: Ensure that the port specified in the integration (default 9506) is not being used by another service on the Elastic Agent host. Use `netstat -ano | grep 9506` on Linux to check for active listeners.
- **VRF Configuration**: On Cisco Nexus switches, logging often occurs over a specific VRF (Virtual Routing and Forwarding) instance. If the switch cannot reach the Agent, ensure you have specified the correct VRF in the command, such as `logging server [IP] use-vrf management`.
- **Firewall Blockage**: Verify that local firewalls on the Elastic Agent host (e.g., `iptables` or `firewalld`) and network firewalls allow traffic on the configured TCP/UDP port.
- **Timezone Mismatch**: If events appear in the past or future in Kibana, verify the switch time settings and use the **Timezone Offset** or **Timezone Map** parameters in the Kibana integration settings to align with the Elastic Stack.

## Ingestion Errors

- **Timestamp Parsing Failures**: If the switch is configured for `seconds` instead of `milliseconds`, the integration may have difficulty parsing the precision. Use `logging timestamp milliseconds` on the switch to resolve.
- **Malformed Syslog Header**: Non-standard syslog formats may fail to parse. Verify the switch is using the standard NX-OS logging format.
- **Field Mapping Errors**: Check the `error.message` field in Kibana Discover for clues about fields that failed to map to ECS. This often happens if the log message format has been customized on the switch.

## Vendor Resources

- [Cisco Nexus Series Switches Support Home](https://www.cisco.com/c/en/us/support/switches/nexus-9000-series-switches/series.html)
- [Cisco NX-OS System Message Guides](https://www.cisco.com/c/en/us/support/switches/nexus-9000-series-switches/products-system-message-guides-list.html)

# Documentation sites

- [Cisco Nexus Integration Reference](https://www.cisco.com/c/en/us/support/switches/nexus-9000-series-switches/products-system-message-guides-list.html)
