# Service Info

## Common use cases

The HPE Aruba CX integration is designed to provide comprehensive observability and security monitoring for HPE Aruba Networking CX Switch series, including the 6000, 6300, and 8360 series.
- **Security Auditing and Compliance:** Monitor authentication, authorization, and accounting (AAA) events, ACL hits, and port security violations to maintain a secure network perimeter.
- **Network Health and Stability:** Track routing protocol events for BGP, OSPF, and EVPN, alongside spanning tree (MSTP/RPVST) changes to ensure high availability and rapid troubleshooting of connectivity issues.
- **Hardware Performance Monitoring:** Gain visibility into physical switch health by collecting logs related to fan speeds, power supply status, temperature fluctuations, and ASIC resource utilization.
- **Configuration Change Tracking:** Audit administrative actions performed via SSH, WebUI (REST), or Console to ensure configuration integrity and maintain a detailed history of network modifications.

## Data types collected

This integration can collect the following types of data:
- **System and Security Logs:** Comprehensive logs covering AAA, ACLs, Port Security, and User Management events.
- **Protocol Events:** Detailed state change and error information for networking protocols including BGP, OSPF, ARP, BFD, and LACP.
- **Hardware Health Metrics:** Log-based health indicators for physical components such as fans, power supplies, and temperature sensors.
- **Configuration and Management Logs:** Audit trails of configuration changes, firmware updates, and REST API interactions.
- **Data Formats:** Primarily Syslog (sent via TCP or UDP) and flat-file logs (collected via filestream).

Use the following data streams for collection:
- **HPE Aruba CX logs (tcp):** Collects Aruba CX logs using the TCP input. This stream is optimized for reliable delivery of system, security, and protocol logs.
- **Aruba CX logs (udp):** Collects Aruba CX logs using the UDP input. This stream is designed for high-volume log ingest where minimal overhead on the source switch is required.
- **Aruba CX logs (filestream):** Collects Aruba logs using the filestream input, typically used for ingesting audit logs or files stored on a management server.

## Compatibility
The **HPE Aruba Networking CX Switch** integration is compatible with the following:
- **Tested Models:** Series 6000, 6300, and 8360 switches.
- **AOS-CX Version:** Tested against AOS-CX version 10.15; compatible with the AOS-CX 10.15 Event Log Message Reference Guide.
- **Language Requirements:** This integration strictly supports logs in the English language.

## Scaling and Performance

To ensure optimal performance in high-volume environments, consider the following:

- **Transport/Collection Considerations:** While UDP (default port 1024) is faster for syslog transmission and places less load on the switch CPU, TCP (default port 1470) is recommended for environments where delivery guarantees are required. For TCP, enable **SSL Configuration** if logs transit over public or untrusted networks to ensure data confidentiality.
- **Data Volume Management:** Configure the Aruba CX switch to forward only necessary events by setting the severity per remote server (e.g., `logging <elastic_agent_ip> severity informational`). Avoid forwarding `debug` level logs in production environments as they can overwhelm the ingest pipeline.

# Set Up Instructions

## Vendor prerequisites
- **Administrative Access:** Command Line Interface (CLI) access to the HPE Aruba CX switch via SSH or console is required.
- **Network Connectivity:** The switch must have network reachability to the IP address of the Elastic Agent on the configured syslog port (e.g., 1470 for TCP or 1024 for UDP).
- **Logging Configuration:** The AOS-CX switch must be configured to forward logs in English.
- **NTP Synchronization:** Network Time Protocol (NTP) should be configured on all switches to ensure timestamps are accurate and synchronized.
- **Permissions:** Sufficient privileges to enter configuration mode (`configure terminal`) and save the configuration (`write memory`).

## Elastic prerequisites

- **Elastic Agent Deployment:** Elastic Agent must be installed and enrolled in a Fleet policy.
- **Integration Enrollment:** The **HPE Aruba CX** integration must be added to the relevant Agent policy.
- **Network Ingress:** Firewall rules on the Elastic Agent host must allow inbound traffic on the ports specified in the integration configuration.

## Vendor set up steps

### For Syslog (CLI Method):
1. Log in to the AOS-CX switch CLI via SSH or console.
2. Enter global configuration mode:
   ```bash
   switch# configure terminal
   ```
3. Configure the remote logging target (the Elastic Agent) with the transport protocol and port. Replace `<elastic_agent_ip>` with your agent's IP.
   For TCP (recommended for reliable delivery, default integration port 1470):
   ```bash
   switch(config)# logging <elastic_agent_ip> port 1470 transport tcp
   ```
   For UDP (default integration port 1024):
   ```bash
   switch(config)# logging <elastic_agent_ip> port 1024 transport udp
   ```
4. Specify the VRF if using a dedicated management network:
   ```bash
   switch(config)# logging <elastic_agent_ip> vrf mgmt port 1470 transport tcp
   ```
5. Set the severity level to filter events sent to the Agent (e.g., `informational` or `notice`):
   ```bash
   switch(config)# logging <elastic_agent_ip> severity informational
   ```
6. Exit and save the configuration to the startup config:
   ```bash
   switch(config)# end
   switch# write memory
   ```

### For Syslog (Web UI Method):
1. Log in to the AOS-CX Web UI using administrative credentials.
2. Navigate to **System > Logging** in the sidebar.
3. Locate the **Logging Servers** section and click the **+ (Add)** button.
4. Enter the **IP Address** of the Elastic Agent.
5. Select the appropriate **VRF** (e.g., `mgmt`) that has connectivity to the Agent.
6. Set the **Severity Level** to `Informational` or higher.
7. Click **Apply** to activate the settings and click the **Save** icon at the top of the UI to persist across reboots.

### For Filestream (Logfile) Collection:
1. Ensure the Elastic Agent has read permissions for the directory containing the AOS-CX logs.
2. Configure the switch or an intermediate collector to write AOS-CX logs to a specific directory (e.g., `/var/log/audit/`).
3. Ensure the log rotation mechanism allows the Elastic Agent to monitor both active and rotated files if historical data is required.

### Vendor Set up Resources
- [AOS-CX Switch Software Documentation Portal](https://arubanetworking.hpe.com/techdocs/AOS-CX/help_portal/Content/home.htm) - Official portal for all AOS-CX configuration.
- [AOS-CX 10.15 Event Log Message Reference Guide](https://www.arubanetworks.com/techdocs/AOS-CX/10.15/HTML/elmrg/Content/fir-int.htm) - Comprehensive list of all event mnemonics and log formats.

## Kibana set up steps

### Collect logs from HPE Aruba CX via TCP
1. In Kibana, navigate to **Management > Integrations** and search for **HPE Aruba CX**.
2. Click **Add HPE Aruba CX**.
3. Under **HPE Aruba CX logs**, ensure the **Collect logs from HPE Aruba CX via TCP** input is enabled.
4. Configure the following variables:
   - **Listen Address** (`listen_address`): The bind address to listen for TCP connections. Set to `0.0.0.0` to bind to all available interfaces. Default: `localhost`.
   - **Listen Port** (`listen_port`): The TCP port number to listen on. Default: `1470`.
   - **Preserve original event** (`preserve_original_event`): Preserves a raw copy of the original event in `event.original`. Default: `False`.
   - **Tags** (`tags`): List of tags to add to the events. Default: `['hpe-aruba-cx', 'forwarded']`.
   - **Processors** (`processors`): Add processors to reduce fields or enhance metadata before parsing.
   - **SSL Configuration** (`ssl`): Provide SSL certificate and key information for encrypted transport.
   - **Custom TCP Options** (`tcp_options`): Specify options like `max_connections`, `framing`, or `line_delimiter`.
5. Click **Save and continue**.

### Collect logs from HPE Aruba CX via UDP
1. Navigate to the **HPE Aruba CX** integration settings.
2. Under **HPE Aruba CX logs**, ensure the **Collect logs from HPE Aruba CX via UDP** input is enabled.
3. Configure the following variables:
   - **Listen Address** (`listen_address`): The bind address to listen for UDP connections. Set to `0.0.0.0` to bind to all available interfaces. Default: `localhost`.
   - **Listen Port** (`listen_port`): The UDP port number to listen on. Default: `1024`.
   - **Preserve original event** (`preserve_original_event`): Preserves a raw copy of the original event in `event.original`. Default: `False`.
   - **Tags** (`tags`): List of tags to add to the events. Default: `['hpe-aruba-cx, 'forwarded']`.
   - **Custom UDP Options** (`udp_options`): Specify options such as `read_buffer`, `max_message_size`, or `timeout`.
   - **Processors** (`processors`): Add processors to reduce fields or enhance metadata before parsing.
4. Click **Save and continue**.

### Collect logs from HPE Aruba CX instances using filestream input.
1. Navigate to the **HPE Aruba CX** integration settings.
2. Under **HPE Aruba CX logs**, enable the **Collect logs from HPE Aruba CX via file** input. Note: this input is **disabled by default** and must be explicitly enabled.
3. Configure the following variables:
   - **Paths** (`paths`): Provide the list of paths to the log files. Default: `['/var/log/audit/*.log']`.
   - **Preserve original event** (`preserve_original_event`): Preserves a raw copy of the original event in `event.original`. Default: `False`.
   - **Tags** (`tags`): List of tags to add to the events. Default: `['hpe-aruba-cx', 'forwarded']`.
   - **Processors** (`processors`): Add processors to filter or enhance events at the Agent level.
4. Click **Save and continue**.

# Validation Steps

After configuration is complete, verify that data is flowing correctly.

### 1. Trigger Data Flow on HPE Aruba CX:
- **Configuration change:** Enter and exit global configuration mode to trigger a CONFIG_MGMT log: `configure terminal` then `exit`
- **Authentication event:** Log out and log back into the switch CLI via SSH to trigger AAA and SSH session logs.
- **Interface event:** Toggle a non-critical, unused interface (replace with an appropriate port): `interface 1/1/1`, `shutdown`, then `no shutdown`.

### 2. Check Data in Kibana:
1. Navigate to **Analytics > Discover**.
2. Select the `logs-*` data view.
3. Enter the KQL filter: `data_stream.dataset : "hpe_aruba_cx.log"`
4. Verify logs appear. Expand a log entry and confirm these fields are present:
   - `event.dataset` (should be `hpe_aruba_cx.log`)
   - `event.code` (the numeric event ID, e.g. `403`, `104`)
   - `log.level` (e.g., `LOG_INFO`, `LOG_WARN`)
   - `aruba.hardware.device` (the switch hostname)
   - `message` (the parsed log payload)
   - `event.action` or `event.outcome` (populated for specific event types only)
5. Navigate to **Analytics > Dashboards** and search for "HPE Aruba CX" to verify visualization population.

# Troubleshooting

## Common Configuration Issues

- **VRF Routing Mismatch**: If the switch is configured to send logs but they never arrive, verify the `vrf` parameter in the `logging` command. If the Agent is on the management network, the command MUST include `vrf mgmt`.
- **Port Conflicts**: Ensure the port configured in Kibana (e.g., 1470) is not being used by another process on the Elastic Agent host. Use `ss -tlnp | grep 1470` (Linux) or `netstat -ano | findstr 1470` (Windows) to verify port availability.
- **ACL/Firewall Blocks**: Check both the switch's outbound ACLs and the Agent host's local firewall (e.g., `iptables` or `firewalld`) to ensure traffic is permitted on the specified UDP/TCP ports.
- **English-Only Requirement**: If logs appear garbled or fail to parse, verify that the switch is not configured for internationalized logging. This integration only supports the standard English log format.

## Ingestion Errors

- **Parsing Failures**: If logs appear in Discover but have a `tags: [_grokparsefailure]` entry, the log format might differ from the expected AOS-CX 10.15 standard. Check the `error.message` field for specific details.
- **Timestamp Mismatches**: If logs do not appear in the default time range, check the switch's NTP status. Large time drifts can cause logs to be indexed into the past or future relative to the current Kibana view.
- **Field Mapping Mismatches**: Review the `event.original` field against the parsed fields. If critical information like `client.ip` is missing, verify that the switch is sending the full log header as per the AOS-CX specification.

## Vendor Resources

- [AOS-CX 10.15 Event Log Message Reference Guide](https://www.arubanetworks.com/techdocs/AOS-CX/10.15/HTML/elmrg/Content/fir-int.htm) - Comprehensive list of all event mnemonics and log formats.

# Documentation sites

- [AOS-CX 10.15 Event Log Message Reference Guide](https://www.arubanetworks.com/techdocs/AOS-CX/10.15/HTML/elmrg/Content/fir-int.htm)
- Refer to the [official vendor website](https://arubanetworking.hpe.com/techdocs/AOS-CX/help_portal/Content/home.htm) for the latest HPE Aruba Networking CX documentation.
