# Service Info

## Common use cases

The Broadcom ProxySG integration allows organizations to ingest and analyze web traffic data, providing deep visibility into user activity, security threats, and network performance.
- **Security Monitoring and Threat Hunting:** Analyze access logs to identify patterns associated with malicious activity, SSL/TLS inspection results, and blocked URL categories to harden the network security posture.
- **Compliance and Auditing:** Maintain a comprehensive record of all web transactions to meet regulatory requirements and internal policy audits regarding data access and user behavior.
- **Bandwidth and Performance Optimization:** Use logged data such as cache hits, bytes transferred, and response times to identify bandwidth bottlenecks and optimize web application performance.
- **Policy Verification:** Ensure that Web Access Policies configured in the Visual Policy Manager (VPM) are correctly filtering traffic by reviewing real-time logs of allowed and denied requests.

## Data types collected

This integration collects several streams of data from Broadcom ProxySG appliances to provide a complete view of network traffic:

- **ProxySG Access logs (logs):** This data stream collects ProxySG access logs from file. It is primarily used when logs are uploaded from the appliance to a central logging server where the Elastic Agent is running.
- **ProxySG logs via UDP (logs):** This data stream collects ProxySG logs (via UDP). It captures real-time syslog-style transmissions from the appliance for high-velocity environments.
- **ProxySG logs via TCP (logs):** This data stream collects ProxySG logs (via TCP). It captures reliable real-time log transmissions from the appliance, ensuring delivery for sensitive security audits.

## Compatibility

This integration is compatible with **Broadcom ProxySG** (formerly Symantec) appliances. It has been specifically tested and documented for:
- **ProxySG / Edge SWG version 7.3 and higher**.
- The integration currently supports the **main**, **bcreportermain_v1**, **bcreporterssl_v1** and **ssl** log formats as defined in the appliance configuration.

## Scaling and Performance

To ensure optimal performance in high-volume environments, consider the following:
- **Transport/Collection Considerations:** For real-time requirements, TCP is the recommended transport protocol to ensure delivery reliability via the **ProxySG logs (via TCP)** input. UDP may be used for high-velocity environments where occasional packet loss is acceptable for reduced overhead. When using the **ProxySG Access logs** (filestream) method, ensure the disk I/O on the logging server can handle the write/read operations of the incoming log files.
- **Data Volume Management:** High-traffic environments should leverage the ProxySG's Web Access Policy to filter out unnecessary logs—such as specific health checks or trusted internal traffic—at the source before they are sent to the Elastic Agent. This significantly reduces the processing load on both the appliance and the Elastic Stack ingest pipelines.
- **Elastic Agent Scaling:** In high-throughput environments exceeding 10,000 events per second, deploy multiple Elastic Agents behind a network load balancer to distribute the Syslog (TCP/UDP) ingestion load. Ensure the host machine for the Agent has sufficient CPU resources to handle the concurrent parsing of the ProxySG logs across multiple data streams.

# Set Up Instructions

## Vendor prerequisites

- **Administrative Access:** Credentials for the ProxySG Management Console with permissions to modify Access Logging and Upload Client settings.
- **Network Connectivity:** Unrestricted network path between the ProxySG appliance and the Elastic Agent host on the configured ports (e.g., TCP `601` or UDP `514`).
- **Log Object Configuration:** A supported log configuration must be configured on the appliance.
- **Visual Policy Manager (VPM) Access:** Permission to install or modify policies to ensure traffic is being written to the access log.
- **Storage for File Uploads:** If using the File Upload method, a destination server (FTP/SFTP/SCP) must be available that the Elastic Agent can access locally.

## Elastic prerequisites

- **Elastic Agent Deployment:** The Elastic Agent must be installed and enrolled in Fleet on a host that can receive network traffic from the ProxySG appliance.
- **Network Port Availability:** The host running the Elastic Agent must have the required TCP/UDP ports open in its local firewall to receive log data.
- **Ingest Pipeline Support:** Ensure your Elasticsearch cluster has sufficient capacity to handle the incoming log volume and process the ProxySG ingest pipelines.

## Vendor set up steps

### For Syslog (TCP/UDP) Collection:
1. Log in to the **ProxySG Management Console**.
2. Navigate to **Configuration > Access Logging > Logs > General**.
3. Select the log object you want to collect and ensure the **Log Format** is set to a supported format.
4. Navigate to **Configuration > Access Logging > Logs > Upload Client**.
5. Select the same log object from the list.
6. Change the **Client type** to `Custom Client`.
7. Click **Settings** and configure:
   - **Primary Host**: Enter the IP Address of your Elastic Agent
   - **Port**: `514` for UDP or `601` for TCP
   - **Protocol**: Select `UDP` or `TCP` depending on your transport preference
8. Click **OK**, then **Apply**.
9. Navigate to the **Upload Schedule** tab.
10. Select the log object and set **Upload type** to `Continuously`.
11. Optionally, set **Wait time before upload** to `5` seconds for near real-time delivery.
12. Click **Apply**.

### For File Upload Collection:
1. Log in to the **ProxySG Management Console**.
2. Navigate to **Configuration > Access Logging > Logs > Upload Client**.
3. Select the log object you want to collect.
4. Set the **Client type** to `FTP Client`, `SFTP Client`, or `SCP Client` depending on your logging server.
5. Click **Settings** and enter the destination server details where the Elastic Agent is located.
6. Under **Save the log file as**, select `text file`.
7. Navigate to the **Upload Schedule** tab and set the **Upload type** to `Periodically` or `Continuously`.
8. Click **Apply**.

### Enable Logging in Policy:
1. Launch the **Visual Policy Manager (VPM)** from the ProxySG Console.
2. Create or edit a **Web Access Layer**.
3. Locate or create a rule for the traffic you wish to monitor.
4. Right-click the **Action** column and select **Set > New > Modify Access Logging**.
5. Select the log object (e.g., `main`) configured in the previous steps.
6. Click **OK**, then click **Install Policy**.

### Vendor Set up Resources

- [Sending Access Logs to a Syslog server - Broadcom Knowledge Base](https://knowledge.broadcom.com/external/article/166529/sending-access-logs-to-a-syslog-server.html) - Detailed guide on configuring the Custom Client for syslog export.
- [Configure access logging on ProxySG to an FTP server - Broadcom Knowledge Base](https://knowledge.broadcom.com/external/article/165586/configure-access-logging-on-proxysg-or-a.html) - Steps for setting up file-based log uploads.

## Kibana set up steps

### 1. Collecting access logs from ProxySG via logging server file
1. In Kibana, navigate to **Management > Integrations** and search for **Broadcom ProxySG**.
2. Click **Add Broadcom ProxySG**.
3. Under **Configure integration**, locate the section for **Collect access logs from ProxySG via logging server file**.
4. Configure the following variables:
   - **Paths** (`paths`): The file pattern matching the location of the log files. Default: `['/var/log/proxysg-log.log']`.
   - **Preserve original event** (`preserve_original_event`): Toggle this to `True` if you wish to keep a raw copy of the event in `event.original`. Default: `False`.
   - **Access Log Format** (`config`): The log configuration type for input. Supported formats: `main`, `ssl`, `bcreportermain_v1`, `bcreporterssl_v1`. Default: `main`.
   - **Tags** (`tags`): Custom tags to append to events for filtering (e.g., `proxysg-access-log`, `forwarded`).
   - **Custom Filestream Options** (`filestream_options`): Specify custom configuration options for the Filestream input.
   - **Processors** (`processors`): Add processors to reduce the number of fields or enhance the event with metadata before parsing.
5. Save the integration to an Elastic Agent policy.

### 2. Collecting logs from ProxySG via UDP
1. In Kibana, navigate to **Management > Integrations** and search for **Broadcom ProxySG**.
2. Click **Add Broadcom ProxySG**.
3. Under **Configure integration**, locate the section for **Collect logs from ProxySG via UDP**.
4. Configure the following variables:
   - **Listen Address** (`udp_host`): The bind address to listen for UDP connections. Set to `0.0.0.0` to bind to all available interfaces. Default: `localhost`.
   - **Listen Port** (`udp_port`): The UDP port number to listen on. Default: `514`.
   - **Preserve original event** (`preserve_original_event`): Preserves a raw copy of the original event in the field `event.original`. Default: `False`.
   - **Access Log Format** (`config`): The log configuration type. Supported formats: `main`, `ssl`, `bcreportermain_v1`, `bcreporterssl_v1`. Default: `main`.
   - **Tags** (`tags`): Custom tags to append to events (e.g., `forwarded`).
   - **Custom UDP Options** (`udp_options`): Specify custom configuration options such as `read_buffer: 100MiB` or `max_message_size: 50KiB`.
   - **Processors** (`processors`): Add processors to execute in the agent before the logs are parsed.
5. Save the integration to an Elastic Agent policy.

### 3. Collecting logs from ProxySG via TCP
1. In Kibana, navigate to **Management > Integrations** and search for **Broadcom ProxySG**.
2. Click **Add Broadcom ProxySG**.
3. Under **Configure integration**, locate the section for **Collect logs from ProxySG via TCP**.
4. Configure the following variables:
   - **Listen Address** (`tcp_host`): The bind address to listen for TCP connections. Set to `0.0.0.0` to bind to all available interfaces. Default: `localhost`.
   - **Listen Port** (`tcp_port`): The TCP port number to listen on. Default: `601`.
   - **Preserve original event** (`preserve_original_event`): Preserves a raw copy of the original event in the field `event.original`. Default: `False`.
   - **Access Log Format** (`config`): The log configuration type. Supported formats: `main`, `ssl`, `bcreportermain_v1`, `bcreporterssl_v1`. Default: `main`.
   - **Tags** (`tags`): Custom tags to append to events (e.g., `forwarded`).
   - **Custom TCP Options** (`tcp_options`): Specify custom configuration options for the TCP input.
   - **SSL Configuration** (`ssl`): Configure encrypted transmission using `certificate` and `key` paths.
   - **Processors** (`processors`): Add processors to execute in the agent before the logs are parsed.
5. Save the integration to an Elastic Agent policy.

# Validation Steps

After configuration is complete, verify that data is flowing correctly.

### 1. Trigger Data Flow on ProxySG:
- **Generate Web Traffic:** Use a workstation configured to use the ProxySG as a gateway and browse several different public websites to generate access logs.
- **Trigger Policy Events:** Attempt to access a URL category that is restricted by your policy to generate "denied" or "blocked" log entries.
- **Force Log Upload:** In the Management Console under **Access Logging > Logs > [Your Log] > Upload Now**, click the button to manually trigger a log push to the Agent.

### 2. Check Data in Kibana:
1. Navigate to **Analytics > Discover**.
2. Select the `logs-*` data view.
3. Enter the KQL filter: `data_stream.dataset : "proxysg.log"`
4. Verify logs appear. Expand a log entry and confirm these fields:
   - `event.dataset` (should be `proxysg.log`)
   - `source.ip` (the client machine IP address)
   - `event.outcome` (e.g., success or failure based on the status code)
   - `message` (the raw "main" format log payload)
5. Navigate to **Analytics > Dashboards** and search for "ProxySG" to verify the pre-built dashboards are populating.

# Troubleshooting

## Common Configuration Issues

- **Log Format Mismatch**: Ensure the ProxySG appliance is explicitly using a format supported by the integration. If a custom format is defined on the appliance, the Elastic Agent will fail to parse the fields correctly. Check the **Configuration > Access Logging > Logs > General** settings.
- **Upload Schedule Delay**: If data appears delayed, check the **Upload Schedule** on the ProxySG. Ensure it is set to `Continuously` rather than `Periodically` or `On-Demand`.
- **Custom Client Port Conflict**: If using the Syslog method, ensure no other service on the Elastic Agent host is using the configured TCP/UDP port. Use `netstat -ano` or `ss -tuln` to verify port availability.
- **VPM Policy Not Applied**: If no logs are appearing, verify that the **Modify Access Logging** action is correctly applied to the relevant rules in the Visual Policy Manager and that the policy has been successfully **Installed**.

## Ingestion Errors

- **Parsing Failures**: If logs appear in Kibana but contain a `_grokparsefailure` or `_jsonparseerror` tag, verify that the raw message in the `event.original` field matches the expected structure of the ProxySG **main** format.
- **Timezone Mismatch**: If logs appear to be delayed or from the future, check that the ProxySG appliance and the Elastic Agent host are synchronized via NTP and that timezone offsets are correctly handled in the integration's advanced settings.
- **Identifying Issues**: In Discover, filter for `error.message : *` or check the `log.level` field of the Elastic Agent logs to find specific ingestion errors.

# Documentation sites

- [Broadcom ProxySG Log Formats Documentation](https://techdocs.broadcom.com/us/en/symantec-security-software/web-and-network-security/edge-swg/7-3/getting-started/page-help-administration/page-help-logging/log-formats/default-formats.html) - Official reference for log format structures.