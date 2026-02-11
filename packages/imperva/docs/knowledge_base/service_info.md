# Service Info

## Common use cases

The Imperva SecureSphere integration enables organizations to ingest security events and system logs directly into the Elastic Stack.
- **Security Incident Monitoring:** Collection of security violations and alerts helps security analysts identify and respond to web application attacks.
- **Compliance and Auditing:** By ingesting system events and administrative logs, organizations can maintain an audit trail of configuration changes and system health.
- **Threat Detection and Analysis:** Correlate Imperva data with other security telemetry in Elastic to identify attack patterns.
- **Performance Monitoring:** Monitor Imperva Gateway health and system events.

## Data types collected

This integration collects several categories of logs from Imperva SecureSphere environments, organized into specific data streams.
- **Imperva SecureSphere logs (`securesphere`)**: This is the primary data stream used to ingest security and operational data. It supports the following collection methods:
    - **Collect Imperva SecureSphere logs via TCP input**: Collects logs from Imperva SecureSphere over a TCP network connection.
    - **Collect Imperva SecureSphere logs via UDP input**: Collects logs from Imperva SecureSphere over a UDP network connection.
    - **Collect Imperva SecureSphere logs via Filestream input**: Collects logs from Imperva SecureSphere by reading log files from a local directory.
- **Security Violations:** Detailed logs of specific security policy breaches captured at the Gateway level.
- **Security Alerts:** Aggregated security events that summarize multiple related violations.
- **System Events:** Operational logs related to the Imperva Management Server (MX) and Gateway health.
- **Data Formats:** All logs are collected in the Common Event Format (CEF) standard via Syslog or direct file reads.

## Compatibility

The Imperva integration is compatible with **Imperva SecureSphere** platforms that support **CEF (Common Event Format)** log output via syslog or local file write.

## Scaling and Performance

To ensure optimal performance in high-volume Imperva environments, consider the following:
- **Transport/Collection Considerations:** For high-volume environments, TCP is recommended over UDP to ensure delivery reliability. Adjust the `max_message_size` (default **50KiB**) in the **Custom TCP Options** or **Custom UDP Options** if your CEF payloads exceed the default buffer size.
- **Data Volume Management:** Reduce ingest load by configuring Imperva "Action Sets" to only forward critical severity events or specific violation types.
- **Elastic Agent Scaling:** For high-throughput environments, deploy multiple Elastic Agents behind a network load balancer to distribute traffic evenly.

# Set Up Instructions

## Vendor prerequisites
1. **Administrative Access:** Obtain administrative credentials for the Imperva SecureSphere Management Server (MX) console.
2. **Network Connectivity:** Ensure that the Imperva Gateway and MX server can reach the Elastic Agent host on the configured Syslog port (default is **9507**).
3. **Configuration Knowledge:** Identify the IP address of the Elastic Agent and determine whether TCP or UDP will be used for log transport.
4. **CEF Support:** Confirm that your Imperva version supports CEF format output.

## Elastic prerequisites
- **Elastic Agent:** The Elastic Agent must be installed and enrolled in Fleet.
- **Connectivity:** The Elastic Agent must be listening on a reachable IP address to receive inbound Syslog traffic from Imperva.

## Vendor set up steps

### For Syslog (TCP/UDP) Collection:

1. Log in to the **Imperva SecureSphere** Management Server (MX) console.
2. Create a new Action Interface with the following configuration settings:
    - **Protocol**: Select **TCP** or **UDP** (match your Elastic Agent configuration).
    - **Host**: Enter the IP address of the Elastic Agent host.
    - **Port**: Enter the port number configured in Kibana (default is `9507`).
    - **Message Format**: Ensure the format is set to **CEF**.
3. Create a new Action Set and add the Action Interface created in step 2.
4. Apply the Action Set to your policies and assign it as a **Followed Action**.
5. Save the configuration and ensure it is applied to the relevant Gateways.

### For Logfile (Filestream) Collection:

1. Configure the Imperva system to write logs to a local file.
2. Ensure the output file format is set to **CEF**.
3. Ensure the Elastic Agent has read permissions for the directory and files.
4. Note the absolute file path or glob pattern for use in the Kibana configuration.

## Kibana set up steps

### Collecting logs from Imperva SecureSphere via TCP.
1. In Kibana, navigate to **Management > Integrations**.
2. Search for **Imperva** and select it.
3. Click **Add Imperva**.
4. Under **Configure integration**, locate the **Collect logs from Imperva SecureSphere via TCP** section and ensure it is enabled.
5. Configure the following fields:
    - **Listen Address** (`listen_address`): The bind address to listen for TCP connections. Set to `0.0.0.0` to bind to all available interfaces. Default: `localhost`.
    - **Listen Port** (`listen_port`): The TCP port number to listen on. Default: `9507`.
    - **Timezone Offset** (`tz_offset`): When interpreting syslog timestamps without a time zone, use this timezone offset. Use this parameter to adjust the timezone offset when importing logs from a host in a different timezone.
    - **Preserve original event** (`preserve_original_event`): Preserves a raw copy of the original event, added to the field `event.original`. Default: `False`.
    - **Custom TCP Options** (`tcp_options`): Specify custom configuration options for the TCP input, such as `max_message_size: 50KiB` or `max_connections: 1`.
    - **SSL Configuration** (`ssl`): SSL configuration options.
    - **Tags** (`tags`): Custom tags to add to the events. Default: `['forwarded', 'imperva.securesphere']`.
    - **Preserve duplicate custom fields** (`preserve_duplicate_custom_fields`): Preserve `imperva.securesphere` fields that were copied to Elastic Common Schema (ECS) fields. Default: `False`.
    - **Processors** (`processors`): Add custom processors to reduce field count or enhance the event with metadata.
6. Click **Save and continue** to deploy the policy to your Elastic Agents.

### Collecting logs from Imperva SecureSphere via UDP.
1. In Kibana, navigate to **Management > Integrations**.
2. Search for **Imperva** and select it.
3. Click **Add Imperva**.
4. Under **Configure integration**, locate the **Collect logs from Imperva SecureSphere via UDP** section and ensure it is enabled.
5. Configure the following fields:
    - **Listen Address** (`listen_address`): The bind address to listen for UDP connections. Set to `0.0.0.0` to bind to all available interfaces. Default: `localhost`.
    - **Listen Port** (`listen_port`): The UDP port number to listen on. Default: `9507`.
    - **Timezone Offset** (`tz_offset`): When interpreting syslog timestamps without a time zone, use this timezone offset. Use this parameter to adjust the timezone offset when importing logs from a host in a different timezone.
    - **Preserve original event** (`preserve_original_event`): Preserves a raw copy of the original event in `event.original`. Default: `False`.
    - **Custom UDP Options** (`udp_options`): Specify custom configuration options for the UDP input, such as `max_message_size: 50KiB` or `timeout: 300s`.
    - **Tags** (`tags`): Custom tags for the event. Default: `['forwarded', 'imperva.securesphere']`.
    - **Preserve duplicate custom fields** (`preserve_duplicate_custom_fields`): Preserve `imperva.securesphere` fields that were copied to ECS fields. Default: `False`.
    - **Processors** (`processors`): Add custom processors to filter or enhance data.
6. Click **Save and continue**.

### Collecting logs from Imperva SecureSphere via File.
1. In Kibana, navigate to **Management > Integrations**.
2. Search for **Imperva** and select it.
3. Click **Add Imperva**.
4. Under **Configure integration**, locate the **Collect logs from Imperva SecureSphere via Filestream** section and ensure it is enabled.
5. Configure the following fields:
    - **Paths** (`paths`): A list of glob-based paths that will be crawled and fetched.
    - **Timezone Offset** (`tz_offset`): Used to adjust the timezone offset when importing logs from a host in a different timezone.
    - **Preserve original event** (`preserve_original_event`): Preserves a raw copy of the original event in `event.original`. Default: `False`.
    - **Tags** (`tags`): Custom tags for the event. Default: `['forwarded', 'imperva.securesphere']`.
    - **Preserve duplicate custom fields** (`preserve_duplicate_custom_fields`): Preserve `imperva.securesphere` fields that were copied to ECS fields. Default: `False`.
    - **Custom Filestream Options** (`filestream_options`): Specify custom configuration options for the Filestream input.
    - **Processors** (`processors`): Define processors to reduce field count or add metadata.
6. Click **Save and continue**.

# Validation Steps

After configuration is complete, verify that data is flowing correctly.

### 1. Trigger Data Flow on Imperva:
- **Security violation:** Attempt to access a known blocked resource to trigger a violation log.
- **Authentication event:** Log out and log back into the Imperva Management Server (MX) administration interface.
- **Configuration change:** Modify a security policy and apply the changes to generate audit logs.

### 2. Check Data in Kibana:
1. Navigate to **Discover** (or **Analytics > Discover** in some Kibana versions).
2. Select the `logs-*` data view.
3. Enter the KQL filter: `data_stream.dataset : "imperva.securesphere"`
4. Verify logs appear. Expand a log entry and confirm these fields:
   - `event.dataset` (should be `imperva.securesphere`)
   - `source.ip`
   - `event.action`
   - `message`
5. Navigate to **Dashboards** (or **Analytics > Dashboards**) and search for "Imperva" to verify pre-built visualizations are populated.

# Troubleshooting

## Common Configuration Issues

- **Incorrect Log Format**: If logs are appearing as a single `message` field without parsed sub-fields, ensure the **CEF** format was selected in the Imperva Action Set configuration.
- **Network Connectivity/Port Conflicts**: If no logs appear in Discover, verify that the Elastic Agent host is listening on the configured port. Ensure the Imperva Gateway can reach this port through any intermediate firewalls.
- **Policy Not Applied**: Logs will not be sent if the Action Set is created but not assigned. Verify the Action Set is linked in the **Followed Action** tab of the specific policy.
- **Missing "Run on Every Event"**: If logs are intermittent, check the Action Interface settings to ensure event triggering is properly configured.

## Ingestion Errors
- **Parsing Failures:** Check the `error.message` field in Kibana Discover. If you see parsing errors, ensure the Imperva appliance is not adding extra headers or prefixes to the CEF message.
- **Timezone Mismatch:** If logs appear with the wrong timestamp, adjust the **Timezone Offset** variable in the Kibana integration settings.
- **Truncated Logs:** If CEF messages are long, they may be truncated. Increase the `max_message_size` in the **Custom TCP Options** or **Custom UDP Options** in Kibana.

## Vendor Resources

- [Imperva: Working with Action Sets and Followed Actions](https://docs-cybersec.thalesgroup.com/bundle/v15.0-waf-management-server-manager-user-guide/page/Working_with_Action_Sets_and_Followed_Actions.htm) - Official guide on configuring Action Sets and Followed Actions.
- [Imperva: Alerts, Violations, and Events Guide](https://docs-cybersec.thalesgroup.com/bundle/v14.7-waf-user-guide/page/1024.htm) - Official guide on understanding data types and event structures.
