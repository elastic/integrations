# Service Info

## Common use cases

The Cisco Secure Email Gateway (formerly Email Security Appliance or ESA) integration enables security administrators to ingest, parse, and analyze critical mail flow and security event data within the Elastic Stack. This visibility is essential for maintaining a secure messaging environment and responding to email-borne threats.

- **Threat Detection and Response:** Monitor Advanced Malware Protection (AMP), Anti-Spam, and Anti-Virus logs to identify and mitigate malicious email attachments, phishing attempts, and spam campaigns in real-time.
- **Mail Flow Auditing:** Track message transitions, delivery status, and internal SMTP system events using Text Mail Logs and Consolidated Event Logs to ensure reliable communication.
- **Administrative Compliance:** Audit system access and configuration changes by collecting Authentication and System logs, ensuring that only authorized users are managing the security infrastructure.
- **System Health Monitoring:** Analyze Status logs to keep track of resource utilization (CPU, RAM, Disk I/O) and queue lengths to proactively manage the performance of the Secure Email Gateway appliance.

## Data types collected

This integration collects several streams of data from Cisco Secure Email Gateway. Each stream is parsed into the Elastic Common Schema (ECS) to enable cross-source analysis:

- **Cisco Secure Email Gateway logs (logfile):** Collects Cisco Secure Email Gateway logs via logfile. This stream is typically used for logs pushed via FTP to a directory monitored by the Elastic Agent. It captures security, mail flow, and system events stored as local files.
- **Cisco Secure Email Gateway logs (tcp):** Collects Cisco Secure Email Gateway logs via TCP input. This stream provides reliable delivery for real-time log streaming from the appliance, ensuring no data is lost during network spikes.
- **Cisco Secure Email Gateway logs (udp):** Collects Cisco Secure Email Gateway logs via UDP input. This stream allows for high-throughput, low-overhead log collection, ideal for high-volume mail environments where minor packet loss is acceptable in exchange for performance.

The integration covers the following functional log types:
- **Security Logs:** Detailed events from security engines including AMP (File Reputation/Analysis), Anti-Spam, and Antivirus results.
- **Mail Flow Logs:** Text Mail logs (`mail_logs`) and Consolidated Event logs (`consolidated_event`) containing envelope information, recipient details, and filtering verdicts.
- **Administrative Logs:** Authentication events, GUI logs (`gui_logs`), and System logs tracking administrative logins, session activity, and configuration commits.
- **Operational Logs:** Status logs containing performance metrics such as CPU load, disk I/O, RAM utilization, and queue statistics.
- **Error and Bounce Logs:** IronPort Text Mail logs (`error_logs`) and Bounce logs tracking system errors and undeliverable messages.

## Compatibility
The **Cisco Secure Email Gateway** (formerly known as Cisco Email Security Appliance or ESA) integration has been specifically tested and validated against the following:
- **Cisco Secure Email Gateway Server version 14.0.0**
- **Virtual Gateway Model C100V**
- Logs following the standard patterns defined in the Cisco ESA documentation.

## Scaling and Performance

To ensure optimal performance in high-volume email environments, consider the following:
- **Transport/Collection Considerations:** While UDP is available for low-overhead transmission, TCP is recommended for environments where delivery guarantees are required (e.g., auditing or threat detection). TCP ensures no log messages are lost due to network congestion. For maximum data integrity, especially for Bounce logs which are not supported via Syslog on certain versions, use the FTP Push (logfile) method.
- **Data Volume Management:** Configure the gateway to forward only necessary events by setting the log level to **Information**. Avoid forwarding **Debug** level logs unless actively troubleshooting, as they can significantly increase CPU load and ingest volume. Use the gateway's log subscription filters to exclude verbose but low-value categories like Status logs if they are redundant with other monitoring tools.
- **Elastic Agent Scaling:** For high-throughput environments or large gateway clusters, deploy multiple Elastic Agents behind a network load balancer to distribute the syslog traffic evenly. Placing Agents geographically close to the gateway appliances can minimize latency and potential packet loss for UDP traffic.

# Set Up Instructions

## Vendor prerequisites

1.  **Administrative Access:** A user account with Administrator privileges on the Cisco Secure Email Gateway is required to configure Log Subscriptions.
2.  **Network Connectivity:** The gateway must be able to reach the Elastic Agent over the configured protocol. Ensure firewall rules allow traffic on the chosen port (typically **TCP/UDP 514** or a custom high port).
3.  **Log Feature Licenses:** Ensure relevant features (AMP, Anti-Spam, Antivirus) are licensed and enabled to generate the corresponding logs.
4.  **FTP Server:** If using the **FTP Push** method, the Elastic Agent host (or a shared storage location accessible by the Agent) must be configured to receive files via FTP.
5.  **Information Requirements:** You must know the IP address of the Elastic Agent and decide on the transport protocol (TCP/UDP/Logfile) before beginning the configuration.

## Elastic prerequisites
- **Elastic Stack version:** 8.11.0 or later is recommended for full feature support.
- **Elastic Agent:** Must be installed on a host machine and enrolled in a Fleet policy.
- **Network Connectivity:** The Elastic Agent must be reachable from the Cisco Secure Email Gateway appliance over the network for TCP/UDP ingestion (typically port `514`).
- **Integration Policy:** The Cisco Secure Email Gateway integration must be added to the Elastic Agent's policy via the Kibana UI.

## Vendor set up steps

The Cisco Secure Email Gateway supports multiple log retrieval methods. Follow the steps below for your preferred collection strategy.

### For Syslog Push (TCP/UDP):
1. Log in to the **Cisco Secure Email Gateway** Administrator Portal.
2. Navigate to **System Administration** > **Log Subscriptions**.
3. Click **Add Log Subscription**.
4. In the **Log Type** dropdown, select a category (e.g., *Text Mail Logs*).
5. **CRITICAL:** Set the **Log Name** to exactly match the required identifier for that category (e.g., `mail_logs`). Refer to the mapping table below.
6. Set the **Log Level** to **Information**.
7. For **Retrieval Method**, select **Syslog Push**.
8. Enter the **Hostname** (IP address of your Elastic Agent) and the **Port** (e.g., `514`).
9. Choose the **Protocol** (**TCP** or **UDP**) and select a **Facility** (e.g., `Local7`).
10. Click **Submit**. Repeat these steps for all necessary categories, then click **Commit Changes**.

### For FTP Push (Logfile):
1. Log in to the **Cisco Secure Email Gateway** Administrator Portal.
2. Navigate to **System Administration** > **Log Subscriptions**.
3. Click **Add Log Subscription**.
4. Select the **Log Type** (Note: Authentication and Bounce logs MUST use this method).
5. **CRITICAL:** Set the **Log Name** field based on the mapping table below.
6. Set the **Log Level** to **Information**.
7. For **Retrieval Method**, select **FTP Push**.
8. Enter the **FTP Server** IP, credentials, and the destination **Directory** where the Elastic Agent will monitor files.
9. Configure the **Rollover Interval** to determine how frequently logs are pushed.
10. Click **Submit** and then **Commit Changes**.

| Log Type Selection               | Required Log Name (String) |
| :------------------------------- | :------------------------- |
| AMP Engine Logs                  | `amp`                      |
| Anti-Spam Logs                   | `antispam`                 |
| Anti-Virus Logs                  | `antivirus`                |
| Authentication Logs              | `authentication`           |
| Bounce Logs                      | `bounces`                  |
| Consolidated Event Logs          | `consolidated_event`       |
| Content Scanner Logs             | `content_scanner`          |
| HTTP Logs                        | `gui_logs`                 |
| IronPort Text Mail Logs (Errors) | `error_logs`               |
| Text Mail Logs                   | `mail_logs`                |
| Status Logs                      | `status`                   |
| System Logs                      | `system`                   |

### Vendor Set up Resources

- [User Guide for AsyncOS 14.0.2 for Cisco Secure Email Gateway - Logging](https://www.cisco.com/c/en/us/td/docs/security/esa/esa14-0-2/user_guide/b_ESA_Admin_Guide_14-0-2/b_ESA_Admin_Guide_12_1_chapter_0100111.html) - Official documentation on configuring log subscriptions and retrieval methods.

## Kibana set up steps

1. In Kibana, navigate to **Management > Integrations**.
2. Search for **Cisco Secure Email Gateway** and select it.
3. Click **Add Cisco Secure Email Gateway**.
4. Choose the appropriate input method (logfile, tcp, or udp) based on your vendor configuration.
5. Enter the configuration values as detailed in the subsections below.
6. Click **Save and continue** to add the integration to your Agent policy.

### Collecting Cisco Secure Email Gateway logs.
Use this section to configure log collection from local files or files received via FTP.
- **Paths** (name: `paths`): Specify the list of file paths to monitor for new log data. For example: `/var/log/cisco-esa/*.log`.
- **Preserve original event** (name: `preserve_original_event`): If enabled, a raw copy of the original event is added to the field `event.original`. Default: `False`.
- **Tags** (name: `tags`): A list of custom tags to add to the exported events. Default: `['forwarded', 'cisco_secure_email_gateway-log']`.
- **Processors** (name: `processors`): Add custom processors to reduce fields or enhance metadata before the logs are parsed. See [Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details.
- **Timezone** (name: `tz_offset`): The IANA time zone or time offset (e.g., `+0200`) used to interpret syslog timestamps that lack a time zone. Default: `UTC`.

### Collecting Cisco Secure Email Gateway logs via TCP input.
Use this section to configure the Elastic Agent to listen for real-time TCP syslog streams.
- **Listen Address** (name: `listen_address`): The bind address the Agent uses to listen for TCP connections. Use `0.0.0.0` to listen on all interfaces. Default: `localhost`.
- **Listen Port** (name: `listen_port`): The TCP port number the Agent listens on. Default: `514`.
- **Preserve original event** (name: `preserve_original_event`): If enabled, a raw copy of the original event is added to the field `event.original`. Default: `False`.
- **SSL Configuration** (name: `ssl`): Configure SSL options for encrypted transport. Use the YAML format to specify the certificate and key paths.
- **Tags** (name: `tags`): A list of custom tags to add to the exported events. Default: `['forwarded', 'cisco_secure_email_gateway-log']`.
- **Processors** (name: `processors`): Add custom processors to enhance or filter data at the Agent level. See [Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details.
- **Timezone** (name: `tz_offset`): The IANA time zone or time offset used for timestamps without zone data. Default: `UTC`.

### Collecting Cisco Secure Email Gateway logs via UDP input.
Use this section to configure the Elastic Agent to listen for UDP syslog datagrams.
- **Listen Address** (name: `listen_address`): The bind address the Agent uses to listen for UDP connections. Use `0.0.0.0` to listen on all interfaces. Default: `localhost`.
- **Listen Port** (name: `listen_port`): The UDP port number the Agent listens on. Default: `514`.
- **Preserve original event** (name: `preserve_original_event`): If enabled, a raw copy of the original event is added to the field `event.original`. Default: `False`.
- **Tags** (name: `tags`): A list of custom tags to add to the exported events. Default: `['forwarded', 'cisco_secure_email_gateway-log']`.
- **Custom UDP Options** (name: `udp_options`): Specify advanced configuration options for the UDP input, such as `read_buffer`, `max_message_size`, or `timeout`.
- **Processors** (name: `processors`): Add custom processors to enhance or filter data at the Agent level. See [Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details.
- **Timezone** (name: `tz_offset`): The IANA time zone or time offset used for timestamps without zone data. Default: `UTC`.

# Validation Steps

After configuration is complete, verify that data is flowing correctly.

### 1. Trigger Data Flow on Cisco Secure Email Gateway:
- **Authentication event:** Log out of the Cisco Secure Email Gateway Administrator Portal and log back in to trigger authentication logs.
- **Configuration event:** Navigate to any setting in the portal, make a minor change, click **Submit**, and then **Commit Changes**.
- **Mail flow event:** Send a test email through the gateway to trigger Text Mail and Consolidated Event log entries.
- **System event:** Run a CLI command like `status` or `version` on the appliance to generate system-level log entries.

### 2. Check Data in Kibana:
1. Navigate to **Analytics > Discover**.
2. Select the `logs-*` data view.
3. Enter the KQL filter: `data_stream.dataset : "cisco_secure_email_gateway.log"`
4. Verify logs appear. Expand a log entry and confirm these fields are populated:
   - `event.dataset` (should be `cisco_secure_email_gateway.log`)
   - `source.ip` (the IP of the Cisco appliance)
   - `event.action` or `event.outcome` (e.g., `login`, `delivered`)
   - `message` (the raw log payload)
5. Navigate to **Analytics > Dashboards** and search for "Cisco Secure Email Gateway" to verify data is populating the pre-built dashboards.

# Troubleshooting

## Common Configuration Issues

- **Log Name Mismatch**: The most common issue is entering a custom string in the "Log Name" field on the Cisco appliance. The integration parser specifically looks for the identifiers listed in the mapping table (e.g., `mail_logs`, `amp`). If these do not match exactly, logs will not be parsed into ECS fields.
- **Missing Authentication/Bounce Logs**: If you are using Syslog Push and notice that Authentication and Bounce logs are missing, this is expected behavior. The Cisco appliance does not support streaming these specific categories via Syslog; you must configure an **FTP Push** subscription for these log types.
- **Incorrect Log Level**: If logs are reaching Elastic but essential details are missing, verify that the **Log Level** is set to **Information**. Lower levels like "Warning" or "Error" do not provide enough data for the integration to function correctly.
- **Port Conflicts**: Ensure that the port configured in Kibana (e.g., 514) is not being used by another service or another Elastic Agent integration. Verify the bind address is set to `0.0.0.0` if the Agent needs to listen on all interfaces.

## Ingestion Errors
- **Unsupported Retrieval Method**: Be aware that the "Syslog Push" method on Cisco ESA explicitly excludes `authentication` and `bounces` categories in certain versions. If these logs are required, use the "FTP Push" (logfile) method instead.
- **Parsing Failures**: If logs appear in Kibana but are not parsed into specific fields, check the `error.message` field. This often happens if the log format has been customized on the Cisco appliance; the integration expects the standard default logging format at the `Information` level.
- **Timezone Offsets**: If logs appear with the wrong timestamp, verify the `Timezone` (**tz_offset**) variable in the Kibana configuration to ensure it matches the timezone configured on the Cisco appliance.

## Vendor Resources

- [Cisco Secure Email Product Page](https://www.cisco.com/site/us/en/products/security/secure-email/index.html)
- [Cisco ESA User Guide & Log Samples](https://www.cisco.com/c/en/us/td/docs/security/ces/user_guide/esa_user_guide_14-0/b_ESA_Admin_Guide_ces_14-0/b_ESA_Admin_Guide_12_1_chapter_0100111.html)

# Documentation sites

- [Cisco Secure Email Product Page](https://www.cisco.com/site/us/en/products/security/secure-email/index.html)
- [User Guide for AsyncOS 14.0.2 for Cisco Secure Email Gateway - Logging](https://www.cisco.com/c/en/us/td/docs/security/esa/esa14-0-2/user_guide/b_ESA_Admin_Guide_14-0-2/b_ESA_Admin_Guide_12_1_chapter_0100111.html)
