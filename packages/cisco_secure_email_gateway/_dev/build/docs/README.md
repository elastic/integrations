# Cisco Secure Email Gateway Integration for Elastic

> **Note**: This documentation was generated using AI and should be reviewed for accuracy.

## Overview

The Cisco Secure Email Gateway (formerly known as Cisco Email Security Appliance or ESA) integration for Elastic enables you to collect and analyze mail flow, security events, and system performance data from your appliances. By centralizing these logs in the Elastic Stack, you'll gain visibility into your messaging environment's security posture and can monitor for email-borne threats in real-time.

This integration facilitates:
- Threat detection and response: Monitor Advanced Malware Protection (AMP), anti-spam, and anti-virus logs to identify and mitigate malicious email attachments, phishing attempts, and spam campaigns.
- Mail flow auditing: Track message transitions, delivery status, and internal SMTP system events using Text Mail logs and Consolidated Event logs to ensure reliable communication.
- Administrative compliance: Audit system access and configuration changes by collecting authentication and system logs to ensure only authorized users manage your security infrastructure.
- System health monitoring: Analyze status logs to track resource utilization like CPU, RAM, disk I/O, and queue lengths to proactively manage appliance performance.

### Compatibility

This integration is compatible with:
- Cisco Secure Email Gateway Server version 14.0.0
- Virtual Gateway Model C100V
- Logs following standard patterns defined in the Cisco ESA documentation

### How it works

This integration collects data from Cisco Secure Email Gateway using three primary methods:
- TCP: Streams logs in real-time for reliable delivery from the appliance to the Elastic Agent.
- UDP: Provides high-throughput, low-overhead collection, which is ideal for high-volume mail environments.
- Logfile: Reads logs that you've pushed via FTP to a directory monitored by the Elastic Agent.

Once the logs are received, the Elastic Agent parses the data into the Elastic Common Schema (ECS). This allows you to correlate email security events with other data sources in your environment for comprehensive analysis. The integration covers various log types including security engine results, mail flow envelopes, administrative activity, and operational performance metrics.

## What data does this integration collect?

The Cisco Secure Email Gateway integration collects various log messages from your appliance and maps them to the Elastic Common Schema (ECS). You can collect this data using the `log` data stream via log file monitoring, TCP, or UDP.

The integration collects the following functional log types:
*   Security logs: Events from security engines including Advanced Malware Protection (AMP) file reputation and analysis, anti-spam, and antivirus results.
*   Mail flow logs: Text mail logs (`mail_logs`) and Consolidated Event logs (`consolidated_event`) that contain envelope information, recipient details, and filtering verdicts.
*   Administrative logs: Authentication events, GUI logs (`gui_logs`), and system logs that track administrative logins, session activity, and configuration commits.
*   Operational logs: Status logs containing performance metrics such as CPU load, disk I/O, RAM utilization, and queue statistics.
*   Error and bounce logs: IronPort text mail logs (`error_logs`) and bounce logs that track system errors and undeliverable messages.

### Supported use cases

Integrating your Cisco Secure Email Gateway logs with the Elastic Stack helps you achieve several security and operational goals:
- Security monitoring and threat detection: You'll use security and mail flow logs to identify malicious email campaigns, monitor for malware attachments via AMP, and analyze spam trends.
- Mail flow visibility: You can track the delivery status of emails, investigate delivery failures using bounce logs, and monitor recipient activity.
- Compliance and auditing: You'll maintain a searchable record of administrative actions and configuration changes to help you meet regulatory requirements and conduct security audits.
- Operational health monitoring: You use system and status logs to monitor the performance of your gateway, ensuring resource usage remains within healthy thresholds and identifying potential hardware or software issues.

## What do I need to use this integration?

Before you can use this integration, you'll need the following Cisco Secure Email Gateway prerequisites:
- Administrative access to the gateway to configure log subscriptions.
- Network connectivity so the gateway can reach the Elastic Agent over the configured protocol, such as `TCP/UDP 514` or a custom port.
- Licenses for features like AMP, Anti-Spam, and Antivirus to generate the corresponding logs.
- An FTP server configured on the Elastic Agent host or a shared storage location if you're using the FTP Push method.
- The IP address of the Elastic Agent and a decision on which transport protocol (TCP, UDP, or Logfile) you'll use.

You also need to meet these Elastic prerequisites:
- Elastic Stack version `8.11.0` or later.
- An Elastic Agent installed on a host machine and enrolled in a Fleet policy.
- Network connectivity allowing the gateway to reach the Elastic Agent host, typically over port `514`.
- The Cisco Secure Email Gateway integration added to your Elastic Agent's policy.

## How do I deploy this integration?

### Agent-based deployment

You must install Elastic Agent on a host that can receive syslog data or access the log files from your Cisco Secure Email Gateway. For detailed installation steps, refer to the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can only install one Elastic Agent per host.

The Elastic Agent acts as a receiver for syslog streams or log files and ships the data to Elastic. Once the data reaches Elastic, ingest pipelines process the events into the correct format.

### Set up steps in Cisco Secure Email Gateway

Cisco Secure Email Gateway (formerly ESA) supports multiple methods to retrieve logs. You'll need to configure log subscriptions to push data to your Elastic Agent.

#### For syslog push (TCP/UDP)

To configure the gateway to push logs via syslog, follow these steps:

1. Log in to the Cisco Secure Email Gateway Administrator Portal.
2. Navigate to **System Administration** > **Log Subscriptions**.
3. Click **Add Log Subscription**.
4. In the **Log Type** dropdown, select a category (e.g., *Text Mail Logs*).
5. **CRITICAL:** Set the **Log Name** to exactly match the required identifier for that category. Use the mapping table below to find the correct string.
6. Set the **Log Level** to **Information**.
7. For **Retrieval Method**, select **Syslog Push**.
8. Enter the **Hostname** (the IP address of your Elastic Agent) and the **Port** you'll configure in Kibana (e.g., `514`).
9. Choose the **Protocol** (**TCP** or **UDP**) and select a **Facility** (e.g., `Local7`).
10. Click **Submit**. Repeat these steps for all necessary categories, then click **Commit Changes**.

#### For FTP push (logfile)

Some logs, such as Authentication and Bounce logs, require the FTP push method. To set this up, follow these steps:

1. Log in to the Cisco Secure Email Gateway Administrator Portal.
2. Navigate to **System Administration** > **Log Subscriptions**.
3. Click **Add Log Subscription**.
4. Select the **Log Type**.
5. **CRITICAL:** Set the **Log Name** field based on the mapping table below.
6. Set the **Log Level** to **Information**.
7. For **Retrieval Method**, select **FTP Push**.
8. Enter the **FTP Server** IP, credentials, and the destination **Directory** where the Elastic Agent will monitor files.
9. Configure the **Rollover Interval** to determine how frequently the gateway pushes logs.
10. Click **Submit** and then **Commit Changes**.

The following table lists the required log names for each log type:

| Log type selection               | Required log name (string) |
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

#### Vendor resources

You can find more details in the following vendor documentation:
- [User Guide for AsyncOS 14.0.2 for Cisco Secure Email Gateway - Logging](https://www.cisco.com/c/en/us/td/docs/security/esa/esa14-0-2/user_guide/b_ESA_Admin_Guide_14-0-2/b_ESA_Admin_Guide_12_1_chapter_0100111.html)

### Set up steps in Kibana

To set up the integration in Kibana, follow these steps:

1. In Kibana, navigate to **Management > Integrations**.
2. Search for **Cisco Secure Email Gateway** and select it.
3. Click **Add Cisco Secure Email Gateway**.
4. Choose the appropriate input method (`logfile`, `tcp`, or `udp`) based on how you configured your Cisco gateway.
5. Enter the configuration values as detailed in the subsections below.
6. Click **Save and continue** to add the integration to your Agent policy.

#### Log file input configuration

Use this section if you're collecting logs from local files or files received via FTP:

- **Paths**: Specify the list of file paths to monitor for new log data (e.g., `/var/log/cisco-esa/*.log`).
- **Preserve original event**: If you enable this, the integration adds a raw copy of the original event to the `event.original` field.
- **Tags**: Add custom tags to your exported events. The default is `['forwarded', 'cisco_secure_email_gateway-log']`.
- **Processors**: Add custom processors to reduce fields or enhance metadata before the logs are parsed. See [Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details.
- **Timezone**: Set the IANA time zone or time offset (e.g., `+0200`) to interpret syslog timestamps that don't have a time zone.

#### TCP input configuration

Use this section to configure the Agent to listen for real-time TCP syslog streams:

- **Listen Address**: The bind address the Agent uses to listen for TCP connections. Use `0.0.0.0` to listen on all interfaces.
- **Listen Port**: The TCP port number the Agent listens on (e.g., `514`).
- **Preserve original event**: If you enable this, the integration adds a raw copy of the original event to the `event.original` field.
- **SSL Configuration**: Configure SSL options for encrypted transport. You'll need to provide the certificate and key paths in YAML format.
- **Tags**: Add custom tags to your exported events.
- **Processors**: Add custom processors to enhance or filter data at the Agent level. See [Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details.
- **Timezone**: Set the IANA time zone or time offset for timestamps without zone data.

#### UDP input configuration

Use this section to configure the Agent to listen for UDP syslog datagrams:

- **Listen Address**: The bind address the Agent uses to listen for UDP connections.
- **Listen Port**: The UDP port number the Agent listens on.
- **Preserve original event**: If you enable this, the integration adds a raw copy of the original event to the `event.original` field.
- **Tags**: Add custom tags to your exported events.
- **Custom UDP Options**: Specify advanced options like `read_buffer`, `max_message_size`, or `timeout`.
- **Processors**: Add custom processors to enhance or filter data at the Agent level. See [Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details.
- **Timezone**: Set the IANA time zone or time offset for timestamps without zone data.

### Validation

To verify the integration is working correctly, you'll need to trigger some log activity and then check Kibana.

#### Trigger data flow on Cisco Secure Email Gateway

You can generate logs by performing these actions on your gateway:

- **Authentication event**: Log out of the Cisco Secure Email Gateway Administrator Portal and log back in.
- **Configuration event**: Change a minor setting in the portal, click **Submit**, and then **Commit Changes**.
- **Mail flow event**: Send a test email through the gateway.
- **System event**: Run a CLI command like `status` or `version` on the appliance.

#### Check data in Kibana

Once you've generated some activity, verify the data in Kibana:

1. Navigate to **Analytics > Discover**.
2. Select the `logs-*` data view.
3. Enter the KQL filter: `data_stream.dataset : "cisco_secure_email_gateway.log"`.
4. Check that logs appear and verify that fields like `event.dataset`, `source.ip`, and `message` are populated.
5. Navigate to **Analytics > Dashboards** and search for **Cisco Secure Email Gateway** to see if the pre-built dashboards show your data.

## Troubleshooting

For help with Elastic ingest tools, check the [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems) documentation.

### Common configuration issues

Use the following tips to resolve common issues you might encounter while using this integration:

- **Log name mismatch**: The most common issue is entering a custom string in the Log Name field on the Cisco appliance. The integration parser specifically looks for the identifiers such as `mail_logs`, `amp`, or `antispam`. If these do not match the expected strings exactly, logs will not be parsed into ECS fields.
- **Missing authentication or bounce logs**: If you are using Syslog Push and notice that Authentication and Bounce logs are missing, this is expected behavior. The Cisco appliance does not support streaming these specific categories via Syslog. You must configure an FTP Push subscription for these log types and use the logfile input.
- **Incorrect log level**: If logs are reaching Elastic but essential details are missing, verify that the Log Level on the gateway is set to `Information`. Lower levels like Warning or Error do not provide enough data for the integration to function correctly. Avoid using the `Debug` level unless you are actively troubleshooting, as it can significantly increase ingest volume.
- **Port conflicts or connectivity issues**: Ensure that the port configured in the integration settings (e.g., `514`) is not being used by another service or another Elastic Agent integration. Verify that the listen address is set to `0.0.0.0` if the Agent needs to listen on all interfaces, and check that no firewalls are blocking the traffic.
- **Parsing failures**: If logs appear in Kibana but are not parsed into specific fields, check the `error.message` field in the event. This often happens if the log format has been customized on the Cisco appliance. The integration expects the standard default logging format at the `Information` level.
- **Timezone offsets**: If logs appear with the wrong timestamp, verify the Timezone (`tz_offset`) setting in the integration configuration to ensure it matches the timezone configured on the Cisco Secure Email Gateway appliance.

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

To ensure optimal performance in high-volume email environments, consider the following strategies:
- Use TCP instead of UDP for log transmission if you require delivery guarantees for auditing or threat detection. While UDP has lower overhead, TCP ensures you don't lose log messages during network congestion.
- Use the FTP Push (logfile) method for bounce logs if your gateway version doesn't support sending them via syslog.
- Set the log level to `Information`. You should avoid using the `Debug` level unless you're actively troubleshooting, as it significantly increases CPU load and ingest volume.
- Apply log subscription filters on the gateway to exclude verbose categories like status logs if you're already monitoring those metrics with other tools.
- Scale your deployment by placing multiple Elastic Agents behind a network load balancer to distribute syslog traffic. You should place agents geographically close to your gateway appliances to minimize latency and potential packet loss for UDP traffic.

## Reference

### Inputs used

{{ inputDocs }}

### Data streams

#### log

The `log` data stream provides events from Cisco Secure Email Gateway of the following types: mail logs, system logs, authentication logs, anti-spam logs, and anti-virus logs.

##### log fields

{{ fields "log" }}

##### log sample event

{{ event "log" }}

### Vendor documentation links

You can find more information about Cisco Secure Email Gateway logging in the following resources:
- [Cisco Secure Email Product Page](https://www.cisco.com/site/us/en/products/security/secure-email/index.html)
- [Cisco ESA User Guide & Log Samples](https://www.cisco.com/c/en/us/td/docs/security/ces/user_guide/esa_user_guide_14-0/b_ESA_Admin_Guide_ces_14-0/b_ESA_Admin_Guide_12_1_chapter_0100111.html)
- [User Guide for AsyncOS 14.0.2 for Cisco Secure Email Gateway - Logging](https://www.cisco.com/c/en/us/td/docs/security/esa/esa14-0-2/user_guide/b_ESA_Admin_Guide_14-0-2/b_ESA_Admin_Guide_12_1_chapter_0100111.html)
