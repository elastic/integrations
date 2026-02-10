# WatchGuard Firebox Integration for Elastic

> **Note**: This documentation was generated using AI and should be reviewed for accuracy.

## Overview

The WatchGuard Firebox integration for Elastic enables you to collect and analyze logs from your WatchGuard Firebox appliances. By ingesting these logs into the Elastic Stack, you gain centralized visibility into your network security posture, traffic patterns, and system health. This integration helps you monitor firewall activity, detect potential security threats, and maintain an audit trail for compliance requirements.

This integration facilitates:
- Network traffic monitoring: Analyze flow logs to identify high-bandwidth users, unusual traffic patterns, and connection trends across trusted, optional, and external interfaces.
- Security incident detection: Monitor blocked connection attempts, intrusion prevention system (IPS) alerts, and malware detection events to identify and mitigate cyber threats.
- Compliance and auditing: Maintain long-term records of administrative logins, configuration changes, and system events to meet regulatory requirements and internal audit standards.
- Operational troubleshooting: Use detailed system logs to diagnose connectivity issues, VPN tunnel failures, and hardware performance bottlenecks within the Firebox environment.

### Compatibility

This integration is compatible with the following versions:
- WatchGuard Fireware OS: This integration is tested and verified against Fireware OS v12.10.3. It's generally compatible with Fireware v12.x versions that support standard syslog output.
- Elastic Stack: This integration requires Kibana and Elasticsearch version 8.13.0 or later (8.x and 9.x stacks are supported).

### How it works

This integration collects data by receiving syslog messages from your WatchGuard Firebox appliances. You configure the Firebox to send its logs using syslog over UDP to the host where the Elastic Agent is running. By default, the integration listens on port `9528`. 

Once the logs reach the Elastic Agent, they are processed and parsed into a structured format. The integration handles various log types, including firewall traffic logs (permitted and denied connections), security service events (IPS, Gateway AntiVirus, and so on), authentication logs for VPN and UI access, and system event logs. The structured data is then sent to Elasticsearch, where you can visualize it using the included dashboards.

## What data does this integration collect?

The WatchGuard Firebox integration collects log messages of the following types:
* Firewall traffic logs: Detailed information about permitted and denied connections, including source and destination IP addresses, ports, and protocols.
* Security service events: Logs from security modules such as Gateway AntiVirus, Intrusion Prevention Service (IPS), WebBlocker, and Application Control.
* Authentication logs: Records of user login attempts to the firewall UI, VPN connections, and proxy authentication events.
* System event logs: Internal Firebox messages regarding hardware status, service restarts, configuration updates, and High Availability (HA) failovers.

### Supported use cases

Integrating WatchGuard Firebox logs with Elastic provides visibility into your network security. You can use this data for the following:
* Network security monitoring: Track allowed and denied traffic to identify potential intrusion attempts or misconfigured rules.
* Threat detection: Monitor logs from security services like Gateway AntiVirus and IPS to respond to malicious activity in real time.
* Compliance auditing: Maintain a record of authentication events and configuration changes to meet compliance requirements.
* Operational troubleshooting: Monitor hardware health and service status to help you resolve connectivity or performance issues quickly.

## What do I need to use this integration?

To use the WatchGuard Firebox integration, you'll need to meet the following vendor and Elastic requirements:

- Administrative credentials for the Fireware Web UI or Policy Manager.
- Network connectivity between the Firebox and the Elastic Agent host. You must ensure that any intermediate firewalls allow traffic on the configured UDP port. The Elastic Agent default is `9528`, and the Firebox default is `514`.
- Standard logging enabled on individual firewall policies. Specifically, the Send a log message checkbox must be selected in the policy's logging settings. For more information, refer to [Set Logging and Notification Preferences](https://www.watchguard.com/help/docs/help-center/en-US/Content/en-US/Fireware/logging/set_logging_notif_pref_pm_c.html) in the WatchGuard documentation.
- A static IP address or DNS name for the Elastic Agent host to prevent connectivity issues if the IP changes.
- Elastic Agent installed on a host and managed through Fleet.
- Kibana version `8.13.0` or later (8.x and 9.x stacks are supported).
- Elastic Agent successfully enrolled in a Fleet policy.
- The UDP port specified in the integration (default `9528`) open on the host's firewall to allow incoming traffic from the Firebox.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the syslog receiver and ship the data to Elastic, where the events will then be processed using the integration's ingest pipelines.

### Set up steps in WatchGuard Firebox

You can configure your WatchGuard Firebox to send logs to the Elastic Agent using either the Fireware Web UI or the WatchGuard Policy Manager.

#### Configuration via Fireware Web UI

To configure your device using the web interface, follow these steps:

1. Log in to the **Fireware Web UI** using your administrative credentials.
2. From the left navigation menu, navigate to **System > Logging**.
3. Select the **Syslog Server** tab.
4. Select the check box for **Send log messages to these syslog servers**.
5. Click **Add** to define a new destination.
6. In the **IP Address** field, enter the IP address of the host where your Elastic Agent is running (replace with your actual value).
7. In the **Port** field, enter the port number configured in your Elastic integration. The Elastic Agent default is `9528`, while the Firebox default is `514`.
8. For **Log Format**, ensure you select **Syslog**.
9. Optional: Provide a **Description** such as `Elastic Agent Syslog`.
10. To ensure complete data, select the check boxes for **The time stamp** and **The serial number of the device**.
11. Under **Syslog Settings**, confirm the facility codes for different log types such as Alarm, Traffic, or Event. It's recommended to keep the defaults (Local0 - Local4).
12. Click **Save** on the Logging page to apply the changes to the Firebox Web UI.

#### Configuration via Policy Manager

To configure your device using the WatchGuard Policy Manager, follow these steps:

1. Open the **WatchGuard Policy Manager** and connect to your Firebox.
2. Navigate to **Setup > Logging**.
3. Select the **Send log messages to these syslog servers** check box.
4. Click **Add**.
5. In the configuration dialog, enter the **IP Address** of the Elastic Agent host (replace with your actual value).
6. Enter the **Port** number. The Elastic Agent default is `9528`, while the Firebox default is `514`.
7. Select **Syslog** as the **Log Format**.
8. Enable the check boxes for **The time stamp** and **The serial number of the device** to include these in the payload.
9. Verify that the **Syslog Settings** for facilities are correctly assigned, which are typically Local0 through Local4.
10. Click **OK** to close the Syslog dialog, and click **OK** again to close the Logging Setup window.
11. Save the configuration to your device by selecting **File > Save > To Firebox**.

### Set up steps in Kibana

To add the integration in Kibana, follow these steps:

1. In Kibana, navigate to **Management > Integrations**.
2. Search for and select **WatchGuard Firebox**.
3. Click **Add WatchGuard Firebox**.
4. Configure the integration with the settings for the UDP input.

The integration supports the following configuration options:

- **Listen Address** (`listen_address`): The bind address to listen for UDP connections. Set to `0.0.0.0` to bind to all available interfaces. Default: `localhost`.
- **Listen Port** (`listen_port`): The UDP port number to listen on. Default: `9528`.
- **Timezone Offset** (`tz_offset`): Use this to adjust the timezone offset when importing logs from a host in a different timezone, such as `Europe/Amsterdam` or `-05:00`. Default: `UTC`.
- **Preserve original event** (`preserve_original_event`): If checked, a raw copy of the original event's added to the field `event.original`. Default: `false`.
- **Custom UDP Options** (`udp_options`): Specify custom configuration options such as `max_message_size` or `timeout`.
- **Tags** (`tags`): Custom tags to append to the logs, for example `forwarded` or `watchguard_firebox-log`.
- **Preserve duplicate custom fields** (`preserve_duplicate_custom_fields`): If enabled, preserves WatchGuard fields that were also copied to ECS fields. Default: `false`.
- **Processors** (`processors`): Add custom processors to reduce fields or enhance metadata before parsing.

After configuring the input, choose the **Agent Policy** where you want to add the integration and click **Save and continue**.

### Validation

To verify the integration, perform the following actions to generate logs:

- **Authentication event:** Log out of the Fireware Web UI and log back in to generate an authentication event log.
- **Configuration change:** Modify a description field in a firewall policy and save the change to the device to generate a configuration event.
- **Traffic event:** From a network client behind the Firebox, browse several external websites to trigger traffic logs. Ensure "Log this action" is enabled on the policy.
- **Diagnostic event:** Use the **Diagnostic Task** tool in the Web UI to run a `ping` to an external host, such as `8.8.8.8` (replace with your actual value).

To confirm the data is in Elasticsearch, follow these steps:

1. Navigate to **Analytics > Discover**.
2. Select the `logs-*` data view.
3. Enter the KQL filter: `data_stream.dataset : "watchguard_firebox.log"`
4. Verify logs appear. Expand a log entry and confirm these fields:
    - `event.dataset` (should be `watchguard_firebox.log`)
    - `source.ip` or `destination.ip`
    - `event.action` or `event.outcome`
    - `message` (the raw log payload)
5. Navigate to **Analytics > Dashboards** and search for "WatchGuard Firebox" to see if the visualizations are populated with data.

## Troubleshooting

For help with Elastic ingest tools, check the [common problems documentation](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Common configuration issues

You might encounter the following issues when setting up or running the integration:
- No data is being collected: Verify that the `Listen Port` in your integration policy (default `9528`) exactly matches the port configured in the **Syslog Server** settings on your WatchGuard Firebox.
- Elastic Agent is rejecting packets: Ensure the `Listen Address` is set to `0.0.0.0` or the specific IP of the host interface receiving the logs. If it's set to `localhost` or `127.0.0.1`, the agent won't accept traffic from external devices.
- Network traffic is blocked: Check that the local firewall on the Elastic Agent host (for example, `iptables`, `ufw`, or Windows Firewall) allows incoming UDP traffic on the configured port.
- Specific traffic logs are missing: Ensure that individual **Firewall Policies** on your Firebox have the **Send a log message** setting enabled. Only logs from policies with this setting will be forwarded using syslog.
- Logs appear with parsing errors: If you see the `_grokparsefailure` tag in your events, verify that the Firebox is using the standard **Syslog** format rather than a legacy or proprietary format.
- Timestamps are incorrect: Adjust the `Timezone Offset` in the integration settings to match the timezone configured on your appliance.
- Missing custom fields: If you need to view non-ECS fields that are usually dropped, ensure the `Preserve duplicate custom fields` option is enabled in the integration configuration.
- General ingestion errors: You can filter for the `error.message` field in Discover to identify specific issues encountered during processing.

### Vendor resources

For more information on configuring log delivery from your device, refer to the following WatchGuard documentation:
- [WatchGuard Syslog Setup Guide](https://www.watchguard.com/help/docs/help-center/en-US/Content/en-US/Fireware/logging/send_logs_to_syslog_c.html)
- [WatchGuard Set Logging and Notification Preferences](https://www.watchguard.com/help/docs/help-center/en-US/Content/en-US/Fireware/logging/set_logging_notif_pref_pm_c.html)
- [WatchGuard Fireware v12.10 Log Catalog (PDF)](https://www.watchguard.com/help/docs/fireware/12/en-US/log_catalog/12_10_Log-Catalog.pdf)

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

To ensure optimal performance in high-volume environments, consider the following:

- Transport and collection considerations: This integration uses `UDP` for log transport. While `UDP` offers higher throughput and lower overhead compared to `TCP`, it's a connectionless protocol that doesn't guarantee delivery. In environments where log loss isn't acceptable, make sure the network path between the Firebox and the `Elastic Agent` is stable and high-speed.
- Data volume management: WatchGuard Fireboxes can generate significant log volumes, especially in high-traffic environments with "Log this action" enabled on many policies. You should consider filtering logs at the source by selecting only necessary log categories, such as Alarms and Events, or disabling logging for high-volume, low-risk internal traffic policies to reduce the load on the `Elastic Agent`.
- Elastic Agent scaling: For high-throughput environments like multi-gigabit firewalls, deploy multiple `Elastic Agents` behind a network load balancer to distribute the incoming `UDP` syslog traffic evenly. Make sure the host running the `Elastic Agent` has sufficient `CPU` and memory resources to handle the parsing overhead associated with the incoming log stream.

## Reference

### Vendor documentation links

You can find more information about WatchGuard Firebox logging and configuration in the following resources:
* [WatchGuard Fireware v12.10 Log Catalog (PDF)](https://www.watchguard.com/help/docs/fireware/12/en-US/log_catalog/12_10_Log-Catalog.pdf)
* [WatchGuard Syslog Setup Guide](https://www.watchguard.com/help/docs/help-center/en-US/Content/en-US/Fireware/logging/send_logs_to_syslog_c.html)
* [WatchGuard Set Logging and Notification Preferences](https://www.watchguard.com/help/docs/help-center/en-US/Content/en-US/Fireware/logging/set_logging_notif_pref_pm_c.html)

### Inputs used

{{ inputDocs }}

### Data streams

#### log

The `log` data stream provides events from WatchGuard Firebox of the following types: traffic, alarm, event, and system logs.

##### log fields

{{ fields "log" }}

##### log sample event

{{ event "log" }}
