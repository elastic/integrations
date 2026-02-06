# Cisco ISE Integration for Elastic

> **Note**: This documentation was generated using AI and should be reviewed for accuracy.

## Overview

The Cisco ISE integration for Elastic lets you collect and parse security and operational data from Cisco Identity Services Engine. It provides comprehensive visibility into network access, authentication events, and system health within the Elastic Stack. By ingesting these logs, you'll gain insights into network activity, monitor for security threats, audit policy compliance, and troubleshoot connectivity issues.

This integration facilitates:
- Security monitoring and threat detection: You can track successful and failed authentication attempts, authorization policies applied, and user access details to identify potential security breaches or policy violations.
- Network access behavior analysis: You'll gain insights into who is accessing the network, from where, and with what devices by collecting detailed accounting data.
- Compliance and auditability: You can maintain a comprehensive audit trail of all network access activities, user authentications, and policy changes to meet regulatory compliance requirements.
- System health monitoring and troubleshooting: You can use detailed system and operational logs to diagnose problems related to network access, policy enforcement, or RADIUS server communication.

### Compatibility

This integration has been tested against Cisco Identity Services Engine (ISE) version 3.1.0.518 and later. For full compatibility, you should use ISE version 3.1.0.518 or later.

It is compatible with Elastic Stack version 8.11.0 or later.

### How it works

This integration collects logs from Cisco ISE by receiving syslog data over `tcp` or `udp` inputs. You can also configure it to read directly from local log files using the `filestream` input if the Elastic Agent has access to the host system.

When you use syslog, you'll configure Cisco ISE as a "Remote Logging Target" to send data to the Elastic Agent's listening port. The agent then processes these logs into Elastic Common Schema (ECS) fields and forwards them to your Elastic deployment, where they can be monitored and analyzed. For high-volume environments, you can deploy multiple Elastic Agents behind a load balancer to handle the incoming syslog stream.

## What data does this integration collect?

The Cisco ISE integration collects log messages including authentication, authorization, accounting (AAA) events, system messages, and policy-related logs. You can ingest these logs through TCP, UDP, or by reading from files using the filestream input. For more details, you can refer to the [Cisco ISE product page](https://www.cisco.com/site/us/en/products/security/identity-services-engine/index.html) and the official [Cisco ISE syslog documentation](https://www.cisco.com/c/en/us/td/docs/security/ise/syslog/Cisco_ISE_Syslogs/m_SyslogsList.html). Additional resources include the [Cisco ISE administrator guide](https://www.cisco.com/c/en/us/td/docs/security/ise/3-1/admin_guide/b_ise_admin_3_1/b_ISE_admin_31_deployment.html) and the [external syslog server configuration guide](https://www.cisco.com/c/en/us/support/docs/security/identity-services-engine/222223-configure-external-syslog-server-on-ise.html).

The Cisco ISE integration collects log messages of the following types:
* Passed authentications: Records of successful user and device authentication attempts.
* Failed attempts: Detailed information on unsuccessful authentication attempts, which you'll find useful for identifying brute-force attacks or unauthorized access.
* RADIUS accounting: Logs detailing session start, stop, and interim updates for tracking user activity and session duration.
* Administrative actions: Audit logs of configuration changes and access to the Cisco ISE administrator portal.
* System events: General system-level messages, service status, and diagnostic logs from the ISE appliance.
* Policy-related logs: Records of policy evaluation and decisions made by the ISE policy engine.

### Supported use cases

Integrating Cisco ISE logs with the Elastic Stack provides comprehensive visibility into your network access control and security posture. You can use this integration for the following:
* Real-time security monitoring: You can detect and respond to suspicious authentication patterns or unauthorized access attempts as they happen.
* Network visibility and auditing: You'll gain a clear view of who's connecting to your network, what devices they're using, and their session durations.
* Compliance and reporting: You can maintain a long-term, searchable archive of authentication and accounting logs to meet regulatory requirements and internal security audits.
* Incident investigation: You can accelerate your response to security incidents by correlating ISE logs with other security and network data within Elastic.

## What do I need to use this integration?

To use this integration, you'll need the following:
- Administrative access to the Cisco ISE Administrator Portal to configure remote logging targets and logging categories.
- Network connectivity between your Cisco ISE deployment and the server hosting the Elastic Agent. The agent's listening port, such as `9025` for TCP or `9026` for UDP, must be reachable from the ISE appliance, and any firewalls must allow the specified protocol and port.
- A maximum message length of `8192` bytes configured for your Cisco ISE remote logging target. This is critical to prevent log segmentation, which can lead to field mapping and parsing errors.
- Familiarity with Cisco ISE logging categories, like passed authentications or failed attempts, to select and forward the relevant log types.
- An Elastic Agent deployed and enrolled in Fleet.
- The TCP or UDP input enabled on the Elastic Agent with a listening port that matches the remote logging target settings in Cisco ISE.
- Elastic Stack version 8.0 or later.

### SSL/TLS configuration

When you use the TCP input, you should configure SSL/TLS to secure the communication between Cisco ISE and the Elastic Agent. You use the `ssl` setting to provide the necessary certificate information:

```yaml
ssl:
  certificate_authorities: ["/path/to/ca.crt"]
  certificate: "/path/to/server.crt"
  key: "/path/to/server.key"
```

If you provide incorrect file paths or invalid certificates, the Elastic Agent won't be able to start the listener, and you won't receive any logs. Ensure the agent has the correct file permissions to read the certificate and key files.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed on a host that can receive syslog data or has access to the log files from the Cisco ISE appliance. For detailed installation instructions, refer to the Elastic Agent [installation guide](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You only need to install one Elastic Agent per host.

Elastic Agent is required to stream data from the syslog or log file receiver and ship the data to Elastic, where the events are processed using the integration's ingest pipelines.

### Set up steps in Cisco ISE

You can configure Cisco ISE to send logs to the Elastic Agent using syslog or by monitoring local log files.

#### Syslog collection

Cisco ISE sends logs to external syslog servers by defining a "Remote Logging Target". This target specifies the destination server and the protocol. Use the following steps to configure the target:

1.  Log in to your Cisco ISE Administration Interface.
2.  Navigate to **Administration > System > Logging > Remote Logging Targets**.
3.  Click **Add** to create a new logging destination.
4.  Configure the remote logging target with these parameters:
    *   **Name**: Provide a descriptive name, such as `elastic-agent-syslog`.
    *   **Target Type**: Select `TCP Syslog` or `UDP Syslog`. This protocol must match your configuration in Kibana.
    *   **Status**: Ensure this is set to `Enabled`.
    *   **Host / IP Address**: Enter the IP address of the server where the Elastic Agent is running (replace with your actual value).
    *   **Port**: Enter the port number the Elastic Agent is configured to listen on. Recommended defaults are `9025` for TCP or `9026` for UDP.
    *   **Facility Code**: Choose a syslog facility code, such as `Local6` or `Local7`.
    *   **Maximum Length**: Set this value to `8192` bytes. This is critical to prevent log messages from being truncated, which can lead to parsing errors.
5.  Click **Save** to create the target. Acknowledge any warning about creating an unsecure connection if it appears.
6.  Navigate to **Administration > System > Logging > Logging Categories** to assign the target to log categories.
7.  For each category you want to forward (for example, `Passed Authentications`, `Failed Attempts`, or `Radius Accounting`), select it from the list.
8.  In the edit view for the category, find the **Targets** section.
9.  Move your newly created target from the **Available** list to the **Selected** list using the arrow icon.
10. Click **Save** for that category and repeat for all other desired categories.

#### Log file collection

If direct syslog forwarding is not feasible, you can collect logs from local files on the Cisco ISE system:

1.  Identify the log file paths on your Cisco ISE deployment that contain the desired events, such as `/var/log/cisco_ise*`.
2.  Ensure that the Elastic Agent has sufficient read permissions to access these log files.
3.  Configure log rotation on Cisco ISE to manage disk usage and ensure new data is written to files monitored by the agent.

#### Vendor resources

The following resources provide more information about Cisco ISE logging:

-   [Configure External Syslog Server On Ise.Html](https://www.cisco.com/c/en/us/support/docs/security/identity-services-engine/222223-configure-external-syslog-server-on-ise.html)
-   [B Ise Admin 31 Deployment.Html](https://www.cisco.com/c/en/us/td/docs/security/ise/3-1/admin_guide/b_ise_admin_3_1/b_ISE_admin_31_deployment.html)

### Set up steps in Kibana

1.  In Kibana, navigate to **Management > Integrations**.
2.  Search for **Cisco ISE** and select the integration.
3.  Click **Add Cisco ISE**.
4.  Configure the integration by selecting an input type that matches your Cisco ISE setup.

Choose the setup instructions below that correspond to your Cisco ISE configuration.

#### TCP input configuration

This input collects logs over a TCP socket.

| Setting | Description |
|---|---|
| **Listen Address** | The bind address for the TCP listener (for example, `0.0.0.0` (replace with your actual value)). |
| **Listen Port** | The TCP port number to listen on. Default: `9025`. |
| **Preserve original event** | If enabled, a raw copy of the original log is stored in the `event.original` field. |

Under **Advanced options**, you can configure the following:

| Setting | Description |
|---|---|
| **Timezone Offset** | Specify a canonical ID (for example, `Europe/Amsterdam`) or offset (for example, `-05:00`) to adjust timestamps for logs without timezone information. |
| **Tags** | Custom tags to add to the events. Default: `['forwarded', 'cisco_ise-log']`. |
| **Processors** | Add custom processors to filter or enhance data before it is parsed. |

#### UDP input configuration

This input collects logs over a UDP socket.

| Setting | Description |
|---|---|
| **Listen Address** | The bind address for the UDP listener (for example, `0.0.0.0` (replace with your actual value)). |
| **Listen Port** | The UDP port number to listen on. Default: `9026`. |
| **Preserve original event** | If enabled, a raw copy of the original log is stored in the `event.original` field. |

Under **Advanced options**, you can configure the following:

| Setting | Description |
|---|---|
| **Custom UDP Options** | Specify settings like `read_buffer`, `max_message_size`, or `timeout`. |
| **Timezone Offset** | Specify a canonical ID (for example, `Europe/Amsterdam`) or offset (for example, `-05:00`) for timestamp adjustment. |
| **Tags** | Custom tags to add to the events. Default: `['forwarded', 'cisco_ise-log']`. |
| **Processors** | Add custom processors to filter or enhance data before it is parsed. |

#### Log file input configuration

This input collects logs directly from files on the host where the Elastic Agent is running.

| Setting | Description |
|---|---|
| **Paths** | A list of file paths to monitor (for example, `/var/log/cisco_ise*` (replace with your actual value)). |
| **Preserve original event** | If enabled, a raw copy of the original log is stored in the `event.original` field. |

Under **Advanced options**, you can configure the following:

| Setting | Description |
|---|---|
| **Timezone Offset** | Specify a canonical ID (for example, `Europe/Amsterdam`) or offset (for example, `-05:00`) for timestamp adjustment. |
| **Tags** | Custom tags to add to the events. Default: `['forwarded', 'cisco_ise-log']`. |
| **Processors** | Add custom processors to filter or enhance data before it is parsed. |

### Validation

After you have completed the configuration, follow these steps to verify that data is flowing correctly:

1.  Navigate to **Management > Fleet > Agents** and verify that the Elastic Agent status is **Healthy** and **Online**.
2.  Trigger data flow on Cisco ISE by performing a test authentication or an administrative action, such as logging into the ISE portal or updating a configuration setting.
3.  In Kibana, navigate to **Analytics > Discover**.
4.  Select the `logs-*` data view and enter the following KQL filter: `data_stream.dataset : "cisco_ise.log"`
5.  Verify that logs appear with populated fields such as `event.dataset`, `source.ip`, `event.action`, and `user.name`.
6.  Navigate to **Analytics > Dashboards** and search for "Cisco ISE" to view the pre-built visualizations and confirm they are being populated with data.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Common configuration issues

You might encounter these issues when configuring the Cisco ISE integration:

- Maximum message length not set to `8192`: If the **Maximum Length** isn't set to `8192` in the Cisco ISE remote logging target configuration, syslog messages might be truncated before being sent to the Elastic Agent. This leads to incomplete log entries and parsing failures, resulting in missing fields or malformed events in Kibana. To fix this, navigate to **Administration > System > Logging > Remote Logging Targets**, edit the target, and set the **Maximum Length** to `8192`.
- Port or protocol mismatch: Your Elastic Agent might be configured to listen on a different port or protocol than what Cisco ISE is sending. Verify that the **Target Type** (`TCP Syslog` or `UDP Syslog`) and **Port** configured in the Cisco ISE remote logging target match the input type and port configured for the integration in Kibana.
- Network connectivity issues: Firewalls, routing issues, or incorrect IP address configuration can prevent Cisco ISE from reaching the Elastic Agent host. Check firewall rules on both the Cisco ISE server and the Elastic Agent host to ensure the configured syslog port (for example, `9025` for TCP or `9026` for UDP) is open and accessible.
- Logging categories not enabled: Cisco ISE won't send logs unless specific logging categories are explicitly assigned to a remote logging target. Ensure your target is selected in the **Remote Logging Targets** list for each desired category under **Administration > System > Logging > Logging Categories**.
- SSL/TLS configuration issues: When you're using the `ssl` settings for TCP, ensure that certificate and key file paths are correct and that the Elastic Agent has sufficient permissions to access them. Mismatched certificates or incorrect `YAML` configuration will prevent the agent from establishing a secure connection.
- Parsing failures due to malformed logs: Cisco ISE logs that are segmented or contain unexpected formats can cause parsing errors. Review the raw logs in Kibana by checking the `message` or `event.original` field for `_grokparsefailure` tags. Ensure the **Maximum Length** in Cisco ISE is set to `8192`.
- UDP buffer limitations: In high-volume environments using the UDP input, you might need to increase the `read_buffer` size in the advanced settings to prevent packet loss during bursts of activity. The default is `100MiB`.

### Vendor resources

For more information about Cisco ISE and syslog configuration, refer to these resources:

- [Configure External Syslog Server On ISE](https://www.cisco.com/c/en/us/support/docs/security/identity-services-engine/222223-configure-external-syslog-server-on-ise.html)
- [Cisco ISE 3.1 Administration Guide - Deployment](https://www.cisco.com/c/en/us/td/docs/security/ise/3-1/admin_guide/b_ise_admin_3_1/b_ISE_admin_31_deployment.html)
- [Cisco ISE Syslog Documentation](https://www.cisco.com/c/en/us/td/docs/security/ise/syslog/Cisco_ISE_Syslogs/m_SyslogsList.html)
- [Cisco ISE Product Page](https://www.cisco.com/site/us/en/products/security/identity-services-engine/index.html)

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

### Transport and collection considerations

When you're configuring syslog, choosing between TCP and UDP involves a trade-off:
- TCP (port `9025`) offers guaranteed delivery, ensuring you don't lose logs, which is critical for security and compliance data.
- UDP (port `9026`) offers higher speed and lower overhead but doesn't guarantee delivery, making it suitable for less critical, high-volume log streams where some loss is acceptable.
- It's critical to set the Maximum Message Length in Cisco ISE to `8192` bytes to prevent log segmentation, which can lead to parsing issues and incorrect field mappings in the Elastic Agent.
- If you're using UDP, you should increase the `read_buffer` in the UDP options to prevent packet loss during traffic spikes.

### Data volume management

Cisco ISE can generate a significant volume of logs depending on your network activity and configured policies. To manage data volume efficiently, you should carefully select which logging categories in Cisco ISE are forwarded to the Elastic Agent:
- Prioritize critical categories such as `Passed Authentications`, `Failed Attempts`, and `Radius Accounting`.
- Filtering at the source reduces the load on both the Cisco ISE system and the Elastic Agent.
- Configure log rotation settings on Cisco ISE to ensure that the agent handles new log data without processing excessively large individual files.

### Elastic Agent scaling

For environments with high log volumes, a single Elastic Agent might reach its capacity limits. In these scenarios, you should consider the following strategies:
- Deploy multiple Elastic Agents, each configured to receive logs from different Cisco ISE logging targets or specific log categories.
- Use a load balancer to distribute incoming TCP or UDP traffic across multiple Elastic Agent instances to prevent any single agent from becoming a bottleneck.
- Place Elastic Agents strategically, ideally close to the Cisco ISE instances, to minimize network latency.
- Ensure the Elastic Agent host has adequate CPU, memory, and disk I/O resources, such as SSD-backed storage, to handle the anticipated log ingestion rate.

### Secure log transmission

While encryption adds some computational overhead, it's necessary for protecting sensitive authentication data. You can configure SSL/TLS settings for TCP inputs:
- `enabled`: Set to `true` to enable SSL.
- `certificate`: The path to the certificate file.
- `key`: The path to the certificate key file.

Here's an example of a secure configuration for the TCP input:

```yaml
ssl:
  enabled: true
  certificate: "/etc/pki/client/cert.pem"
  key: "/etc/pki/client/cert.key"
  certificate_authorities: ["/etc/pki/ca/ca.pem"]
  verification_mode: "full"
```

**Warning:** Using `verification_mode: "none"` is insecure because it doesn't verify the server's identity. Don't use this in production environments.

## Reference

### Inputs used

{{ inputDocs }}

### Data streams

The Cisco ISE integration includes the following data stream:
- `log`

#### `log`

The `log` data stream provides events from Cisco ISE of the following types: authentication, accounting, and system events. This includes logs for passed authentications, failed attempts, and RADIUS accounting.

##### `log` fields

The following table lists the exported fields for this data stream:

{{ fields "log" }}

##### `log` sample event

It's an example of what a sample event looks like for this data stream:

{{ event "log" }}

### Performance and scaling

To ensure the integration performs reliably as your environment grows, you should follow these recommendations:
- You must set the Maximum Length to `8192` bytes in your Cisco ISE configuration. This prevents the Elastic Agent from having to process fragmented syslog messages, which can significantly increase CPU usage and cause parsing failures.
- You should monitor the Elastic Agent's resource consumption during peak hours to ensure it can keep up with the volume of authentication and accounting logs.
- You should ensure that any firewalls or load balancers in the data path are configured to handle the expected syslog throughput.

### Vendor documentation links

You can refer to the following official resources for more information about Cisco ISE and its syslog implementation:
- [Configure external syslog server on ISE](https://www.cisco.com/c/en/us/support/docs/security/identity-services-engine/222223-configure-external-syslog-server-on-ise.html)
- [Cisco ISE administration guide: Deployment](https://www.cisco.com/c/en/us/td/docs/security/ise/3-1/admin_guide/b_ise_admin_3_1/b_ISE_admin_31_deployment.html)
- [Official Cisco ISE syslog documentation](https://www.cisco.com/c/en/us/td/docs/security/ise/syslog/Cisco_ISE_Syslogs/m_SyslogsList.html)
- [Official Cisco ISE product page](https://www.cisco.com/site/us/en/products/security/identity-services-engine/index.html)
