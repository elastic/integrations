# Cisco ISE Integration for Elastic

> **Note**: This documentation was generated using AI and should be reviewed for accuracy.

## Overview

The Cisco ISE integration for Elastic lets you collect logs from Cisco Identity Services Engine. It provides comprehensive visibility into network access, authentication events, and system health within the Elastic Stack. By ingesting Cisco ISE logs, you'll gain insights into network activity, monitor for security threats, audit policy compliance, and troubleshoot connectivity issues.

This integration facilitates:
- Security monitoring and threat detection: Tracks authentication attempts, authorization changes, and policy matches.
- Network traffic analysis: Monitors RADIUS and TACACS+ accounting data for network usage patterns.
- Compliance auditing: Provides a detailed audit trail for administrative actions and user access.
- System health monitoring: Collects system-level logs to ensure the stability and performance of your ISE deployment.

### Compatibility

We've tested this integration with Cisco ISE versions 3.1.0.518. We expect newer versions to work, but we haven't tested them yet.

This integration is compatible with Elastic Stack version 8.11.0 or higher.

### How it works

This integration collects logs from Cisco ISE by receiving syslog data over TCP or UDP. You can also configure it to read directly from log files if the Elastic Agent has access to the host system. When you use syslog, you'll configure Cisco ISE as a "Remote Logging Target" to send data to the Elastic Agent's listening port. The agent then processes these logs into Elastic Common Schema (ECS) fields and forwards them to your Elastic deployment.

### Performance and scaling

To ensure high performance in large-scale Cisco ISE environments, you should consider the following:
- Load balancing: Use a load balancer to distribute syslog traffic across multiple Elastic Agents if you're handling a high volume of events.
- Resource allocation: Monitor the CPU and memory usage of the host running the Elastic Agent, especially when using the `ssl` configuration or complex `processors`.
- Log segmentation: Always set the `Maximum Length` on your Cisco ISE Remote Logging Target to `8192` bytes. This prevents log fragmentation, which reduces processing overhead and ensures accurate parsing.

### Setup and configuration

To get started with the Cisco ISE integration, you'll need to prepare your Cisco ISE environment and then configure the integration in Kibana.

### Vendor documentation links
You can find more information about configuring Cisco ISE in the following resources:
- [Configure External Syslog Server On Ise](https://www.cisco.com/c/en/us/support/docs/security/identity-services-engine/222223-configure-external-syslog-server-on-ise.html)
- [B Ise Admin 31 Deployment](https://www.cisco.com/c/en/us/td/docs/security/ise/3-1/admin_guide/b_ise_admin_3_1/b_ISE_admin_31_deployment.html)
- [Official Cisco ISE Syslog Documentation](https://www.cisco.com/c/en/us/td/docs/security/ise/syslog/Cisco_ISE_Syslogs/m_SyslogsList.html)
- [Official Cisco ISE Product Page](https://www.cisco.com/site/us/en/products/security/identity-services-engine/index.html)
- [Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html)

## What data does this integration collect?

The Cisco ISE integration collects log messages of the following types:
- **Passed Authentications**: Records of successful user and device authentication attempts.
- **Failed Attempts**: Detailed information on unsuccessful authentication attempts, which is useful for identifying brute-force attacks or unauthorized access.
- **RADIUS Accounting**: Logs detailing session start, stop, and interim updates for tracking user activity and session duration.
- **Administrative Actions**: Audit logs of configuration changes and access to the Cisco ISE Administrator Portal.
- **System Events**: General system-level messages, service status, and diagnostic logs from the ISE appliance.

### Supported use cases

Integrating Cisco ISE logs with the Elastic Stack provides comprehensive visibility into your network access control and security posture. You can use this integration for:
- **Real-time security monitoring**: You can detect and respond to suspicious authentication patterns or unauthorized access attempts as they happen.
- **Network visibility and auditing**: You can gain a clear view of who's connecting to your network, what devices they're using, and their session durations.
- **Compliance and reporting**: You can maintain a long-term, searchable archive of authentication and accounting logs to meet regulatory requirements and internal security audits.
- **Incident investigation**: You can accelerate your response to security incidents by correlating ISE logs with other security and network data within Elastic.

### SSL/TLS configuration

When you configure the integration to collect data over encrypted connections, you must provide valid certificate settings.

For secure communication, you can use the `ssl` configuration options. These include settings for the certificate authority (CA), server certificate, and private key. You can find more details in the [SSL configuration documentation](https://www.elastic.co/guide/en/beats/filebeat/current/configuration-ssl.html#ssl-common-config).

Example SSL configuration for a TCP input:
```yaml
ssl:
  enabled: true
  certificate_authorities: ["/etc/pki/root/ca.pem"]
  certificate: "/etc/pki/client/cert.pem"
  key: "/etc/pki/client/cert.key"
```

### Performance and scaling

To ensure your Cisco ISE integration scales efficiently as your log volume grows, consider the following guidance:
- **Efficient file discovery**: If you're collecting logs from files using the filestream input, use prospector configurations to manage how the agent discovers and monitors files.
- **Rotated logs**: For environments with high log rotation, configure fingerprint-based file identity to ensure the agent correctly tracks files even after they've been renamed.
- **UDP buffer sizes**: When you're using the UDP input, you may need to increase the `read_buffer` size (e.g., to `100MiB`) to prevent packet loss during traffic spikes.
- **Processor usage**: Use [Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) to drop unnecessary fields early in the pipeline, which reduces the processing load on the agent and the amount of data sent to Elasticsearch.

### Vendor documentation links

For more information about configuring Cisco ISE and understanding its log formats, refer to the following resources:
- [Configure External Syslog Server On Ise](https://www.cisco.com/c/en/us/support/docs/security/identity-services-engine/222223-configure-external-syslog-server-on-ise.html)
- [B Ise Admin 31 Deployment](https://www.cisco.com/c/en/us/td/docs/security/ise/3-1/admin_guide/b_ise_admin_3_1/b_ISE_admin_31_deployment.html)
- [Official Cisco ISE Syslog Documentation](https://www.cisco.com/c/en/us/td/docs/security/ise/syslog/Cisco_ISE_Syslogs/m_SyslogsList.html)
- [Official Cisco ISE Product Page](https://www.cisco.com/site/us/en/products/security/identity-services-engine/index.html)

## What do I need to use this integration?

To use this integration, you'll need the following:

- Administrative access to the Cisco ISE Administrator Portal to configure remote logging targets and logging categories.
- Network connectivity between your Cisco ISE deployment and the server hosting the Elastic Agent.
- Access to the Cisco ISE Administration Interface to set the **Maximum Message Length** to `8192` bytes for remote logging targets. This is critical to prevent log segmentation and parsing errors.
- Elastic Stack version 8.11.0 or higher.

### SSL/TLS configuration

When you use the TCP input, you should configure SSL/TLS to secure the communication between Cisco ISE and the Elastic Agent. You use the `ssl` setting to provide the necessary certificate information.

```yaml
ssl:
  certificate_authorities: ["/path/to/ca.crt"]
  certificate: "/path/to/server.crt"
  key: "/path/to/server.key"
```

**Warning**: If you provide incorrect file paths or invalid certificates, the Elastic Agent won't be able to start the listener, and you won't receive any logs. Ensure the agent has the correct file permissions to read the certificate and key files.

### Performance and scaling

To ensure your deployment can handle the volume of logs generated by Cisco ISE, consider the following:

- Use the TCP input instead of UDP for high-traffic environments to ensure reliable delivery and allow for SSL/TLS encryption.
- Monitor the CPU and memory usage of the host running the Elastic Agent. High event rates may require vertical scaling of the host resources.
- If you're using the UDP input and notice dropped packets, you can increase the `read_buffer` size in the `udp_options` configuration to help handle spikes in traffic.
- For very large deployments, you can deploy multiple Elastic Agents and use a load balancer to distribute the syslog traffic from Cisco ISE.

### Vendor resources

For more information on configuring your environment, refer to the following Cisco and Elastic resources:

- [Configure External Syslog Server On Ise](https://www.cisco.com/c/en/us/support/docs/security/identity-services-engine/222223-configure-external-syslog-server-on-ise.html)
- [B Ise Admin 31 Deployment](https://www.cisco.com/c/en/us/td/docs/security/ise/3-1/admin_guide/b_ise_admin_3_1/b_ISE_admin_31_deployment.html)
- [Official Cisco ISE Syslog Documentation](https://www.cisco.com/c/en/us/td/docs/security/ise/syslog/Cisco_ISE_Syslogs/m_SyslogsList.html)
- [Official Cisco ISE Product Page](https://www.cisco.com/site/us/en/products/security/identity-services-engine/index.html)
- [Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html)

## How do I deploy this integration?

### Agent-based deployment

The Elastic Agent is a unified agent that collects data from your systems and ships it to Elastic. Elastic Agent is required to stream data from the syslog or log file receiver and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

To deploy this integration:

1. **Install Elastic Agent** on a host that has network access to both your Elastic deployment and the data source.
   - See the [Elastic Agent installation guide](https://www.elastic.co/guide/en/fleet/current/install-fleet-managed-elastic-agent.html)

2. **Enroll the agent** in Fleet:
   - In Kibana, go to **Management** → **Fleet** → **Agents**
   - Click **Add agent** and follow the enrollment instructions

3. **Add the integration** to an agent policy:
   - Go to **Management** → **Integrations**
   - Search for "Cisco ISE"
   - Click **Add Cisco ISE** and configure the settings
   - Assign to an existing policy or create a new one

The following table summarizes the network requirements:

| Direction | Protocol | Port | Purpose |
|-----------|----------|------|----------|
| Agent → Elastic | HTTPS | 443 | Data shipping to Elasticsearch |
| Source → Agent | TCP | 514 (configurable) | Syslog reception |
| Source → Agent | UDP | 514 (configurable) | Syslog reception |
| Agent (local) | — | — | File read access required |

### Onboard and configure

Before you can collect data, ensure you have the necessary permissions and network access. You'll need administrative access to the Cisco ISE Administrator Portal and a clear network path between the Cisco ISE appliance and the host running the Elastic Agent.

### Set up steps in Cisco ISE

Cisco ISE sends logs to external syslog servers by defining a "Remote Logging Target." This target specifies the destination server (Elastic Agent) and the protocol. Please follow these setup steps:

1.  Log in to your Cisco ISE Administration Interface.
2.  Navigate to **Administration > System > Logging > Remote Logging Targets**.
3.  Click **Add** to create a new logging destination.
4.  Configure the remote logging target with the following parameters:
    *   **Name**: Provide a descriptive name, for example, `elastic-agent-syslog`.
    *   **Target Type**: Select `TCP Syslog` or `UDP Syslog`. This protocol must match the input configuration of your Elastic Agent.
    *   **Status**: Ensure this is set to **Enabled**.
    *   **Host / IP Address**: Enter the IP address of the server where the Elastic Agent is running.
    *   **Port**: Enter the port number the Elastic Agent is configured to listen on. The recommended defaults are `9025` for `TCP` or `9026` for `UDP`.
    *   **Facility Code**: Choose a syslog facility code, such as `Local6` or `Local7`.
    *   **Maximum Length**: Set this value to `8192` bytes to prevent log messages from being truncated, which can lead to parsing errors.
5.  Click **Save** to create the target.
6.  Next, assign the new target to the log categories you wish to export. Navigate to **Administration > System > Logging > Logging Categories**.
7.  For each category you want to forward, select it from the list (e.g., **Passed Authentications**, **Failed Attempts**, **Radius Accounting**).
8.  In the edit view for the category, find the **Targets** section and move your newly created target from the **Available** list to the **Selected** list.
9.  Click **Save** for that category.


### Set up steps in Kibana

1. In Kibana, navigate to **Management > Integrations**.
2. Search for "Cisco ISE" and select the integration.
3. Click **Add Cisco ISE**.
4. Choose your desired input type based on how Cisco ISE is configured to send logs and configure the following fields:

### Validation

After configuration is complete, follow these steps to verify data is flowing correctly from Cisco ISE to the Elastic Stack.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

To avoid common issues and ensure successful data collection, verify your Cisco ISE configuration follows the above setup steps.



### Common configuration issues

You might encounter these issues when configuring the Cisco ISE integration:

-   Maximum message length not set to `8192`: If the Maximum Length is not set to `8192` in the Cisco ISE remote logging target configuration, syslog messages may be truncated before being sent to the Elastic Agent. This leads to incomplete log entries and parsing failures, resulting in missing fields or malformed events in Kibana.
-   Port or protocol mismatch: The Elastic Agent might be configured to listen on a different port or protocol than what Cisco ISE is sending. Verify that the **Target Type** (`TCP Syslog` or `UDP Syslog`) and **Port** configured in the Cisco ISE remote logging target match the input type and port configured for the integration in Kibana. For example, if Cisco ISE is sending to `UDP` port `9026`, the integration must be configured for `UDP` input on port `9026`.
-   Network connectivity issues: Firewalls, routing issues, or incorrect IP address configuration can prevent Cisco ISE from reaching the Elastic Agent host. Check firewall rules on both the Cisco ISE server and the Elastic Agent host to ensure the configured syslog port (e.g., `9025` `TCP`, `9026` `UDP`) is open and accessible.
-   Logging categories not enabled: Cisco ISE won't send logs unless specific logging categories are explicitly assigned to a remote logging target. Ensure your target is selected in the **Remote Logging Targets** list for each desired category under **Administration > System > Logging > Logging Categories**.
-   SSL/TLS configuration issues: When you're using the `ssl` advanced setting, ensure that certificate and key file paths are correct and that the Elastic Agent has sufficient permissions to access them. Mismatched certificates or incorrect `YAML` configuration will prevent the agent from establishing a secure connection.

### Ingestion errors

You can use the following steps to resolve errors during data ingestion:

-   Parsing failures due to malformed logs: Cisco ISE logs that are segmented or contain unexpected formats can cause parsing errors. Review the raw logs in Kibana by checking the `message` or `event.original` field for `_grokparsefailure` tags. Ensure the **Maximum Length** in Cisco ISE is set to `8192`.
-   Missing fields in Kibana: If fields like `user.name` or `source.ip` are missing, verify that you've assigned the relevant logging categories (like **Passed Authentications** or **Radius Accounting**) to your remote logging target in the Cisco ISE portal.

### Performance and scaling

To ensure the integration scales effectively in high-volume environments, consider the following:

-   Adjusting the UDP buffer: When you're using the `UDP` input, you may need to increase the `read_buffer` size in the advanced settings. The default is `100MiB`, but higher traffic volumes may require larger buffers to prevent packet loss during bursts of activity.
-   Preventing log fragmentation: Maintaining the **Maximum Length** at `8192` bytes is critical for performance. Smaller values cause Cisco ISE to split messages into multiple fragments, which increases the processing load and significantly risks parsing errors in the `cisco_ise.log` data stream.

### Vendor resources

For more information about Cisco ISE and syslog configuration, refer to these resources:

-   [Configure External Syslog Server On Ise](https://www.cisco.com/c/en/us/support/docs/security/identity-services-engine/222223-configure-external-syslog-server-on-ise.html)
-   [B Ise Admin 31 Deployment](https://www.cisco.com/c/en/us/td/docs/security/ise/3-1/admin_guide/b_ise_admin_3_1/b_ISE_admin_31_deployment.html)
-   [Official Cisco ISE Syslog Documentation](https://www.cisco.com/c/en/us/td/docs/security/ise/syslog/Cisco_ISE_Syslogs/m_SyslogsList.html)
-   [Official Cisco ISE Product Page](https://www.cisco.com/site/us/en/products/security/identity-services-engine/index.html)

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation. A common approach for large-scale collection is to use a load balancer or a dedicated collector between your Cisco ISE nodes and the Elastic Agents.

### Syslog scaling

When you're dealing with high-volume syslog traffic from Cisco ISE, consider the following strategies to ensure reliable ingestion:
- Use a load balancer to distribute incoming TCP or UDP traffic across multiple Elastic Agent instances to prevent any single agent from becoming a bottleneck.
- If you're using UDP, you should increase the `read_buffer` in the `udp_options` to prevent packet loss during traffic spikes.
- Ensure you've set the **Maximum Length** to `8192` bytes in the Cisco ISE remote logging target configuration. This prevents log fragmentation, which reduces processing overhead on the Elastic Agent and prevents parsing errors in Elasticsearch.

### Filestream scaling

If you're collecting logs from local files on the Cisco ISE system, the `filestream` input's performance depends on the underlying disk I/O and how you manage log files. To optimize this, you should:
- Configure log rotation settings on Cisco ISE to ensure that new log data is always written to files monitored by the agent without creating excessively large individual files that are hard to process.
- Monitor the CPU and memory usage of the Elastic Agent host. High-volume log files may require more resources for the agent's internal queue and processing.
- Ensure the Elastic Agent has sufficient read permissions to access the log files, typically located in paths like `/var/log/cisco_ise*`.
- Use SSD-backed storage for log directories to minimize I/O wait times when the agent is reading large volumes of historical data.

### Advanced SSL/TLS configuration

For secure log transmission using TCP, you can configure SSL/TLS settings. While encryption adds some computational overhead, it's necessary for protecting sensitive authentication data.

You can configure the `ssl` settings with the following options:
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

### Implementation of vendor recommendations

To maintain performance while ensuring data quality, you'll need to follow these vendor-specific requirements:
- **Administrative access:** You must have administrative access to the Cisco ISE Administrator Portal to configure remote logging targets and logging categories effectively.
- **Network connectivity:** Your Elastic Agent's listening port (e.g., TCP `9025`, UDP `9026`) must be reachable from the ISE appliance. Ensure any firewalls in between allow the specified protocol and port.
- **Message length:** Always configure the Cisco ISE remote logging target with a **Maximum Message Length** of `8192` bytes. This is the most critical setting for preventing log segmentation, which can lead to incorrect field mappings and parsing errors.
- **Log categories:** Familiarize yourself with Cisco ISE's logging categories (e.g., `Passed Authentications`, `Failed Attempts`, `RADIUS Accounting`) so you only forward the relevant log types needed for your analysis.

## Reference

### log

The `log` data stream collects various log types from Cisco ISE, including authentication, accounting, and system events. This includes logs for passed authentications, failed attempts, and RADIUS accounting.

The following table lists the exported fields for this data stream:

{{fields "log"}}

This is an example of what a sample event looks like for this data stream:

{{event "log"}}

### Setup and deployment

To begin collecting data, you must configure Cisco ISE to forward logs to the Elastic Agent.

### Performance and scaling

To ensure the integration performs reliably as your environment grows, you should follow these recommendations:

- You must set the **Maximum Length** to `8192` bytes in your Cisco ISE configuration. This prevents the Elastic Agent from having to process fragmented syslog messages, which can significantly increase CPU usage and cause parsing failures.
- You should monitor the Elastic Agent's resource consumption during peak hours to ensure it can keep up with the volume of authentication and accounting logs.
- You should ensure that any firewalls or load balancers in the data path are configured to handle the expected syslog throughput.

### Inputs used

The following inputs are available to collect data for this integration:

{{ inputDocs }}

### Vendor documentation links

You can refer to the following official resources for more information about Cisco ISE and its syslog implementation:
- [Configure external syslog server on ISE](https://www.cisco.com/c/en/us/support/docs/security/identity-services-engine/222223-configure-external-syslog-server-on-ise.html)
- [Cisco ISE administration guide: Deployment](https://www.cisco.com/c/en/us/td/docs/security/ise/3-1/admin_guide/b_ise_admin_3_1/b_ISE_admin_31_deployment.html)
- [Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html)
- [Official Cisco ISE syslog documentation](https://www.cisco.com/c/en/us/td/docs/security/ise/syslog/Cisco_ISE_Syslogs/m_SyslogsList.html)
- [Official Cisco ISE product page](https://www.cisco.com/site/us/en/products/security/identity-services-engine/index.html)
