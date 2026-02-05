# Juniper SRX Integration for Elastic

> **Note**: This documentation was generated using AI and should be reviewed for accuracy.

## Overview

The Juniper SRX integration for Elastic enables you to collect and analyze logs from Juniper SRX Series Firewalls. By ingesting these logs into the Elastic Stack, you gain comprehensive visibility into your network's security posture and operational status. You can use this data to identify threats, monitor traffic patterns, and troubleshoot network issues effectively.

This integration facilitates:
- Security monitoring and threat detection: Ingests `RT_IDS` and `RT_IDP` logs to identify and respond to network-based attacks, including screen events or sophisticated intrusion attempts.
- Traffic analysis and session tracking: Uses `RT_FLOW` and `AppTrack` logs to gain insights into network traffic patterns, session creations, closures, and denied attempts.
- Web and content security: Tracks user activity and security efficacy using `RT_UTM` and `RT_AAMW` logs, which capture web filtering results, antivirus detections, and advanced anti-malware actions.
- Security intelligence orchestration: Monitors `RT_SECINTEL` logs to verify the effectiveness of automated security intelligence feeds and specific actions taken against malicious IP addresses or domains.

### Compatibility

This integration is compatible with Juniper SRX Series Firewalls running Junos versions that support structured-data logging. Your device must be capable of generating syslog messages in the `structured-data` + `brief` format for successful parsing.

### How it works

This integration collects logs from Juniper SRX firewalls by receiving syslog data over TCP or UDP, or reading a log file. You deploy an Elastic Agent on a host that is configured as a syslog receiver. The agent listens for incoming logs, parses the structured messages, and forwards the data to your Elastic deployment into the `log` data stream. The agent can also watch log files written locally to the Elastic Agent's host. This allows you to visualize and search your security data in real-time.

## What data does this integration collect?

The Juniper SRX integration collects log messages in structured-data format from various security and system processes. It processes the following types of data:
*   Firewall session logs: Information on session creation, closing, and denials (`RT_FLOW`).
*   Intrusion detection and prevention (IDP) logs: Security screen events and attack log events (`RT_IDS`, `RT_IDP`).
*   Unified threat management (UTM) logs: Events related to web filtering, antivirus, and antispam detection (`RT_UTM`).
*   Advanced anti-malware logs: Records of malware actions and host infection events (`RT_AAMW`).
*   Security intelligence logs: Data related to security intelligence actions (`RT_SECINTEL`).
*   Juniper SRX logs: Captures all the security and system processes mentioned above in structured-data format.

### Supported use cases

Integrating your Juniper SRX logs with the Elastic Stack provides several security and operational benefits. You can use this integration for the following:
*   Real-time threat monitoring: Identify and respond to threats detected by IDP, UTM, and anti-malware systems as they happen.
*   Network visibility: Analyze firewall session data to understand traffic patterns and identify potential bottlenecks or unusual activity.
*   Security auditing: Maintain a searchable, long-term archive of security events and intelligence actions to support compliance requirements.
*   Incident investigation: Use detailed session and security logs to trace the origin and impact of security incidents across your network.

## What do I need to use this integration?

To collect logs from your Juniper SRX devices, you'll need to meet these vendor-specific requirements:
- Gain administrative access to the Juniper SRX CLI using SSH or a console connection to perform configuration changes.
- Ensure network connectivity exists between the Juniper SRX management or data interfaces and the host running the Elastic Agent.
- Set up firewall rules to allow traffic on the configured syslog port, which defaults to `9006` for this integration.
- Use an SRX device running a Junos version that supports `structured-data` syslog formatting.

You'll also need to prepare your Elastic environment with the following:
- Install and enroll an Elastic Agent in Fleet or configure it to run in standalone mode.
- Install the Juniper SRX integration package, version `1.26.0` or higher, in Kibana.
- Ensure network access is available for the agent to receive inbound syslog traffic on your specified port.

## How do I deploy this integration?

### Agent-based deployment

You must install Elastic Agent on a host that can receive syslog data or access log files from your Juniper SRX device. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You'll only need one Elastic Agent per host.

You'll need the Elastic Agent to stream data from the syslog or log file receiver and ship it to Elastic. From there, the integration's ingest pipelines will process the events.

### Set up steps in Juniper SRX

You can configure your Juniper SRX device to send logs using syslog or write them to a file for collection.

#### Syslog (UDP or TCP) configuration

Follow these steps to configure remote syslog:

1.  Log in to the Juniper SRX device using SSH or the console port.
2.  Enter configuration mode by typing `configure`.
3.  Set the remote syslog destination to the IP address of your Elastic Agent. Replace `<AGENT_IP>` with your agent's IP and `<PORT>` with your configured port (for example, `9006`).
    ```bash
    set system syslog host <AGENT_IP> any any
    set system syslog host <AGENT_IP> port 9006
    ```
4.  Configure the mandatory log format. This integration only supports the `structured-data` format with the `brief` option:
    ```bash
    set system syslog host <AGENT_IP> structured-data brief
    ```
5.  Set the security logging mode to `event` to ensure security logs are sent to the syslog process:
    ```bash
    set security log mode event
    set security log format syslog
    ```
6.  Verify your configuration by running `show system syslog`. Ensure the host entry includes the `structured-data { brief; }` block.
7.  Commit your changes by typing `commit`.

#### Log file configuration

Follow these steps to write logs to a local file:

1.  Log in to the Juniper SRX device or the intermediate log host.
2.  Configure the SRX to write logs to a file using the structured format:
    ```bash
    set system syslog file juniper-srx.log any any
    set system syslog file juniper-srx.log structured-data brief
    ```
3.  Ensure the Elastic Agent has read permissions for the file. The default path is `/var/log/juniper-srx.log`.
4.  Commit the changes on the SRX device.

#### Vendor resources

For more information, refer to these Juniper resources:

-   [Junos CLI reference | structured-data](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/structured-data-edit-system.html)
-   [Direct system log messages to a remote destination](https://www.juniper.net/documentation/us/en/software/junos/network-mgmt/topics/topic-map/directing-system-log-messages-to-a-remote-destination.html)
-   [SRX Getting Started - Configure System Logging](https://supportportal.juniper.net/s/article/SRX-Getting-Started-Configure-System-Logging)
-   [SRX Getting Started - Configure Traffic Logging (Security Policy Logs) for SRX Branch Devices](https://supportportal.juniper.net/s/article/SRX-Getting-Started-Configure-Traffic-Logging-Security-Policy-Logs-for-SRX-Branch-Devices)

### Set up steps in Kibana

You'll need to enable and configure the integration input method that matches your Juniper configuration. Follow the setup instructions that match your configuration.

#### UDP input configuration

This input collects logs over a UDP socket.

1.  In Kibana, navigate to **Management > Integrations** and search for **Juniper SRX**.
2.  Click **Add Juniper SRX**.
3.  Locate the **Collecting syslog from Juniper SRX via UDP** input.
4.  Configure the `syslog_host` (default: `localhost`) and `syslog_port` (default: `9006`).
5.  If you want to keep the raw log, enable **Preserve original event** to store it in `event.original`.
6.  Optionally, configure **Custom UDP Options** like `read_buffer` (default `100MiB`) or `max_message_size` (default `50KiB`).
7.  Save the integration to your Agent policy.

#### TCP input configuration

This input collects logs over a TCP socket.

1.  In Kibana, navigate to **Management > Integrations** and search for **Juniper SRX**.
2.  Click **Add Juniper SRX**.
3.  Locate the **Collecting syslog from Juniper SRX via TCP** input.
4.  Configure the `syslog_host` (default: `localhost`) and `syslog_port` (default: `9006`).
5.  If you're using encryption, configure the **SSL Configuration** settings with your certificate and key.
6.  Under **Custom TCP Options**, you can set the `framing` method (default `delimiter`) or `max_connections`.
7.  Save the integration to your Agent policy.

#### Log file input configuration

This input collects logs directly from files on the host where the Elastic Agent is running.

1.  In Kibana, navigate to **Management > Integrations** and search for **Juniper SRX**.
2.  Click **Add Juniper SRX**.
3.  Locate the **Collecting syslog from Juniper SRX via file** input.
4.  Set the `paths` to the absolute path of your log files (default: `/var/log/juniper-srx.log`).
5.  Save the integration to your Agent policy.

### Validation

After you've finished the configuration, verify that data is flowing correctly into Elasticsearch.

To trigger data flow, perform these actions on your Juniper SRX:
-   **Generate traffic events**: From a device behind the firewall, visit a website or ping an external IP that matches a logged security policy.
-   **Generate configuration events**: Enter configuration mode in the CLI, make a minor change like an interface description, and run `commit`.
-   **Generate authentication events**: Log out and back into the SRX CLI or J-Web interface.

To check the data in Kibana:
1.  Navigate to **Analytics > Discover**.
2.  Select the `logs-*` data view.
3.  Filter for `data_stream.dataset: "juniper_srx.log"`.
4.  Verify that logs appear and contain expected fields like `event.action`, `source.ip`, or `event.outcome`.
5.  Navigate to **Analytics > Dashboards** and search for "Juniper SRX" to see the pre-built visualizations.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Common configuration issues

You may encounter the following issues when configuring the Juniper SRX integration:
- Missing structured data format: If logs appear in Kibana as a raw string in the `message` field and are not parsed, ensure you've committed the `set system syslog host <IP> structured-data brief` command on the SRX device. This integration requires the `structured-data` format to identify fields.
- Security logs not sent: If you receive system logs but traffic or IDP logs (like `RT_FLOW` or `RT_IDS`) are missing, verify that `set security log mode event` is configured in the Junos CLI. By default, SRX devices may send security logs using the data plane, bypassing system syslog settings.
- Port mismatch: Confirm that the port configured on the Juniper SRX (for example, `set system syslog host <IP> port 9006`) matches the `syslog_port` value in your Elastic Agent integration settings.
- Network connectivity issues: Verify there are no firewalls or network Access Control Lists (ACLs) blocking UDP or TCP traffic on port `9006` between the SRX management interface and the Elastic Agent host.
- Parsing failures: Check the `error.message` field in Kibana. If it contains "Provided Grok expressions do not match", it typically indicates the device is sending logs in standard syslog format instead of the required `structured-data` format.
- Incomplete or truncated logs: If log messages are cut off, you may need to increase the `max_message_size` in the integration's UDP or TCP options to accommodate large structured-data payloads.

### Vendor resources

The following resources provide additional information for troubleshooting Juniper SRX syslog configurations:
- [Junos CLI reference | structured-data](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/structured-data-edit-system.html)
- [Direct System Log Messages to a Remote Destination - Juniper Networks](https://www.juniper.net/documentation/us/en/software/junos/network-mgmt/topics/topic-map/directing-system-log-messages-to-a-remote-destination.html)
- [Example: Forward structured system syslog messages from SRX - Juniper Support](https://supportportal.juniper.net/s/article/JSA-STRM-SRX-Example-How-to-forward-structured-system-syslog-messages-from-SRX-to-JSA)
- [KB16502 - Configure System Logging](https://supportportal.juniper.net/s/article/SRX-Getting-Started-Configure-System-Logging)
- [Juniper SRX Product Documentation](https://www.juniper.net/documentation/en_US/release-independent/junos/information-products/pathway-pages/srx-series/product/)

## Performance and scaling

To ensure optimal performance in high-volume environments, consider the following:
- Manage your data volume by configuring the Juniper SRX appliance to forward only necessary events, such as `RT_FLOW` or `RT_IDS`, using Junos syslog facility and severity filters. Don't forward excessive debug-level logs at the source because it can overwhelm the ingest pipeline.
- Scale your deployment by placing multiple Elastic Agents behind a network load balancer to distribute the ingestion load in high-throughput environments. You should place agents in close network proximity to the SRX devices to reduce latency and minimize the impact of network congestion on log delivery.

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Inputs used

{{ inputDocs }}

### Vendor documentation links

The following resources provide additional information about Juniper SRX logging and configuration:
- [Juniper SRX Product Page](https://www.juniper.net/documentation/en_US/release-independent/junos/information-products/pathway-pages/srx-series/product/)
- [Junos Documentation on Structured Data](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/structured-data-edit-system.html)
- [KB16502 - Configure System Logging](https://supportportal.juniper.net/s/article/SRX-Getting-Started-Configure-System-Logging)
- [Juniper SRX integration | Elastic integrations](https://www.elastic.co/docs/reference/integrations/juniper_srx)

### Data streams

#### log

The `log` data stream provides events from Juniper SRX devices. These logs include the following types:
- Traffic logs
- Security logs
- Authentication logs
- Junos OS system events

##### log fields

{{ fields "log" }}

##### log sample event

{{ event "log" }}
