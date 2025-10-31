# Juniper SRX Integration for Elastic

## Overview

The Juniper SRX integration for Elastic collects logs from Juniper SRX devices, enabling real-time visibility into network security, traffic patterns, and threat detection. By parsing and visualizing syslog data, this integration helps security and network operations teams to monitor firewall events, detect threats, and ensure compliance.

This integration facilitates several key use cases:
- **Network Security Monitoring**: Track firewall session events (creation, closure, denial) to monitor network traffic and identify potential security issues.
- **Threat Detection and Response**: Analyze intrusion detection (IDS), intrusion prevention (IDP), and advanced anti-malware (AAMW) logs to respond to security threats in real-time.
- **Compliance and Auditing**: Centralize security logs for audit trails and compliance reporting on network access and security policy enforcement.
- **Unified Threat Management (UTM) Monitoring**: Gain visibility into application-layer threats by monitoring web filtering, antivirus, antispam, and content filtering events.

### Compatibility

This integration is compatible with Juniper SRX series firewalls running Junos OS version 19.x or later. Supported models range from branch office devices to data center appliances.

This integration is compatible with Elastic Stack version 8.11.0 or higher.

### How it works

The integration collects logs sent from Juniper SRX devices via the syslog protocol. Elastic Agent listens for these syslog messages on a configured TCP or UDP port, or reads them from a log file. The agent processes and parses the incoming logs, enriching them with additional metadata before sending them to Elasticsearch for indexing and analysis.

## What data does this integration collect?

The Juniper SRX integration collects the following log types from SRX devices:

*   **RT_FLOW**: Session creation, closure, and denial events, including NAT translations.
*   **RT_IDS**: Intrusion detection system events, including screen-based attacks (TCP, UDP, ICMP).
*   **RT_UTM**: Unified Threat Management events such as web filtering, antivirus, and antispam.
*   **RT_IDP**: Intrusion detection and prevention attack logs.
*   **RT_AAMW**: Advanced anti-malware detection events.
*   **RT_SECINTEL**: Security intelligence events tracking connections to known malicious sources.
*   **System logs**: General system-level events from the SRX device.

All logs must be sent in the `structured-data + brief` syslog format.

## What do I need to use this integration?

- A Juniper SRX firewall running Junos OS 19.x or later.
- Administrator access to the SRX device.
- Network connectivity between the SRX device and the Elastic Agent host.
- An Elastic Stack deployment (version 8.11.0 or higher).
- An Elastic Agent installed and running on a host that can receive syslog messages from the SRX device.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed to stream data from the syslog receiver or log file to Elastic. You can install only one Elastic Agent per host. For more details, see the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/install-elastic-agents.html).

### Onboard / configure

#### 1. Configure Syslog on Juniper SRX

First, configure your Juniper SRX device to send logs to the Elastic Agent.

1.  Access the SRX device Command Line Interface (CLI) via SSH or a console connection.

2.  Enter configuration mode:

    `configure`

3.  Enable structured data format for syslog messages. This is required for the integration to correctly parse the logs.

    `set system syslog structured-data`


4.  Configure the Elastic Agent host as the syslog destination. Replace `<ELASTIC_AGENT_IP>` and `<PORT>` with the IP address and port where the Elastic Agent is listening (e.g., `9006`).
    ```
    set system syslog host <ELASTIC_AGENT_IP> port <PORT>
    set system syslog host <ELASTIC_AGENT_IP> facility-override local0
    ```

5.  To forward all system logs, use the following command:

    `set system syslog host <ELASTIC_AGENT_IP> any any`

6.  Enable security log streaming and set the format to `sd-syslog`.
    ```
    set security log mode stream
    set security log format sd-syslog
    set security log stream <stream-name> host <ELASTIC_AGENT_IP>
    set security log stream <stream-name> port <PORT>
    ```
    *Note: Replace `<stream-name>` with a descriptive name for your log stream.*

7.  Commit the changes to apply the new configuration.

    `commit`

For more details, refer to the Juniper Knowledge Base article [KB16502](https://kb.juniper.net/InfoCenter/index?page=content&id=kb16502).

#### 2. Configure the Integration in Kibana

1.  In Kibana, navigate to **Management → Integrations**.
2.  Search for "Juniper SRX" and select the integration.
3.  Click **Add Juniper SRX**.
4.  Configure the integration settings. Provide a descriptive **Integration name**.
5.  Choose the **Input type** for collecting logs. The available options are detailed below.

##### UDP Input
Collect logs via a UDP syslog listener. This is recommended for most systems where occasional log loss is acceptable.

**Basic Options**

| Option | Description | Default Value |
|---|---|---|
| Syslog Host | The IP address the agent should listen on. Use `0.0.0.0` to listen on all available interfaces. | `localhost` |
| Syslog Port | The port to listen on for syslog messages. This must match the port configured on the SRX device. | `9006` |

**Advanced Options**

| Option | Description | Default Value |
|---|---|---|
| `read_buffer` | The size of the UDP receive buffer in bytes. | `104857600` (100MiB) |
| `max_message_size` | The maximum size of a single syslog message in bytes. | `51200` (50KiB) |
| `timeout` | The read timeout for the UDP socket. | `5m` |
| `preserve_original_event` | If enabled, the original raw log message is stored in the `event.original` field. | `false` |

##### TCP Input
Collect logs via a TCP syslog listener. This provides reliable, ordered delivery and is suitable for environments where log loss is not acceptable.

**Basic Options**

| Option | Description | Default Value |
|---|---|---|
| Syslog Host | The IP address the agent should listen on. Use `0.0.0.0` to listen on all available interfaces. | `localhost` |
| Syslog Port | The port to listen on for syslog messages. This must match the port configured on the SRX device. | `9006` |

**Advanced Options**

| Option | Description | Default Value |
|---|---|---|
| `max_message_size` | The maximum size of a single syslog message in bytes. | `20971520` (20MiB) |
| `timeout` | The read timeout for the TCP socket. | `5m` |
| SSL Settings | Configuration for TLS/SSL encryption. | Disabled |
| `preserve_original_event` | If enabled, the original raw log message is stored in the `event.original` field. | `false` |

##### File Input
Collect logs from files on the host where the Elastic Agent is running.

**Basic Options**

| Option | Description | Default Value |
|---|---|---|
| Paths | A list of file paths to monitor for new log entries. Glob patterns are supported. | `[/var/log/juniper-srx.log]` |

**Advanced Options**

| Option | Description | Default Value |
|---|---|---|
| `preserve_original_event` | If enabled, the original raw log message is stored in the `event.original` field. | `false` |

6.  Select an existing agent policy or create a new one.
7.  Click **Save and continue** to add the integration to your chosen policy.

### Validation

1.  Generate some network traffic that will be logged by the SRX firewall.
2.  In Kibana, navigate to the **Discover** tab.
3.  Select the appropriate data view (e.g., `logs-juniper_srx.log-*`).
4.  Filter the data for `data_stream.dataset: "juniper_srx.log"`.
5.  Verify that log events from your SRX device are appearing. You can test specific log types by filtering on the `juniper.srx.tag` field, for example, `juniper.srx.tag: RT_FLOW_SESSION_CREATE`.

## Troubleshooting

For help with Elastic ingest tools, see [Common problems](https://www.elastic.co/guide/en/fleet/current/common-problems.html).

**Issue: No logs are appearing in Elasticsearch.**
*   **Verify Connectivity**: Ensure the SRX device can reach the Elastic Agent host and port. Use `ping` or `telnet <ELASTIC_AGENT_IP> <PORT>` from the SRX CLI.
*   **Check Firewalls**: Confirm that any firewalls between the SRX device and the agent host allow traffic on the configured syslog port.
*   **Confirm SRX Configuration**: Use `show configuration system syslog` on the SRX device to verify the settings are correct.
*   **Check Agent Logs**: Review the Elastic Agent logs for any connection errors or parsing issues.

**Issue: Events are not parsed correctly.**
*   **Verify Syslog Format**: Ensure the log format on the SRX device is set to `structured-data + brief`. Custom log formats may not parse correctly.
*   **Check Junos OS Version**: Confirm you are running Junos OS 19.x or later.
*   **Preserve Original Event**: Enable the `preserve_original_event` option in the integration settings to capture the raw log message in the `event.original` field for inspection.

## Scaling

For high-volume environments, you can scale horizontally by sending logs from multiple SRX devices to a load-balanced pool of Elastic Agents.

*   **UDP Input**: When using UDP, consider increasing the agent's read buffer size (`read_buffer`) and max message size (`max_message_size`) under the advanced options to handle large log volumes and prevent message loss. The default read buffer is 100MiB and the max message size is 50KiB.
*   **TCP Input**: TCP provides reliable, ordered delivery and is suitable for environments where log loss is not acceptable.
*   **Network**: Ensure adequate network bandwidth is available between the SRX devices and the Elastic Agents. A dedicated management network is recommended.

For more information on scaling, see the [Ingest Architectures](https://www.elastic.co/guide/en/ingest/current/ingest-reference-architectures.html) documentation.

## Reference

### log

The `log` data stream collects and parses log messages from Juniper SRX devices.

#### log fields

{{ fields "log" }}

#### log sample event

{{ event "log" }}

### Inputs used
{{ inputDocs }}

### Vendor Resources

*   [Juniper SRX Series Documentation](https://www.juniper.net/documentation/en_US/release-independent/junos/information-products/pathway-pages/srx-series/product/)
*   [KB16502: SRX Getting Started - Configure System Logging](https://kb.juniper.net/InfoCenter/index?page=content&id=kb16502)
*   [JunOS Structured Data Configuration](https://www.juniper.net/documentation/en_US/junos/topics/reference/configuration-statement/structured-data-edit-system.html)
