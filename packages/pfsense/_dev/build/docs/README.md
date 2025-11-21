# pfSense Integration for Elastic

## Overview

The pfSense integration enables you to collect and parse logs from pfSense and OPNsense firewalls. By ingesting these logs into the Elastic Stack, you can monitor network traffic, analyze security events, and gain comprehensive visibility into your network's health and security. This integration supports log collection over syslog, making it easy to centralize firewall data for analysis and visualization.

This integration facilitates:

- Monitoring firewall accept/deny events.
- Analyzing VPN, DHCP, and DNS activity.
- Auditing system and authentication events.
- Visualizing network traffic through pre-built dashboards.

### Compatibility

This integration is compatible with recent versions of pfSense and OPNsense. It requires Elastic Stack version 8.11.0 or higher.

### How it works

The pfSense integration works by collecting logs sent from pfSense or OPNsense devices via the syslog protocol. An Elastic Agent is set up on a host designated as a syslog receiver. The firewall is then configured to forward its logs to this agent. The agent processes and forwards the data to your Elastic deployment, where it is parsed, indexed, and made available for analysis in Kibana. The integration supports both UDP and TCP for log transport.

## What data does this integration collect?

This integration collects several types of logs from pfSense and OPNsense, providing a broad view of network and system activity. The supported log types include:

- **Firewall**: Logs detailing traffic allowed or blocked by firewall rules.
- **Unbound**: DNS resolver logs.
- **DHCP Daemon**: Logs related to DHCP lease assignments and requests.
- **OpenVPN**: Virtual Private Network connection and status logs.
- **IPsec**: IP security protocol logs for VPN tunnels.
- **HAProxy**: High-availability and load balancer logs.
- **Squid**: Web proxy access and system logs.
- **PHP-FPM**: Logs related to user authentication events in the web interface.

Logs that do not match these types will be dropped by the integration's ingest pipeline.

## What do I need to use this integration?

- A pfSense or OPNsense firewall with administrative access to configure log forwarding.
- Network connectivity between the firewall and the Elastic Agent host.
- An installed Elastic Agent to receive the syslog data.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed on a host that will receive the syslog data from your pfSense or OPNsense device. For detailed installation instructions, refer to the Elastic Agent [installation guide](docs-content://reference/fleet/install-elastic-agents.md). Only one Elastic Agent is needed per host.

### Set up steps in pfSense

1.  Log in to the pfSense web interface.
2.  Navigate to **Status > System Logs**, and then click the **Settings** tab.
3.  Scroll to the bottom and check the **Enable Remote Logging** box.
4.  In the **Remote log servers** field, enter the IP address and port of your Elastic Agent host (e.g., `192.168.1.10:9001`).
5.  Under **Remote Syslog Contents**, you have two options:
    - **Syslog format (Recommended)**: Check the box for **Syslog format**. This format provides the firewall hostname and proper timezone information in the logs.
    - **BSD format**: If you use the default BSD format, you must configure the **Timezone Offset** setting in the integration policy in Kibana to ensure timestamps are parsed correctly.
6.  Select the logs you wish to forward. To capture logs from packages like HAProxy or Squid, you must select the **Everything** option.
7.  Click **Save**.

For more details, refer to the [official pfSense documentation](https://docs.netgate.com/pfsense/en/latest/monitoring/logs/settings.html).

### Set up steps in OPNsense

1.  Log in to the OPNsense web interface.
2.  Navigate to **System > Settings > Logging / Targets**.
3.  Click the **+** (Add) icon to create a new logging target.
4.  Configure the settings as follows:
    - **Transport**: Choose the desired transport protocol (UDP, TCP).
    - **Applications**: Leave empty to send all logs, or select the specific applications you want to monitor.
    - **Hostname**: Enter the IP address of the Elastic Agent host.
    - **Port**: Enter the port number the agent is listening on.
    - **Certificate**: (For TLS only) Select the appropriate client certificate.
    - **Description**: Add a descriptive name, such as "Syslog to Elastic".
5.  Click **Save**.

### Set up steps in Kibana

1.  In Kibana, navigate to **Management > Integrations**.
2.  Search for "pfSense" and select the integration.
3.  Click **Add pfSense**.
4.  Configure the integration by selecting an input type and providing the necessary settings. The module is configured by default to use the `UDP` input on port `9001`.

#### UDP Input Configuration

This input collects logs over a UDP socket.

| Setting | Description |
|---|---|
| **Syslog Host** | The bind address for the UDP listener (e.g., `0.0.0.0` to listen on all interfaces). |
| **Syslog Port** | The UDP port to listen on (e.g., `9001`). |
| **Internal Networks** | A list of your internal IP subnets. Supports CIDR notation and named ranges like `private`. |
| **Timezone Offset** | If using BSD format logs, set the timezone offset (e.g., `-05:00` or `EST`) to correctly parse timestamps. Defaults to the agent's local timezone. |
| **Preserve original event** | If checked, a raw copy of the original log is stored in the `event.original` field. |

#### TCP Input Configuration

This input collects logs over a TCP socket.

| Setting | Description |
|---|---|
| **Syslog Host** | The bind address for the TCP listener (e.g., `0.0.0.0`). |
| **Syslog Port** | The TCP port to listen on (e.g., `9001`). |
| **Internal Networks** | A list of your internal IP subnets. |
| **Timezone Offset** | If using BSD format logs, set the timezone offset to correctly parse timestamps. |
| **SSL Configuration** | Configure SSL options for encrypted communication. See the [SSL documentation](https://www.elastic.co/guide/en/beats/filebeat/current/configuration-ssl.html#ssl-common-config) for details. |
| **Preserve original event** | If checked, a raw copy of the original log is stored in the `event.original` field. |

After configuring the input, assign the integration to an agent policy and click **Save and continue**.

### Validation

1.  First, verify on your pfSense or OPNsense device that logs are being actively sent to the configured Elastic Agent host.
2.  In Kibana, navigate to **Discover**.
3.  In the search bar, enter `data_stream.dataset: "pfsense.log"` and check for incoming documents.
4.  Verify that events are appearing with recent timestamps.
5.  Navigate to **Dashboard** and search for the pfSense dashboards to see if the visualizations are populated with data.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

- **No data is being collected**:
  - Verify network connectivity between the firewall and the Elastic Agent host.
  - Ensure there are no firewalls or network ACLs blocking the syslog port.
  - Confirm that the listening port in the integration policy matches the destination port on the firewall.
- **Incorrect Timestamps**:
  - If using the default BSD log format from pfSense, ensure the **Timezone Offset** is correctly configured in the integration settings in Kibana. The recommended solution is to switch to the **Syslog format** on the pfSense device.

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### log

The `log` data stream collects and parses all supported log types from the pfSense or OPNsense firewall.

#### log fields

{{ fields "log" }}

#### log sample event

{{ event "log" }}

### Inputs used

{{ inputDocs }}
