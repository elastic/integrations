# pfSense Integration for Elastic

## Overview
The pfSense integration for Elastic enables the collection of logs from pfSense and OPNsense firewalls. It parses logs received over the network via syslog (UDP, TCP, or TLS), providing visibility into network traffic, security events, and system health.

This integration facilitates real-time monitoring and analysis of firewall activity, helping with threat detection and network troubleshooting.

### How it works
The integration works by receiving syslog data streams from pfSense or OPNsense devices. Elastic Agent listens on a configured network port (UDP, TCP, or TLS), receives the logs, processes them through its ingest pipelines to parse and structure the data, and then securely sends the data to Elasticsearch for indexing and analysis.

## What data does this integration collect?
The pfSense integration collects and parses the following types of logs:
* Firewall
* Unbound (DNS)
* DHCP Daemon
* OpenVPN
* IPsec
* HAProxy
* Squid (Web Proxy)
* PHP-FPM (Authentication events)

**Note:** The HAProxy dashboards are compatible with the official HAProxy integration. For the best experience, it is recommended to also install the HAProxy integration assets. All other log types not listed above will be dropped.

## What do I need to use this integration?
You need an installed Elastic Agent to act as the collection point for the syslog data.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed to stream data from the syslog receiver and ship it to Elastic. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/install-elastic-agents.html).

### Onboard / configure

Follow the steps below to configure your pfSense or OPNsense device to send logs to the Elastic Agent.

#### pfSense Setup

1.  In the pfSense web interface, navigate to **Status > System Logs**, and then click on the **Settings** tab.
2.  Scroll to the bottom and check the **Enable Remote Logging** box.
3.  (Optional) Select a specific source interface to use for log forwarding under **Source Address**.
4.  In the **Remote log servers** field, enter the IP address and port of your Elastic Agent (e.g., `192.168.100.50:9001`).
5.  Under **Remote Syslog Contents**, select the logs you wish to forward.
    *   To collect logs from packages like HAProxy or Squid, you must select **Everything**.
    *   For standard logs, you can select individual services like Firewall, DHCP, OpenVPN, etc.

#### OPNsense Setup

1.  In the OPNsense web interface, navigate to **System > Settings > Logging / Targets**.
2.  Click the **Add** button (plus icon) to create a new logging target.
3.  Configure the target with the following settings:
    *   **Transport**: UDP, TCP, or TLS, matching your Elastic Agent input configuration.
    *   **Applications**: Leave empty to forward all logs, or select specific applications.
    *   **Levels & Facilities**: Leave with "Nothing Selected".
    *   **Hostname**: The IP address of your Elastic Agent.
    *   **Port**: The port your Elastic Agent is listening on.
    *   **Certificate**: (For TLS only) Select the appropriate client certificate.
    *   **Description**: A descriptive name, e.g., "Syslog to Elastic".
4.  Click **Save**.

**Important Configuration Note:**

The pfSense integration supports both the BSD logging format (default on pfSense) and the standard Syslog format (RFC 5424, an option on pfSense).

The **Syslog format is highly recommended** as it provides the firewall's hostname and includes proper timezone information in the timestamps.

If you must use the BSD format, you **must** configure the `Timezone Offset` setting in the integration policy. If you do not, timestamps will default to the timezone of the Elastic Agent, which may be incorrect. For more details, see the pfSense [log settings documentation](https://docs.netgate.com/pfsense/en/latest/monitoring/logs/settings.html).

### Validation

1.  On a host connected to the pfSense network, generate traffic that will trigger a firewall log event. For example, attempt a connection that you know will be blocked by a firewall rule.
2.  Check the pfSense system logs to confirm that new event data is being written. In the pfSense web interface, navigate to **Status > System Logs > Firewall**.
3.  In Kibana, navigate to the **Discover** tab or open the pre-built **Firewall - Dashboard [pfSense]** dashboard.
4.  Filter for pfSense data by using the KQL query `event.dataset : "pfsense.log"`.
5.  Verify that new log events from the pfSense host are appearing. You should see logs corresponding to the traffic you generated.

A huge thanks to [a3ilson](https://github.com/a3ilson) for the https://github.com/pfelk/pfelk repo, which is the foundation for the majority of the grok patterns and dashboards in this integration.

## Reference

### log
The `log` data stream contains all log types collected from the pfSense or OPNsense device.

#### log fields
{{ fields "log" }}

#### log sample event
{{ event "log" }}

### Inputs used
{{ inputDocs }}
