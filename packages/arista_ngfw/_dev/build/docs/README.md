# Arista NG Firewall Integration for Elastic

> **Note**: This documentation was generated using AI and should be reviewed for accuracy.

## Overview

The Arista NG Firewall integration for Elastic enables you to collect and analyze logs and metrics from Arista NG Firewall (formerly Untangle). By ingesting event-driven logs and statistics into the Elastic Stack, you'll gain deep visibility into network security, traffic patterns, and system performance in real-time.

This integration facilitates:
- Network security monitoring to detect and investigate security threats by analyzing events from the Firewall, Intrusion Prevention (IPS), and Web Filter modules.
- Traffic analysis and auditing of session events and HTTP request/response logs to understand internal network usage and audit user web activity.
- System health and performance tracking using periodic statistics events for network interfaces and system resource utilization.
- Administrative audit logging of logins and configuration changes to ensure accountability and detect unauthorized access attempts.

### Compatibility

This integration is compatible with all current standard releases of Arista NG Firewall (formerly Untangle NG Firewall) that support remote syslog forwarding via the Events configuration menu.

This integration requires:
- Elastic Stack version `8.11.0` or later for full ingestion, dashboard and field mapping support.
- An active Elastic Agent enrolled in a Fleet policy.

### How it works

This integration collects several categories of logs from Arista NG Firewall via the syslog protocol. You configure your Arista appliance to forward its events to the host running Elastic Agent. The agent listens for incoming data over `TCP` or `UDP`, processes the messages into the Elastic Common Schema (ECS), and maps them to the `log` data stream. This data stream captures firewall policy actions, security events, session information, web activity, and system metrics.

## What data does this integration collect?

The Arista NG Firewall integration collects several categories of logs from Arista NG Firewall (formerly Untangle) via the syslog protocol. These events are processed and mapped to the Elastic Common Schema (ECS) within the `log` data stream.

This integration collects log messages of the following types:
* Firewall events: Records of firewall policy actions such as allow or block decisions, including source and destination IP addresses, ports, and rule IDs.
* Security events: Logs from the Intrusion Prevention System (IPS), including threat signatures and severity levels.
* Traffic and session logs: Detailed session information, including byte counts, session duration, and protocol metadata.
* Web and application logs: HTTP request and response details, including URLs, user agents, and Web Filter categorization events.
* Administrative logs: Audit trails for administrator logins, configuration modifications, and management actions.
* System metrics: Statistics for network interfaces and general system resource utilization.

### Supported use cases

Integrating Arista NG Firewall logs with the Elastic Stack provides visibility into your network security and operational status. You can use this integration for the following use cases:
* Security monitoring: Detect and respond to threats identified by the Intrusion Prevention System (IPS) and firewall policy violations.
* Network traffic analysis: Use Kibana dashboards to visualize network traffic patterns, identify bandwidth-heavy applications, and optimize network performance.
* Audit and compliance: Maintain a searchable record of administrative actions and configuration changes to meet compliance requirements.
* Troubleshooting: Investigate connectivity issues or policy misconfigurations by analyzing detailed session and firewall event logs.

## What do I need to use this integration?

To use this integration, you'll need the following vendor prerequisites:
- Administrative credentials for the Arista NG Firewall (Edge Threat Management) web interface to configure event forwarding.
- Network connectivity between the firewall and the Elastic Agent host. You must ensure that any intermediate firewalls allow traffic on the selected syslog port (it's `9010` by default).
- Enabled and active modules such as Web Filter, Intrusion Prevention, or Firewall on the Arista appliance to generate the relevant event data.
- The IP address or hostname of the machine running the Elastic Agent to configure the remote syslog target.

You'll also need the following Elastic prerequisites:
- Elastic Stack (Elasticsearch and Kibana) version `8.11.0` or later for full compatibility.
- An active Elastic Agent installed and enrolled in Fleet.
- The Arista NG Firewall integration added to an Elastic Agent policy.
- Port `9010` (or your custom-configured port) open on the Elastic Agent host to accept incoming TCP/UDP syslog traffic.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed on a host that'll receive the syslog data from your Arista NG Firewall. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the syslog receiver and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Set up steps in Arista NG Firewall

You need to configure your Arista NG Firewall to forward events to the Elastic Agent host. Follow these steps to enable and configure the forwarding service:

1. Log in to the Arista NG Firewall administration interface.
2. Navigate to **Config > Events > Syslog** from the main dashboard.
3. Check the box for **Enable Remote Syslog** to activate the forwarding service.
4. Configure the destination connection details for your Elastic Agent:
   - **Host**: Enter the IP address or hostname of the machine running the Elastic Agent.
   - **Port**: Enter the port number configured in the integration settings (default is `9010`).
   - **Protocol**: Select either `UDP` or `TCP` to match your intended Elastic Agent input type.
5. Critical performance step: By default, a rule to "Send all events" may exist. It's strongly recommended to disable or delete this rule to prevent system instability due to high log volume.
6. Click **Add** to create specific rules for the data streams required for this integration.
7. For each rule, provide a **Description** (for example, "Elastic Firewall Logs") and select the **Class** from the dropdown menu. This integration supports the following classes:
   - `AdminLoginEvent`
   - `FirewallEvent`
   - `HttpRequestEvent`
   - `HttpResponseEvent`
   - `IntrusionPreventionLogEvent`
   - `SessionEvent`
   - `SessionStatsEvent`
   - `SystemStatEvent`
   - `WebFilterEvent`
8. (Optional) Use **Add Field** under **Conditions** to further filter the events sent to Elastic.
9. Click **Done** to save the individual rule settings.
10. Click **Save** in the bottom-right corner of the main configuration window to apply the syslog changes to the firewall.

#### Vendor resources

You can find more information about configuring syslog in the following Arista resources:
- [How to create syslog event rules - Arista Networks](https://support.edge.arista.com/hc/en-us/articles/115012950828-How-to-create-syslog-event-rules)
- [Events Configuration - Arista Edge Threat Management Wiki](https://wiki.edge.arista.com/index.php/Events)

### Set up steps in Kibana

To add the integration to your Elastic Agent policy, follow these steps:

1. In Kibana, navigate to **Management > Integrations**.
2. Search for **Arista NG Firewall** and select the integration.
3. Click **Add Arista NG Firewall**.
4. Configure the integration by selecting an input type and providing the settings described below.

Choose the setup instructions that match the protocol you selected in the Arista NG Firewall configuration:

#### TCP input configuration

This input collects logs over a TCP socket. Configure the following settings:
- **TCP host to listen on**: The interface address to bind the TCP listener. Set to `0.0.0.0` to listen on all interfaces. Default: `localhost`.
- **TCP Port to listen on**: The port number to receive TCP syslog traffic. Default: `9010`.
- **Preserve original event**: If enabled, this preserves a raw copy of the original event in the `event.original` field. Default: `false`.
- **Tags**: Custom tags for the event. Default: `arista-ngfw`, `forwarded`.
- **Processors**: Optional Agent-side processors to filter or enhance data before ingestion. See [Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details.
- **Timezone**: IANA time zone (for example, `America/New_York`) or offset (for example, `-05:00`) for interpreting timestamps. Default: `UTC`.
- **Interface Mapping**: Provide physical device names (for example, `eth0`) and friendly aliases (for example, `External`) for your firewall interfaces.

#### UDP input configuration

This input collects logs over a UDP socket. Configure the following settings:
- **UDP host to listen on**: The interface address to bind the UDP listener. Set to `0.0.0.0` to listen on all interfaces. Default: `localhost`.
- **UDP Port to listen on**: The port number to receive UDP syslog traffic. Default: `9010`.
- **Preserve original event**: If enabled, this preserves a raw copy of the original event in the `event.original` field. Default: `false`.
- **Tags**: Custom tags for the event. Default: `arista-ngfw`, `forwarded`.
- **Processors**: Optional Agent-side processors to filter or enhance data before ingestion. See [Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details.
- **Timezone**: IANA time zone or offset for timestamp interpretation. Default: `UTC`.
- **Interface Mapping**: Provide physical device names (for example, `eth1`) and friendly aliases (for example, `Internal`) for your firewall interfaces.

After configuring the inputs, assign the integration to an agent policy and click **Save and continue**.

### Validation

After the configuration is complete, follow these steps to verify data is flowing correctly from Arista NG Firewall to the Elastic Stack:

1. Trigger data flow on the Arista NG Firewall:
   - **Generate authentication event**: Log out of the Arista NG Firewall administration UI and log back in to trigger an `AdminLoginEvent`.
   - **Generate web traffic**: From a client device located behind the Arista firewall, browse to several different websites to generate `HttpRequestEvent` and `WebFilterEvent` logs.
   - **Generate firewall event**: Attempt to access a service that's explicitly blocked by a firewall rule to trigger a `FirewallEvent`.

2. Check the data in Kibana:
   - Navigate to **Analytics > Discover**.
   - Select the `logs-*` data view.
   - In the search bar, enter the filter: `data_stream.dataset: "arista_ngfw.log"`.
   - Verify that logs appear. Expand a log entry and confirm these fields:
     - `event.dataset` (should be `arista_ngfw.log`)
     - `source.ip` and/or `destination.ip`
     - `message` (the raw log payload)
   - Navigate to **Analytics > Dashboards** and search for "Arista NG Firewall" to view pre-built visualizations.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Common configuration issues

If you encounter issues while setting up or using the Arista NG Firewall integration, consider the following common configuration issues:
- **Port mismatch**: The Arista UI defaults to port `514` for syslog, while the integration defaults to `9010`. You'll want to ensure both the appliance and the Kibana input configuration use the same port number.
- **Rules not enabled**: Even if you configure the Syslog Server and set it to "Enabled" in the Arista interface, no data will flow until you add specific syslog rules in the lower section of the Events tab and check the Remote Syslog box for each rule.
- **Binding failures**: If the Elastic Agent can't bind to the configured host (like `localhost`), the listener might fail to start. You should set the `tcp_host` or `udp_host` to `0.0.0.0` if you want to listen on all available network interfaces.
- **Network firewalls**: If your Elastic Agent host has a local firewall like `ufw` or `firewalld`, you'll need to explicitly allow incoming traffic on port `9010`.
- **Parsing failures**: If you see logs in Kibana with `_grokparsefailure` or `_jsonparsefailure` tags, verify the Arista appliance sends logs in the expected syslog format and check that no custom log prefixes are breaking the parser.
- **Timestamp mismatches**: If logs aren't appearing when you expect, check for timezone offset issues and ensure the Timezone setting in the integration matches the timezone on your Arista NG Firewall appliance.
- **Missing fields**: If fields like `source.ip` are missing, verify that the corresponding Arista module (such as the Firewall or Web Filter) is logging those details and that you've included the event class in your syslog rules.

## Performance and scaling

To ensure optimal performance in high-volume environments, you should consider the following:
- Choose the appropriate transport protocol for your environment. The integration supports both `TCP` and `UDP` for syslog ingestion. For high-reliability environments where log loss is unacceptable, `TCP` is recommended despite slightly higher overhead. `UDP` provides higher throughput with lower latency but doesn't guarantee delivery in congested networks.
- Manage data volume at the source to prevent performance issues. To prevent performance degradation on both the Arista device and the Elastic Agent, you'll want to avoid using the `Send all events` rule. Instead, configure specific syslog rules for only the necessary event classes such as `Firewall`, `Session`, and `IPS`. Filtering at the source significantly reduces the ingestion load and storage requirements.
- Scale your Elastic Agent deployment for high-throughput environments. If you've got multiple firewall clusters, you can deploy multiple Elastic Agents behind a network load balancer to distribute traffic evenly. You'll want to place agents close to the data source to minimize latency and ensure dedicated agent nodes have sufficient CPU and memory allocations to handle peak traffic.

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Inputs used

The following inputs are used by this integration:

{{ inputDocs }}

### Data streams

#### log

The `log` data stream provides events from Arista NG Firewall of the following types: firewall traffic logs, security events, and system alerts.

##### log fields

{{ fields "log" }}

##### log sample event

{{ event "log" }}

### Vendor documentation links

For more information about Arista NG Firewall configuration and event management, see these vendor resources:
* [Arista Events Configuration Wiki](https://wiki.edge.arista.com/index.php/Events)
* [Arista Edge Threat Management - Official Product Page](https://edge.arista.com/ng-firewall/)
* [How to create syslog event rules - Arista Networks](https://support.edge.arista.com/hc/en-us/articles/115012950828-How-to-create-syslog-event-rules)
