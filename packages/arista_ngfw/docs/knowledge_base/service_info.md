# Service Info

## Common use cases

The Arista NG Firewall integration (formerly Untangle) provides deep visibility into network security, traffic patterns, and system performance by ingesting event-driven logs and statistics into the Elastic Stack. This allows security teams and network administrators to monitor the health and security posture of their edge environment in real-time.

- **Network Security Monitoring:** Detect and investigate security threats by analyzing events from the Firewall, Intrusion Prevention (IPS), and Web Filter modules to identify blocked attacks or policy violations.
- **Traffic Analysis and Auditing:** Monitor session events and HTTP request/response logs to understand internal network usage, identify top talkers, and audit user web activity for compliance.
- **System Health and Performance Tracking:** Utilize periodic statistics events, such as interface and system stats, to create performance dashboards that visualize throughput, CPU load, and memory usage across the appliance.
- **Administrative Audit Logging:** Track administrative logins and configuration changes to ensure accountability and detect unauthorized access attempts to the firewall management interface.

## Data types collected

This integration collects several categories of logs from Arista NG Firewall (formerly Untangle) via the syslog protocol, mapping them to the **Arista NG Firewall logs** data stream.

- **Firewall Events:** Collects details on firewall policy actions (Allow/Block), including source and destination IP addresses, ports, and rule IDs.
- **Security Events:** Captures Intrusion Prevention System (IPS) logs, threat signatures, and severity levels.
- **Traffic and Session Logs:** Records detailed session information, including byte counts, session duration, and protocol metadata.
- **Web and Application Logs:** Tracks HTTP request and response details, including URLs, user agents, and Web Filter categorization events.
- **Administrative Logs:** Provides audit trails for administrator logins, configuration modifications, and management actions.
- **System Metrics:** Ingests statistics for network interfaces and general system resource utilization.

According to the data stream definitions, this integration collects:
- **Arista NG Firewall logs (`arista_ngfw.log`):** A logs-type data stream that processes events sent via either TCP or UDP, mapping them to the Elastic Common Schema (ECS).

## Compatibility

### Vendor Requirements
The **Arista NG Firewall** integration is compatible with the following third-party vendor versions:
- **Arista NG Firewall (formerly Untangle NG Firewall):** Supports all current standard releases of the NG Firewall software capable of remote syslog forwarding via the Events configuration menu.

### Elastic Prerequisites
- **Elastic Agent:** An active Elastic Agent must be installed and enrolled in a policy via Fleet.
- **Elastic Stack:** Recommended version 8.11.0 or later for full dashboard and field mapping support.

## Scaling and Performance

To ensure optimal performance in high-volume environments, consider the following:
- **Transport/Collection Considerations:** The integration supports both TCP and UDP for syslog ingestion. For high-reliability environments where log loss is unacceptable, TCP is recommended despite slightly higher overhead. UDP provides higher throughput with lower latency but does not guarantee delivery in congested networks.
- **Data Volume Management:** To prevent performance degradation on both the Arista device and the Elastic Agent, users should avoid the "Send all events" rule. Instead, configure specific syslog rules for only the necessary event classes (e.g., Firewall, Session, IPS). Filtering at the source significantly reduces the ingestion load and storage requirements.
- **Elastic Agent Scaling:** For high-throughput environments with multiple firewall clusters, deploy multiple Elastic Agents behind a network load balancer to distribute traffic evenly. Place Agents close to the data source to minimize latency and ensure dedicated Agent nodes have sufficient CPU and memory allocations to handle peak traffic.

# Set Up Instructions

## Vendor prerequisites
- **Administrative Access:** High-level administrative credentials for the Arista NG Firewall (Edge Threat Management) web interface are required to configure event forwarding.
- **Network Connectivity:** The firewall must have a clear network path to the Elastic Agent host. Ensure that any intermediate firewalls allow traffic on the selected syslog port (default **9010**).
- **Log Generation:** Specific modules (e.g., **Web Filter**, **Intrusion Prevention**, **Firewall**) must be enabled and active on the Arista appliance to generate the relevant event data.
- **Appliance IP/Hostname:** You must know the IP address or hostname of the machine running the Elastic Agent to configure the remote syslog target.

## Elastic prerequisites

- **Elastic Stack Version:** Ensure your Elastic Stack (Elasticsearch and Kibana) is on version 8.11.0 or later for full compatibility.
- **Elastic Agent:** An active Elastic Agent must be installed and enrolled in Fleet.
- **Integration Policy:** The Arista NG Firewall integration must be added to an Elastic Agent policy.
- **Connectivity:** Port **9010** (or your custom-configured port) must be open on the Elastic Agent host to accept incoming TCP/UDP syslog traffic.

## Vendor set up steps

### For Syslog Forwarding (TCP/UDP):

1. Log in to the Arista NG Firewall administration interface.
2. Navigate to **Config > Events > Syslog** from the main dashboard.
3. Check the box for **Enable Remote Syslog** to activate the forwarding service.
4. Configure the destination connection details for your Elastic Agent:
    - **Host**: Enter the IP address or hostname of the machine running the Elastic Agent.
    - **Port**: Enter the port number configured in the integration settings (default is `9010`).
    - **Protocol**: Select either `UDP` or `TCP` to match your intended Elastic Agent input type.
5. **Critical Performance Step**: By default, a rule to "Send all events" may exist. It is strongly recommended to **disable or delete** this rule to prevent system instability due to high log volume.
6. Click **Add** to create specific rules for the data streams required for this integration.
7. For each rule, provide a **Description** (e.g., "Elastic Firewall Logs") and select the **Class** from the dropdown menu. Recommended classes include:
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

### Vendor Set up Resources

- [How to create syslog event rules - Arista Networks](https://support.edge.arista.com/hc/en-us/articles/115012950828-How-to-create-syslog-event-rules)
- [Events Configuration - Arista Edge Threat Management Wiki](https://wiki.edge.arista.com/index.php/Events)

## Kibana set up steps

### Collects logs from Arista NG Firewall via TCP
1. In Kibana, navigate to **Integrations > Arista NG Firewall**.
2. Click **Add Arista NG Firewall**.
3. Under **Collects logs from Arista NG Firewall via TCP**, configure the following:
    - **TCP host to listen on**: The interface address to bind the TCP listener. Set to `0.0.0.0` to listen on all interfaces. Default: `localhost`.
    - **TCP Port to listen on**: The port number to receive TCP syslog traffic. Default: `9010`.
    - **Preserve original event**: If enabled, preserves a raw copy of the original event in the `event.original` field. Default: `False`.
    - **Tags**: Custom tags for the event. Default: `['arista-ngfw', 'forwarded']`.
    - **Processors**: Optional Agent-side processors to filter or enhance data before ingestion.
    - **Timezone**: IANA time zone (e.g., `America/New_York`) or offset (e.g., `-05:00`) for interpreting timestamps. Default: `UTC`.
    - **Device name for interface ID 1**: The physical device name for interface 1 (e.g., `eth0`).
    - **Alias for interface ID 1**: A friendly name for interface 1 (e.g., `External`).
    - **Device name for interface ID 2**: The physical device name for interface 2 (e.g., `eth1`).
    - **Alias for interface ID 2**: A friendly name for interface 2 (e.g., `Internal`).
4. Save and deploy the integration to your Agent policy.

### Collects logs from Arista NG Firewall via UDP
1. In Kibana, navigate to **Integrations > Arista NG Firewall**.
2. Click **Add Arista NG Firewall**.
3. Under **Collects logs from Arista NG Firewall via UDP**, configure the following:
    - **UDP host to listen on**: The interface address to bind the UDP listener. Set to `0.0.0.0` to listen on all interfaces. Default: `localhost`.
    - **UDP Port to listen on**: The port number to receive UDP syslog traffic. Default: `9010`.
    - **Preserve original event**: If enabled, preserves a raw copy of the original event in the `event.original` field. Default: `False`.
    - **Tags**: Custom tags for the event. Default: `['arista-ngfw', 'forwarded']`.
    - **Processors**: Optional Agent-side processors.
    - **Timezone**: IANA time zone or offset for timestamp interpretation. Default: `UTC`.
    - **Device name for interface ID 1**: The physical device name for interface 1 (e.g., `eth0`).
    - **Alias for interface ID 1**: A friendly name for interface 1 (e.g., `WAN`).
    - **Device name for interface ID 2**: The physical device name for interface 2 (e.g., `eth1`).
    - **Alias for interface ID 2**: A friendly name for interface 2 (e.g., `LAN`).
4. Save and deploy the integration to your Agent policy.

# Validation Steps

After configuration is complete, follow these steps to verify data is flowing correctly from Arista NG Firewall to the Elastic Stack.

### 1. Trigger Data Flow on Arista NG Firewall:
- **Generate authentication event:** Log out of the Arista NG Firewall administration UI and log back in to trigger an `AdminLoginEvent`.
- **Generate web traffic:** From a client device located behind the Arista firewall, browse to several different websites to generate `HttpRequestEvent` and `WebFilterEvent` logs.
- **Generate firewall event:** Attempt to access a service that is explicitly blocked by a firewall rule to trigger a `FirewallEvent`.

### 2. Check Data in Kibana:
1. Navigate to **Analytics > Discover**.
2. Select the `logs-*` data view.
3. Enter the KQL filter: `data_stream.dataset : "arista_ngfw.log"`
4. Verify logs appear. Expand a log entry and confirm these fields:
   - `event.dataset` (should be `arista_ngfw.log`)
   - `source.ip` and/or `destination.ip`
   - `message` (the raw log payload)
5. Navigate to **Analytics > Dashboards** and search for "Arista NG Firewall" to view pre-built visualizations.

# Troubleshooting

## Common Configuration Issues
- **Port Mismatch**: The Arista UI defaults to port 514 for syslog, while the integration defaults to **9010**. Ensure both the appliance and the Kibana input configuration use the same port number.
- **Rules Not Enabled**: Even if the Syslog Server is configured and "Enabled" in Arista, no data will flow until specific **Syslog Rules** are added in the lower section of the Events tab and the "Remote Syslog" checkbox is checked for each rule.
- **Binding Failures**: If the Elastic Agent cannot bind to the configured host (e.g., `localhost`), it may fail to start the listener. Ensure the `tcp_host` or `udp_host` is set to `0.0.0.0` if you want to listen on all available network interfaces.
- **Network Firewalls**: If the Agent host has a local firewall (like `ufw` or `firewalld`), you must explicitly allow incoming traffic on port 9010.

## Ingestion Errors
- **Parsing Failures**: If logs appear in Kibana but contain the `_grokparsefailure` or `_jsonparsefailure` tags, verify that the Arista appliance is sending logs in the expected syslog format and that no custom log prefixes have been added that might break the parser.
- **Timestamp Mismatches**: If logs appear to be missing, check for a timezone offset issue. Ensure the **Timezone** variable in the Kibana integration settings matches the timezone configured on the Arista NG Firewall appliance.
- **Missing Fields**: If specific fields like `source.ip` are missing, ensure that the relevant Arista module (e.g., Firewall or Web Filter) is properly logging those details and that the event class is included in your Syslog Rules.

## Vendor Resources

- [Arista Events Configuration Wiki](https://wiki.edge.arista.com/index.php/Events) - Technical documentation regarding the Arista event system.
- [Arista Edge Threat Management - Official Product Page](https://edge.arista.com/ng-firewall/) - General information about Arista NG Firewall.

# Documentation sites

- [How to create syslog event rules - Arista Networks](https://support.edge.arista.com/hc/en-us/articles/115012950828-How-to-create-syslog-event-rules)
- [Arista Edge Threat Management Wiki](https://wiki.edge.arista.com/index.php/Events)
