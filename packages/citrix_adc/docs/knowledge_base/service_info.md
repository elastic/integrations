
# Service Info

## Common use cases
- Monitor Citrix ADC health and performance across `interface`, `lbvserver`, `service`, `system`, and `vpn` data streams.
- Ingest Citrix NetScaler logs (CEF or syslog) for security and operational visibility.
- Use provided dashboards to visualize trends, measure usage, and derive insights.
- Create alerts to reduce MTTD/MTTR and reference logs when troubleshooting.
- Understand virtual server load, client/server connections, requests, and responses across Citrix ADC.

## Data types collected
- Metrics: `interface`, `lbvserver`, `service`, `system`, `vpn` (collected via HTTP/JSON polling of Citrix APIs).
- Logs: Citrix NetScaler syslog events. CEF format is recommended; RFC 5424-compliant syslog is recommended (supported in NetScaler 14.1+).
- Example events and exported fields for each dataset are available in the integration README.
  - **`interface`**: This is the `interface` data stream. The Citrix ADC interfaces are numbered in slot/port notation. In addition to modifying the characteristics of individual interfaces, you can configure virtual LANs to restrict traffic to specific groups of hosts. `interface` data stream collects metrics related to id, state, inbound packets, outbound packets and received packets.
  - **`lbvserver`**: This is the `lbvserver` data stream. The load balancing server is logically located between the client and the server farm, and manages traffic flow to the servers in the server farm. `lbvserver` data stream collects metrics related to name, state, client connections, requests and responses.
  - **`service`**: This is the `service` data stream. With the help of the service endpoint, metrics like throughput, client-server connections, request bytes can be collected along with other statistics for Service resources. `service` data stream collects metrics related to name, IP address, port, throughput and transactions.
  - **`system`**: This is the `system` data stream. With the help of the system endpoint, metrics like memory in use, total system memory, CPU count can be collected along with other statistics for system resources.
  - **`vpn`**: This is the `vpn` data stream. Citrix VPN is the add-on that provides full Secure Sockets Layer (SSL) virtual private network (VPN) capabilities to Citrix Gateway, allowing users to access remote applications on internal networks securely. `vpn` data stream collects metrics like CPS, ICA license, client-server requests, file system and sockets.
  - **`logs`**: The `citrix_adc.log` dataset provides events from the configured syslog server.

## Compatibility
- Tested against Citrix ADC versions `v13.0`, `v13.1`, and `v14.1`.
- Elastic Agent is required. Elasticsearch and Kibana can be Elastic Cloud or self-managed.

## Scaling and Performance
- Prefer CEF logging for application firewall events; use RFC 5424-compliant syslog where supported (NetScaler 14.1+).
- Choose the appropriate log transport (file, TCP, or UDP) based on volume and reliability needs.
- Use multiple Agent inputs or scale syslog receivers as ingestion volume increases. Vendor-specific performance guidance is not provided in the README.

# Set Up Instructions

For step-by-step instructions on how to set up an integration, check the [quick start](integrations://docs/extend/quick-start.md).

**NOTE:** It is recommended to configure the application firewall to enable CEF-formatted logs.

## Vendor prerequisites
- Host(s) and administrator credentials for the Citrix ADC instance.
- Host format: `http[s]://<hostname>:<port>` (example: `http://example.com:9090`).
- Access to NetScaler GUI to enable CEF logging and/or configure syslog servers.

## Elastic prerequisites
- Elastic Agent installed and enrolled.
- Kibana `>= 8.13.0` and an available Elasticsearch cluster.
- Permissions to add the Citrix ADC integration in Kibana.

## Vendor set up steps
- Configure CEF format (recommended for WAF events):
  1. Navigate to Security in the NetScaler GUI.
  2. Click Application Firewall.
  3. Select Change Engine Settings.
  4. Enable CEF Logging.
- Configure Syslog format (if not using CEF):
  - Use the Citrix WAF GUI to configure syslog servers and message types to be sent.
  - RFC 5424-compliant syslog is recommended when supported (NetScaler 14.1+). See “Configuring audit log action”.
  - References:
    - [How to Send Application Firewall Messages to a Separate Syslog Server](https://support.citrix.com/s/article/CTX138973-how-to-send-application-firewall-messages-to-a-separate-syslog-server)
    - [How to Send NetScaler Application Firewall Logs to Syslog Server and NS.log](https://support.citrix.com/s/article/CTX483235-send-logs-to-external-syslog-server?language=en_US)
    - [Configuring audit log action](https://docs.netscaler.com/en-us/citrix-adc/current-release/system/audit-logging/configuring-audit-logging.html#configuring-audit-log-action)

## Kibana set up steps
1. In Kibana, go to Management > Integrations.
2. Search for “Citrix ADC”.
3. Select the Citrix ADC integration and add it.
4. Choose how to collect logs and configure parameters.
  If you want to collect logs via logfile, keep Collect logs from Citrix ADC via file toggle on and then configure following parameters:
    - Paths
  or if you want to collect logs via TCP, keep Collect logs from Citrix ADC via TCP toggle on and then configure following parameters:
    - Listen Address
    - Listen Port
  or if you want to collect logs via UDP, keep Collect logs from Citrix ADC via UDP toggle on and and then configure following parameters:
    - Listen Address
    - Listen Port
5. Save the integration.
6. Note: It is recommended to enable CEF logging on the application firewall.

# Validation Steps
- After configuration, open the Citrix ADC integration’s Assets tab to view the available dashboards; they should populate with data for the configured datasets.
- You can also verify metrics and logs in Discover under the `logs-*` data view.

# Troubleshooting

## Dummy values
It is possible that for some fields, Citrix ADC sets dummy values. For example, a field cpuusagepcnt is represented by citrix_adc.system.cpu.utilization.pct. cpuusagepcnt is set to 4294967295 for some instances. If you also encounter it for some fields, reach out to the Citrix ADC support team.

## Type conflicts
If `host.ip` is shown conflicted under ``logs-*`` data view, this issue can be solved by reindexing the ``Interface``, ``LBVserver``, ``Service``, ``System``, and ``VPN`` data stream's indices.

## Common Configuration Issues
- Dashboards not populated: verify the chosen log collection method (file/TCP/UDP) is enabled and correctly configured.
- Logs not parsed as expected: prefer CEF logging and ensure RFC 5424-compliant syslog is enabled when supported (14.1+).

## Ingestion Errors
- Type conflicts (for example, `host.ip` under `logs-*`): reindex the `Interface`, `LBVserver`, `Service`, `System`, and `VPN` data stream indices.

## Vendor Resources
- NetScaler Syslog Message Reference: [link](https://developer-docs.netscaler.com/en-us/netscaler-syslog-message-reference/current-release)
- How to send WAF messages to a separate syslog server: [link](https://support.citrix.com/s/article/CTX138973-how-to-send-application-firewall-messages-to-a-separate-syslog-server)
- How to send NetScaler Application Firewall logs to external syslog/NS.log: [link](https://support.citrix.com/s/article/CTX483235-send-logs-to-external-syslog-server?language=en_US)
- Configuring audit log action (RFC 5424): [link](https://docs.netscaler.com/en-us/citrix-adc/current-release/system/audit-logging/configuring-audit-logging.html#configuring-audit-log-action)
- NITRO API metrics references:
  - Interface: [link](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/network/interface/)
  - LBVserver: [link](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/lb/lbvserver/)
  - Service: [link](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/basic/service/)
  - System: [link](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/system/system/)
  - VPN: [link](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/vpn/vpn/)

# Documentation sites
- Elastic ECS Field Reference: [link](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html)
