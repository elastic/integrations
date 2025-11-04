
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

## Compatibility
- Tested against Citrix ADC versions `v13.0`, `v13.1`, and `v14.1`.
- Minimum Kibana version: `8.13.0`.
- Elastic Agent is required. Elasticsearch and Kibana can be Elastic Cloud or self-managed.

## Scaling and Performance
- Prefer CEF logging for application firewall events; use RFC 5424-compliant syslog where supported (NetScaler 14.1+).
- Choose the appropriate log transport (file, TCP, or UDP) based on volume and reliability needs.
- Use multiple Agent inputs or scale syslog receivers as ingestion volume increases. Vendor-specific performance guidance is not provided in the README.

# Set Up Instructions

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
4. Choose how to collect logs and configure parameters:
   - File: set Paths.
   - TCP: set Listen Address and Listen Port.
   - UDP: set Listen Address and Listen Port.
5. Save the integration.
6. Note: It is recommended to enable CEF logging on the application firewall.

# Validation Steps
- After configuration, open the Citrix ADC integration’s Assets tab to view the available dashboards; they should populate with data for the configured datasets.
- You can also verify metrics and logs in Discover under the `logs-*` data view.

# Troubleshooting

## Common Configuration Issues
- Dashboards not populated: verify the chosen log collection method (file/TCP/UDP) is enabled and correctly configured.
- Logs not parsed as expected: prefer CEF logging and ensure RFC 5424-compliant syslog is enabled when supported (14.1+).

## Ingestion Errors
- Type conflicts (for example, `host.ip` under `logs-*`): reindex the `Interface`, `LBVserver`, `Service`, `System`, and `VPN` data stream indices.

## API Authentication Errors
- Not covered in the source README.

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
- Citrix ADC integration README in this package for examples, exported fields, and setup notes.
