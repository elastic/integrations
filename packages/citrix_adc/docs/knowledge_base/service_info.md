
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
- Host format: `http[s]://<hostname>:<port>` (example: `http://example.com:9080`).
- For metrics collection: Network connectivity from Elastic Agent to Citrix ADC management IP on port 80 (HTTP) or 443 (HTTPS).
- For metrics collection: A user account with read-only access to the NITRO API (see vendor set up steps).
- For log collection: Access to NetScaler GUI to enable CEF logging and/or configure syslog servers.

## Elastic prerequisites
- Elastic Agent installed and enrolled.
- Kibana `>= 8.13.0` and an available Elasticsearch cluster.
- Permissions to add the Citrix ADC integration in Kibana.

## Vendor set up steps

### NITRO API access (for metrics collection)
The NITRO REST API is enabled by default on Citrix ADC appliances. To configure access for Elastic Agent:
1. Verify network connectivity from the Elastic Agent host to the Citrix ADC management IP on port 80 (HTTP) or 443 (HTTPS).
2. Create a dedicated read-only system user for monitoring:
   - In the NetScaler GUI, navigate to **System > User Administration > Users**.
   - Click **Add** to create a new user (e.g., `elastic_monitor`).
   - Assign a **Command Policy** with read-only access (e.g., `read-only` built-in policy, or a custom policy limiting access to stat commands).
   - For more details, see [Configuring Users, User Groups, and Command Policies](https://docs.netscaler.com/en-us/citrix-adc/current-release/system/authentication-and-authorization-for-system-user/user-usergroups-command-policies.html).
3. Test API connectivity by accessing the following URL in a browser: `http://<citrix-adc-ip>/nitro/v1/stat/system`
4. (Optional) For secure connections, configure SSL certificates on the Citrix ADC and use HTTPS.
- References:
  - [NITRO API Getting Started Guide](https://citrix-landing-page.readthedocs-hosted.com/projects/citrix-adc-nitro-api-reference/en/12.1/before-you-begin/)
  - [Citrix ADC NITRO API Reference](https://developer-docs.citrix.com/projects/citrix-adc-nitro-api-reference/en/latest/)

### CEF logging (recommended for WAF events)
- Configure CEF format:
  1. Navigate to Security in the NetScaler GUI.
  2. Click Application Firewall.
  3. Select Change Engine Settings.
  4. Enable CEF Logging.

### Syslog configuration (if not using CEF)
- Use the Citrix WAF GUI to configure syslog servers and message types to be sent.
- RFC 5424-compliant syslog is recommended when supported (NetScaler 14.1+). See "Configuring audit log action".
- References:
  - [How to Send Application Firewall Messages to a Separate Syslog Server](https://support.citrix.com/s/article/CTX138973-how-to-send-application-firewall-messages-to-a-separate-syslog-server)
  - [How to Send NetScaler Application Firewall Logs to Syslog Server and NS.log](https://support.citrix.com/s/article/CTX483235-send-logs-to-external-syslog-server?language=en_US)
  - [Configuring audit log action](https://docs.netscaler.com/en-us/citrix-adc/current-release/system/audit-logging/configuring-audit-logging.html#configuring-audit-log-action)

## Kibana set up steps
1. In Kibana, go to Management > Integrations.
2. Search for "Citrix ADC".
3. Select the Citrix ADC integration and add it.

**For metrics collection (NITRO API):**
4. Enter the Citrix ADC hostname in format: `http://<hostname>:<port>` or `https://<hostname>:<port>` (default port is 80 for HTTP, 443 for HTTPS).
5. Enter the username and password for the API user created in the vendor setup steps.
6. (Optional) Configure SSL settings if using HTTPS with self-signed certificates.

**For log collection:**
7. Choose how to collect logs and configure parameters:
   - If you want to collect logs via logfile, keep "Collect logs from Citrix ADC via file" toggle on and configure:
     - Paths
   - If you want to collect logs via TCP, keep "Collect logs from Citrix ADC via TCP" toggle on and configure:
     - Listen Address
     - Listen Port
   - If you want to collect logs via UDP, keep "Collect logs from Citrix ADC via UDP" toggle on and configure:
     - Listen Address
     - Listen Port
8. Save the integration.
9. Note: It is recommended to enable CEF logging on the application firewall.

# Validation Steps
- After configuration, open the Citrix ADC integration’s Assets tab to view the available dashboards; they should populate with data for the configured datasets.
- You can also verify metrics and logs in Discover under the `logs-*` data view.

# Troubleshooting

## Dummy values
It is possible that for some fields, Citrix ADC sets dummy values. For example, a field cpuusagepcnt is represented by citrix_adc.system.cpu.utilization.pct. cpuusagepcnt is set to 4294967295 for some instances. If you also encounter it for some fields, reach out to the Citrix ADC support team.

## Type conflicts
If `host.ip` is shown conflicted under ``logs-*`` data view, this issue can be solved by reindexing the ``Interface``, ``LBVserver``, ``Service``, ``System``, and ``VPN`` data stream's indices.

## Common Configuration Issues
- Metrics dashboards not populated: verify the hostname URL format (`http://<hostname>:<port>`), username/password, and network connectivity to the Citrix ADC management IP.
- API authentication errors: ensure the user account has the `read-only` command policy or appropriate permissions to access `/nitro/v1/stat/` endpoints.
- Dashboards not populated (logs): verify the chosen log collection method (file/TCP/UDP) is enabled and correctly configured.
- Logs not parsed as expected: prefer CEF logging and ensure RFC 5424-compliant syslog is enabled when supported (14.1+).

## Ingestion Errors
- Type conflicts (for example, `host.ip` under `logs-*`): reindex the `Interface`, `LBVserver`, `Service`, `System`, and `VPN` data stream indices.

## Vendor Resources

### NITRO API Documentation
- NITRO API Getting Started Guide: [link](https://citrix-landing-page.readthedocs-hosted.com/projects/citrix-adc-nitro-api-reference/en/12.1/before-you-begin/)
- Citrix ADC NITRO API Reference: [link](https://developer-docs.citrix.com/projects/citrix-adc-nitro-api-reference/en/latest/)
- Configuring Users, User Groups, and Command Policies: [link](https://docs.netscaler.com/en-us/citrix-adc/current-release/system/authentication-and-authorization-for-system-user/user-usergroups-command-policies.html)
- NITRO API statistics endpoints:
  - Interface: [link](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/network/interface/)
  - LBVserver: [link](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/lb/lbvserver/)
  - Service: [link](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/basic/service/)
  - System: [link](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/system/system/)
  - VPN: [link](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/vpn/vpn/)

### Syslog/Logging Documentation
- NetScaler Syslog Message Reference: [link](https://developer-docs.netscaler.com/en-us/netscaler-syslog-message-reference/current-release)
- How to send WAF messages to a separate syslog server: [link](https://support.citrix.com/s/article/CTX138973-how-to-send-application-firewall-messages-to-a-separate-syslog-server)
- How to send NetScaler Application Firewall logs to external syslog/NS.log: [link](https://support.citrix.com/s/article/CTX483235-send-logs-to-external-syslog-server?language=en_US)
- Configuring audit log action (RFC 5424): [link](https://docs.netscaler.com/en-us/citrix-adc/current-release/system/audit-logging/configuring-audit-logging.html#configuring-audit-log-action)

# Documentation sites
- Elastic ECS Field Reference: [link](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html)