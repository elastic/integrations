# Citrix ADC Integration for Elastic

## Overview

The Citrix ADC integration for Elastic collects logs and metrics from your Citrix ADC instances, providing real-time visibility into network activity, threat detection, and security operations. This integration allows you to monitor the health and performance of your Citrix ADC environment, ingest Citrix NetScaler logs for security and operational analysis, and use pre-built dashboards to visualize trends and derive insights.

### Compatibility

This integration has been tested and is compatible with Citrix ADC versions `v13.0`, `v13.1`, and `v14.1`.

The minimum required Kibana version is `8.13.0`.

### How it works

This integration uses the Elastic Agent to collect data from Citrix ADC instances. Metrics are collected by polling the Citrix NITRO APIs via HTTP/JSON, while logs are collected from syslog messages (CEF or RFC 5424 compliant) or log files.

## What data does this integration collect?

The Citrix ADC integration collects the following types of data:

*   **Metrics:** `interface`, `lbvserver`, `service`, `system`, and `vpn` metrics are collected via HTTP/JSON polling of the Citrix NITRO APIs.
*   **Logs:** Citrix NetScaler syslog events are collected. CEF format is recommended for Web Application Firewall (WAF) events, and RFC 5424-compliant syslog is recommended for other log types (supported in NetScaler 14.1+).

### Supported use cases

*   Monitor Citrix ADC health and performance across `interface`, `lbvserver`, `service`, `system`, and `vpn` data streams.
*   Ingest Citrix NetScaler logs (CEF or syslog) for security and operational visibility.
*   Use provided dashboards to visualize trends, measure usage, and derive insights.
*   Create alerts to reduce MTTD/TR and reference logs when troubleshooting.
*   Understand virtual server load, client/server connections, requests, and responses across Citrix ADC.

## What do I need to use this integration?

### Vendor prerequisites

*   Host(s) and administrator credentials for the Citrix ADC instance.
*   Host format: `http[s]://<hostname>:<port>` (example: `http://example.com:9090`).
*   Access to the NetScaler GUI to enable CEF logging and/or configure syslog servers.

### Elastic prerequisites

*   An installed and enrolled Elastic Agent.
*   Kibana version `>= 8.13.0` and an available Elasticsearch cluster.
*   Permissions to add the Citrix ADC integration in Kibana.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the syslog or log file receiver and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Onboard / configure

#### Vendor set up steps

##### Configure CEF format (recommended for WAF events)

1.  Navigate to **Security** in the NetScaler GUI.
2.  Click **Application Firewall**.
3.  Select **Change Engine Settings**.
4.  Enable **CEF Logging**.

##### Configure Syslog format (if not using CEF)

*   Use the Citrix WAF GUI to configure syslog servers and message types to be sent.
*   RFC 5424-compliant syslog is recommended when supported (NetScaler 14.1+). See [Configuring audit log action](https://docs.netscaler.com/en-us/citrix-adc/current-release/system/audit-logging/configuring-audit-logging.html#configuring-audit-log-action).
*   **References:**
    *   [How to Send Application Firewall Messages to a Separate Syslog Server](https://support.citrix.com/s/article/CTX138973-how-to-send-application-firewall-messages-to-a-separate-syslog-server)
    *   [How to Send NetScaler Application Firewall Logs to Syslog Server and NS.log](https://support.citrix.com/s/article/CTX483235-send-logs-to-external-syslog-server?language=en_US)

#### Kibana set up steps

1.  In Kibana, go to **Management > Integrations**.
2.  Search for “Citrix ADC”.
3.  Select the Citrix ADC integration and add it.
4.  Choose how to collect logs and configure the parameters:
    *   **File:** set **Paths**.
    *   **TCP:** set **Listen Address** and **Listen Port**.
    *   **UDP:** set **Listen Address** and **Listen Port**.
5.  Save the integration.

### Validation

After configuration, open the Citrix ADC integration’s **Assets** tab to view the available dashboards; they should populate with data for the configured datasets.

- While adding the integration, if you want to collect logs via logfile, keep **Collect logs from Citrix ADC via file** toggle on and then configure following parameters:
    - `Paths`
- If you want to collect logs via TCP, keep **Collect logs from Citrix ADC via TCP** toggle on and then configure following parameters:
    - `Listen Address`
    - `Listen Port`
- If you want to collect logs via UDP, keep **Collect logs from Citrix ADC via UDP** toggle on and and then configure following parameters:
    - `Listen Address`
    - `Listen Port`

You can also verify metrics and logs in **Discover** under the `logs-*` data view.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Dummy values
It is possible that for some fields, Citrix ADC sets dummy values. For example, a field `cpuusagepcnt` is represented by `citrix_adc.system.cpu.utilization.pct`. The `cpuusagepcnt` value is set to `4294967295` for some instances. If you also encounter it for some fields, reach out to the Citrix ADC support team.

### Common Configuration Issues
*   **Dashboards not populated:** Verify the chosen log collection method (file/TCP/UDP) is enabled and correctly configured.
*   **Logs not parsed as expected:** Prefer CEF logging and ensure RFC 5424-compliant syslog is enabled when supported (14.1+).

### Ingestion Errors
*   **Type conflicts:** If `host.ip` is shown conflicted under the `logs-*` data view, this issue can be solved by reindexing the `Interface`, `LBVserver`, `Service`, `System`, and `VPN` data stream's indices.

### Vendor Resources
*   [NetScaler Syslog Message Reference](https://developer-docs.netscaler.com/en-us/netscaler-syslog-message-reference/current-release)
*   [How to send WAF messages to a separate syslog server](https://support.citrix.com/s/article/CTX138973-how-to-send-application-firewall-messages-to-a-separate-syslog-server)
*   [How to send NetScaler Application Firewall logs to external syslog/NS.log](https://support.citrix.com/s/article/CTX483235-send-logs-to-external-syslog-server?language=en_US)
*   [Configuring audit log action (RFC 5424)](https://docs.netscaler.com/en-us/citrix-adc/current-release/system/audit-logging/configuring-audit-logging.html#configuring-audit-log-action)
*   NITRO API metrics references:
    *   [Interface](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/network/interface/)
    *   [LBVserver](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/lb/lbvserver/)
    *   [Service](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/basic/service/)
    *   [System](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/system/system/)
    *   [VPN](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/vpn/vpn/)

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

Prefer CEF logging for application firewall events; use RFC 5424-compliant syslog where supported (NetScaler 14.1+). Choose the appropriate log transport (file, TCP, or UDP) based on volume and reliability needs. Use multiple Agent inputs or scale syslog receivers as ingestion volume increases.

## Reference

### Interface

The `interface` data stream collects metrics related to id, state, inbound packets, outbound packets and received packets.

#### Interface fields

{{ fields "interface" }}

{{ event "interface" }}

### Load Balancing Virtual Server

The `lbvserver` data stream collects metrics related to name, state, client connections, requests and responses.

#### Load Balancing Virtual Server fields

{{ fields "lbvserver" }}

{{ event "lbvserver" }}

### Service

The `service` data stream collects metrics like throughput, client-server connections, request bytes can be collected along with other statistics for Service resources.

#### Service fields

{{ fields "service" }}

{{ event "service" }}

### System

The `system` data stream collects metrics like memory in use, total system memory, CPU count can be collected along with other statistics for system resources.

#### System fields

{{ fields "system" }}

{{ event "system" }}

### VPN

The `vpn` data stream collects metrics like CPS, ICA license, client-server requests, file system and sockets.

#### VPN fields

{{ fields "vpn" }}

{{ event "vpn" }}

### Logs

The `citrix_adc.log` dataset provides events from the configured syslog server.

#### Logs fields

{{ fields "log" }}

{{ event "log" }}

### Inputs used
{{ inputDocs }}

### API usage

These APIs are used with this integration:

*   [Interface](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/network/interface/)
*   [LBVserver](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/lb/lbvserver/)
*   [Service](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/basic/service/)
*   [System](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/system/system/)
*   [VPN](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/vpn/vpn/)
