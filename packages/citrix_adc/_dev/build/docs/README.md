# Citrix ADC Integration

## Overview

The Citrix ADC integration allows you to monitor your Citrix ADC instance. Citrix ADC is an application delivery controller that performs application-specific traffic analysis to intelligently distribute, optimize, and secure Layer 4 - Layer 7 (L4–L7) network traffic for web applications.

The Citrix Web App Firewall prevents security breaches, data loss, and possible unauthorized modifications to websites that access sensitive business or customer information. It does so by filtering both requests and responses, examining them for evidence of malicious activity, and blocking requests that exhibit such activity. Your site is protected not only from common types of attacks, but also from new, as yet unknown attacks. In addition to protecting web servers and websites from unauthorized access, the Web App Firewall protects against vulnerabilities in legacy CGI code or scripts, web frameworks, web server software, and other underlying operating systems.

Use the Citrix ADC integration to:

Collect metrics related to the interface, lbvserver, service, system, vpn and logs.
Create visualizations to monitor, measure and analyze the usage trend and key data, and derive business insights.
Create alerts to reduce the MTTD and also the MTTR by referencing relevant logs when troubleshooting an issue.

As an example, you can use the data from this integration to understand the load of the virtual servers, client-server connections, requests and responses across the Citrix ADC.

## Data streams

The Citrix ADC integration collects metrics data.

Metrics give you insight into the statistics of the Citrix ADC. Metrics data streams collected by the Citrix ADC integration include [interface](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/network/interface/), [lbvserver](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/lb/lbvserver/), [service](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/basic/service/), [system](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/system/system/) and [vpn](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/vpn/vpn/), so that the user could monitor and troubleshoot the performance of the Citrix ADC instances.

**Log** is used to retrieve Citrix Netscaler logs. See more details in the documentation [here](https://developer-docs.netscaler.com/en-us/netscaler-syslog-message-reference/current-release).

**NOTE:** You can monitor metrics and logs inside the ingested documents for Citrix ADC in the `logs-*` index pattern from `Discover`.

## Compatibility

This integration has been tested against Citrix ADC `v13.0`, `v13.1` and `v14.1`.

## Requirements

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). 

The minimum **Kibana version** required is **8.12.0**.  

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

To ingest data from Citrix ADC, you must know the host(s) and the administrator credentials for the Citrix ADC instance.

Host Configuration Format: `http[s]://<hostname>:<port>`
Example Host Configuration: `http://example.com:9090`

## Setup
  
For step-by-step instructions on how to set up an integration, check the [quick start](integrations://docs/extend/quick-start.md).

**NOTE:** It is recommended to configure the application firewall to enable CEF-formatted logs.

### Configure CEF format

1. Navigate to **Security** the NetScaler GUI.
2. Click **Application Firewall** node.
3. Select Change Engine Settings.
4. Enable CEF Logging.

### Configure Syslog format

You can use the Citrix WAF GUI to configure syslog servers and WAF message types to be sent to the syslog servers. Refer to [How to Send Application Firewall Messages to a Separate Syslog Server](https://support.citrix.com/s/article/CTX138973-how-to-send-application-firewall-messages-to-a-separate-syslog-server) and [How to Send NetScaler Application Firewall Logs to Syslog Server and NS.log](https://support.citrix.com/s/article/CTX483235-send-logs-to-external-syslog-server?language=en_US) for details.

**NOTE:** Using RFC 5424 compliant syslog messages is recommended when using syslog, if supported by NetScaler. Support for RFC 5424 was added in NetScaler 14.1. Refer to [Configuring audit log action](https://docs.netscaler.com/en-us/citrix-adc/current-release/system/audit-logging/configuring-audit-logging.html#configuring-audit-log-action).

## Validation

After the integration is successfully configured, click the Assets tab of the Citrix ADC Integration to display a list of available dashboards. The dashboard for your configured datastream should be populated with the required data.

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search bar, type **Citrix ADC**.
3. Select the **Citrix ADC** integration and add it.
4. While adding the integration, if you want to collect logs via logfile, keep **Collect logs from Citrix ADC via file** toggle on and then configure following parameters:
   - Paths

   or if you want to collect logs via TCP, keep **Collect logs from Citrix ADC via TCP** toggle on and then configure following parameters:
   - Listen Address
   - Listen Port

   or if you want to collect logs via UDP, keep **Collect logs from Citrix ADC via UDP** toggle on and and then configure following parameters:
   - Listen Address
   - Listen Port
5. Save the integration.

### Troubleshooting

#### Dummy values

It is possible that for some fields, Citrix ADC sets dummy values. For example, a field `cpuusagepcnt` is represented by `citrix_adc.system.cpu.utilization.pct`. `cpuusagepcnt` is set to `4294967295` for some [instances](https://github.com/citrix/citrix-adc-metrics-exporter/issues/44). If you also encounter it for some fields, reach out to the [Citrix ADC support team](https://support.citrix.com/plp/products/citrix_adc/tabs/popular-solutions).

#### Type conflicts

If `host.ip` is shown conflicted under ``logs-*`` data view, this issue can be solved by [reindexing](https://www.elastic.co/guide/en/elasticsearch/reference/current/use-a-data-stream.html#reindex-with-a-data-stream) the ``Interface``, ``LBVserver``, ``Service``, ``System``, and ``VPN`` data stream's indices.

## Metrics reference

### Interface

This is the `interface` data stream. The Citrix ADC interfaces are numbered in slot/port notation. In addition to modifying the characteristics of individual interfaces, you can configure virtual LANs to restrict traffic to specific groups of hosts. `interface` data stream collects metrics related to id, state, inbound packets, outbound packets and received packets.

{{event "interface"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "interface"}}

### Load Balancing Virtual Server

This is the `lbvserver` data stream. The load balancing server is logically located between the client and the server farm, and manages traffic flow to the servers in the server farm. `lbvserver` data stream collects metrics related to name, state, client connections, requests and responses.

{{event "lbvserver"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "lbvserver"}}

### Service

This is the `service` data stream. With the help of the service endpoint, metrics like throughput, client-server connections, request bytes can be collected along with other statistics for Service resources. `service` data stream collects metrics related to name, IP address, port, throughput and transactions.

{{event "service"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "service"}}

### System

This is the `system` data stream. With the help of the system endpoint, metrics like memory in use, total system memory, CPU count can be collected along with other statistics for system resources.

{{event "system"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "system"}}

### VPN

This is the `vpn` data stream. Citrix VPN is the add-on that provides full Secure Sockets Layer (SSL) virtual private network (VPN) capabilities to Citrix Gateway, allowing users to access remote applications on internal networks securely. `vpn` data stream collects metrics like CPS, ICA license, client-server requests, file system and sockets.

{{event "vpn"}}

**ECS Field Reference**

Check this [reference document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for more information on ECS fields.

{{fields "vpn"}}

### Logs

The `citrix_adc.log` dataset provides events from the configured syslog server.

{{event "log"}}

**ECS Field Reference**

Check this [reference document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for more information on ECS fields.

{{fields "log"}}
