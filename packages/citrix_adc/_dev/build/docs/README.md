# Citrix ADC Integration

## Overview

The Citrix ADC integration allows you to monitor your Citrix ADC instance. Citrix ADC is an application delivery controller that performs application-specific traffic analysis to intelligently distribute, optimize, and secure Layer 4 - Layer 7 (L4–L7) network traffic for web applications.

Use the Citrix ADC integration to:

Collect metrics related to the interface, lbvserver, service, system and vpn.
Create visualizations to monitor, measure and analyze the usage trend and key data, and derive business insights.
Create alerts to reduce the MTTD and also the MTTR by referencing relevant logs when troubleshooting an issue.

As an example, you can use the data from this integration to understand the load of the virtual servers, client-server connections, requests and responses across the Citrix ADC.

## Data streams

The Citrix ADC integration collects metrics data.

Metrics give you insight into the statistics of the Citrix ADC. Metrics data streams collected by the Citrix ADC integration include [interface](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/network/interface/), [lbvserver](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/lb/lbvserver/), [service](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/basic/service/), [system](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/system/system/) and [vpn](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/vpn/vpn/), so that the user could monitor and troubleshoot the performance of the Citrix ADC instances.

Note:
- Users can monitor and see the metrics inside the ingested documents for Citrix ADC in the logs-* index pattern from `Discover`.

## Compatibility

This integration has been tested against Citrix ADC `v13.0` and `v13.1`.

## Prerequisites

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

In order to ingest data from Citrix ADC, you must know the host(s) and the administrator credentials for the Citrix ADC instance.

Host Configuration Format: `http[s]://host[:port]`

Example Host Configuration: `http://localhost:9080`

## Setup
  
For step-by-step instructions on how to set up an integration, see the [Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Validation

After the integration is successfully configured, clicking on the Assets tab of the Citrix ADC Integration should display a list of available dashboards. Click on the dashboard available for your configured datastream. It should be populated with the required data.

### Troubleshooting

There could be a possibility that for some of the fields, Citrix ADC sets dummy values. For example, a field `cpuusagepcnt` is represented by `citrix_adc.system.cpu.utilization.pct`. `cpuusagepcnt` is set to `4294967295` for some [instances](https://github.com/citrix/citrix-adc-metrics-exporter/issues/44). If you also encounter it for some fields please reach out to the [Citrix ADC support team](https://support.citrix.com/plp/products/citrix_adc/tabs/popular-solutions).

## Metrics reference

### Interface

This is the `interface` data stream. The Citrix ADC interfaces are numbered in slot/port notation. In addition to modifying the characteristics of individual interfaces, you can configure virtual LANs to restrict traffic to specific groups of hosts. `interface` data stream collects metrics related to id, state, inbound packets, outbound packets and received packets.

{{event "interface"}}

{{fields "interface"}}

### Load Balancing Virtual Server

This is the `lbvserver` data stream. The load balancing server is logically located between the client and the server farm, and manages traffic flow to the servers in the server farm. `lbvserver` data stream collects metrics related to name, state, client connections, requests and responses.

{{event "lbvserver"}}

{{fields "lbvserver"}}

### Service

This is the `service` data stream. With the help of the service endpoint, metrics like throughput, client-server connections, request bytes can be collected along with other statistics for Service resources. `service` data stream collects metrics related to name, IP address, port, throughput and transactions.

{{event "service"}}

{{fields "service"}}

### System

This is the `system` data stream. With the help of the system endpoint, metrics like memory in use, total system memory, CPU count can be collected along with other statistics for system resources.

{{event "system"}}

{{fields "system"}}

### VPN

This is the `vpn` data stream. Citrix VPN is the add-on that provides full Secure Sockets Layer (SSL) virtual private network (VPN) capabilities to Citrix Gateway, allowing users to access remote applications on internal networks securely. `vpn` data stream collects metrics like CPS, ICA license, client-server requests, file system and sockets.

{{event "vpn"}}

{{fields "vpn"}}