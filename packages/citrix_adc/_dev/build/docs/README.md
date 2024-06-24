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

Note:
- Users can monitor and see the metrics and logs inside the ingested documents for Citrix ADC in the logs-* index pattern from `Discover`.
## Requirements

Elastic Agent must be installed. For more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).  

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

The minimum **Kibana version** required is **8.12.0**.  

## Compatibility

This integration has been tested against Citrix ADC `v13.0`, `v13.1` and `v14.1`.

## Prerequisites

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

In order to ingest data from Citrix ADC, you must know the host(s) and the administrator credentials for the Citrix ADC instance.

Host Configuration Format: `http[s]://host[:port]`

Example Host Configuration: `http://localhost:9080`

## Setup
  
For step-by-step instructions on how to set up an integration, see the [Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

### Steps for configuring CEF format:

1. Navigate to **Security** the NetScaler GUI.
2. Click **Application Firewall** node.
3. Select Change Engine Settings.
4. Enable CEF Logging.

**Note**: It is recommended to configure the application firewall to enable CEF-formatted logs.

### Steps for configuring Syslog format:

The Citrix WAF GUI can be used to configure syslog servers and WAF message types to be sent to the syslog servers. Refer to [How to Send Application Firewall Messages to a Separate Syslog Server](https://support.citrix.com/article/CTX138973) and [How to Send NetScaler Application Firewall Logs to Syslog Server and NS.log](https://support.citrix.com/article/CTX211543) for details.

## Validation

After the integration is successfully configured, clicking on the Assets tab of the Citrix ADC Integration should display a list of available dashboards. Click on the dashboard available for your configured datastream. It should be populated with the required data.

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations
2. In "Search for integrations" search bar, type Citrix ADC
3. Click on the "Citrix ADC" integration from the search results.
4. Click on the "Add Citrix ADC" button to add the integration.
5. While adding the integration, if you want to collect logs via logfile, keep **Collect logs from Citrix ADC via file** toggle on and then configure following parameters:
   - Paths

   or if you want to collect logs via TCP, keep **Collect logs from Citrix ADC via TCP** toggle on and then configure following parameters:
   - Listen Address
   - Listen Port

   or if you want to collect logs via UDP, keep **Collect logs from Citrix ADC via UDP** toggle on and and then configure following parameters:
   - Listen Address
   - Listen Port
6. Save the integration.

### Troubleshooting

#### Dummy values

There could be a possibility that for some of the fields, Citrix ADC sets dummy values. For example, a field `cpuusagepcnt` is represented by `citrix_adc.system.cpu.utilization.pct`. `cpuusagepcnt` is set to `4294967295` for some [instances](https://github.com/citrix/citrix-adc-metrics-exporter/issues/44). If you also encounter it for some fields please reach out to the [Citrix ADC support team](https://support.citrix.com/plp/products/citrix_adc/tabs/popular-solutions).


#### Type conflicts

If host.ip is shown conflicted under ``logs-*`` data view, then this issue can be solved by [reindexing](https://www.elastic.co/guide/en/elasticsearch/reference/current/use-a-data-stream.html#reindex-with-a-data-stream) the ``Interface``, ``LBVserver``, ``Service``, ``System``, and ``VPN`` data stream's indices.

## Metrics reference

### Interface

This is the `interface` data stream. The Citrix ADC interfaces are numbered in slot/port notation. In addition to modifying the characteristics of individual interfaces, you can configure virtual LANs to restrict traffic to specific groups of hosts. `interface` data stream collects metrics related to id, state, inbound packets, outbound packets and received packets.

{{event "interface"}}

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "interface"}}

### Load Balancing Virtual Server

This is the `lbvserver` data stream. The load balancing server is logically located between the client and the server farm, and manages traffic flow to the servers in the server farm. `lbvserver` data stream collects metrics related to name, state, client connections, requests and responses.

{{event "lbvserver"}}

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "lbvserver"}}

### Service

This is the `service` data stream. With the help of the service endpoint, metrics like throughput, client-server connections, request bytes can be collected along with other statistics for Service resources. `service` data stream collects metrics related to name, IP address, port, throughput and transactions.

{{event "service"}}

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "service"}}

### System

This is the `system` data stream. With the help of the system endpoint, metrics like memory in use, total system memory, CPU count can be collected along with other statistics for system resources.

{{event "system"}}

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "system"}}

### VPN

This is the `vpn` data stream. Citrix VPN is the add-on that provides full Secure Sockets Layer (SSL) virtual private network (VPN) capabilities to Citrix Gateway, allowing users to access remote applications on internal networks securely. `vpn` data stream collects metrics like CPS, ICA license, client-server requests, file system and sockets.

{{event "vpn"}}

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "vpn"}}

### Logs

The `citrix_adc.log` dataset provides events from the configured syslog server.

{{event "log"}}

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "log"}}