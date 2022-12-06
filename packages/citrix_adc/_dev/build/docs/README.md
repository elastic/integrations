# Citrix ADC Integration

## Overview

The Citrix ADC integration allows you to monitor your Citrix ADC instance. Citrix ADC is an application delivery controller that performs application-specific traffic analysis to intelligently distribute, optimize, and secure Layer 4 - Layer 7 (L4–L7) network traffic for web applications.

Use the Citrix ADC integration to collect metrics related to the interface and service. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference logs when troubleshooting an issue.

## Data streams

The Citrix ADC integration collects metrics data.

Metrics give you insight into the statistics of the Citrix ADC. Metrics data streams collected by the Citrix ADC integration include [interface](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/network/interface/) and [service](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/basic/service/), so that the user could monitor and troubleshoot the performance of the Citrix ADC instances.

Note:
- Users can monitor and see the metrics inside the ingested documents for Citrix ADC in the logs-* index pattern from `Discover`.

## Compatibility

This integration has been tested against Citrix ADC `v13.0` and `v13.1`.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

In order to ingest data from Citrix ADC, you must know the host(s) and the administrator credentials for the Citrix ADC instance.

Host Configuration Format: `http[s]://host[:port]`

Example Host Configuration: `http://localhost:9080`

## Metrics reference

### Interface

This is the `interface` data stream. The Citrix ADC interfaces are numbered in slot/port notation. In addition to modifying the characteristics of individual interfaces, you can configure virtual LANs to restrict traffic to specific groups of hosts.

{{event "interface"}}

{{fields "interface"}}

### Service

This is the `service` data stream. With the help of the service endpoint, metrics like throughput, client-server connections, request bytes can be collected along with other statistics for Service resources.

{{event "service"}}

{{fields "service"}}
