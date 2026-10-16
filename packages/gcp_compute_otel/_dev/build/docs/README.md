# GCP Compute Engine OpenTelemetry Assets

This package contains Kibana assets for monitoring [Compute Engine](https://cloud.google.com/compute) virtual machines with Google Cloud Monitoring metrics collected by the OpenTelemetry Collector.

The package is **content only**. It does not configure data collection. Use the **[Google Cloud Monitoring (OpenTelemetry)](https://www.elastic.co/docs/reference/integrations/googlecloudmonitor_input_otel)** input package (`googlecloudmonitor_input_otel`) to collect Compute Engine metrics into Elasticsearch.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage
the Elastic Stack on your own hardware.

## Setup

Install the **[Google Cloud Monitoring OpenTelemetry Input](https://www.elastic.co/docs/reference/integrations/googlecloudmonitor_input_otel)** package (`googlecloudmonitor_input_otel`) and configure it to collect Compute Engine Cloud Monitoring metrics (for example, `compute.googleapis.com/instance/cpu/utilization`). This content package provides assets that visualize data collected by that input.

When configuring the input package, set the dataset name to `gcp.compute.otel` so that data is written to the `metrics-gcp.compute.otel-default` data stream, which these dashboards query.

## Dashboards

| Dashboard | Description |
|-----------|-------------|
| **[GCP Compute] Overview** | Fleet-wide health overview covering CPU utilization, memory, swap, disk throughput, IOPS, latency, network, firewall drops, and instance availability across zones. |
| **[GCP Compute] GCE Instance Detail** | Per-instance deep-dive into CPU, memory, swap, network throughput, disk throughput, IOPS, I/O latency, queue depth, disk health, uptime, and interruption events. |

## Alerting Rule Templates
{{alertRuleTemplates}}

## SLO Templates
{{sloTemplates}}
