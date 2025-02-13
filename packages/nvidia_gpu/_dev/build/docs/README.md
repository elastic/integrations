# Nvidia GPU Monitoring

Use the NVIDIA GPU Monitoring integration to monitor the health and performance of your NVIDIA GPUs. The integration collects metrics from the NVIDIA Datacenter GPU Manager and sends them to Elasticsearch.

## Data streams

**stats** give you insight into the state of the NVIDIA GPUs.
Metric data streams collected by the Nvidia GPU Monitoring integration include `stats`. See more details in the [Metrics](#metrics-reference).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

You need the NVIDIA Datacenter GPU Manager (DCGM) installed on your system (or exposed via a docker container with the GPU device mounted) to collect metrics from the NVIDIA GPUs. You can download the DCGM from the [NVIDIA website](https://developer.nvidia.com/dcgm). By default the DCGM exporter does not expose all available metrics.

## Setup

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

When running on Kubernetes, you can use ${env.NODE_NAME} to get the node name for use in the hosts field. For example: `hosts: http://${env.NODE_NAME}:9400/metrics`.


{{event "stats"}}
{{fields "stats"}}