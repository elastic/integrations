# Nvidia GPU Monitoring

Use the NVIDIA GPU Monitoring integration to monitor the health and performance of your NVIDIA GPUs. The integration collects metrics from the NVIDIA Datacenter GPU Manager and sends them to Elasticsearch.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

You need the NVIDIA Datacenter GPU Manager (DCGM) installed on your system (or exposed via a docker container with the GPU device mounted) to collect metrics from the NVIDIA GPUs. You can download the DCGM from the [NVIDIA website](https://developer.nvidia.com/dcgm). By default the DCGM exporter does not expose all available metrics, to customize the list of available metrics, a csv file with the desired metrics is required. For instructions on how to do this, review the dcgm-exporter documentation.

If DCGM Exporter is configured to provide enrichment of Kubernetes data, the pod, namespace, and container information will be attached to the corresponding metrics. This is useful for monitoring and attributing GPU usage in Kubernetes environments.

This integration has been tested with version 3.3.9 of the DCGM exporter.

## Setup

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

When running on Kubernetes, you can use ${env.NODE_NAME} to get the node name for use in the hosts field. For example: `hosts: http://${env.NODE_NAME}:9400/metrics`.

### Customizing the list of available metrics

With `dcgm-exporter` you can configure which fields are collected by specifying a custom CSV file.
You will find the default CSV file under `etc/default-counters.csv` in the repository, which is copied on your system or container to `/etc/dcgm-exporter/default-counters.csv`

The layout and format of this file is as follows:

```
# Format
# If line starts with a '#' it is considered a comment
# DCGM FIELD, Prometheus metric type, help message

# Clocks
DCGM_FI_DEV_SM_CLOCK,  gauge, SM clock frequency (in MHz).
DCGM_FI_DEV_MEM_CLOCK, gauge, Memory clock frequency (in MHz).
```

A custom csv file can be specified using the `-f` option or `--collectors` as follows:

```shell
dcgm-exporter -f /tmp/custom-collectors.csv
```

See more in the [DCGM Github Repository](https://github.com/NVIDIA/dcgm-exporter/tree/main)

## Data streams

### Stats

`stats` give you insight into the state of the NVIDIA GPUs.
Metric data streams collected by the Nvidia GPU Monitoring integration include `stats`. See more details in the [Metrics](#metrics-reference).

{{event "stats"}}

{{fields "stats"}}