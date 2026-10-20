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
Alert rule templates provide pre-defined configurations for creating alert rules in Kibana.

For more information, refer to the [Elastic documentation](https://www.elastic.co/docs/reference/fleet/alerting-rule-templates).

Alert rule templates require Elastic Stack version 9.6.0 or later.

**The following alert rule templates are available:**

<details>
<summary>View the alert rule templates</summary>

| Name | Description |
|---|---|
| [GCP Compute OTel] CPU saturation across a zone | Alerts when a significant share of the VM fleet in a zone runs at or above 90% of its reserved CPU cores (averaged over 15 minutes). Fleet-level by design: a single busy VM does not page. Returns one row per breaching project and zone with the saturated instance names. |
| [GCP Compute OTel] CPU steal from host contention | Alerts when VMs in a zone spend at least 10% of their vCPU time ready to run but not scheduled by the hypervisor (CPU steal, from scheduler_wait_time) over 15 minutes. Shared-core VMs, which are throttled by design, are excluded. Returns one row per affected project and zone. |
| [GCP Compute OTel] Disk at provisioned IOPS or throughput limit | Alerts when a disk with independently provisioned performance (Hyperdisk, pd-extreme) uses at least 90% of its provisioned IOPS or provisioned throughput, averaged over 15 minutes. Disks without provisioning metrics (pd-standard, pd-balanced, pd-ssd) are skipped. Returns one row per saturated disk. |
| [GCP Compute OTel] Persistent disk I/O saturation | Alerts when an attached disk has a sustained deep I/O queue (average queue depth >= 8) combined with elevated average I/O latency over 15 minutes, indicating it is at its IOPS or throughput ceiling. Latency thresholds differ by storage type. Returns one row per saturated disk. |
| [GCP Compute OTel] Disk performance severely degraded | Alerts when GCE reports a disk's performance status as Severely Degraded for every sample in a 20-minute window. The routine Degraded status is intentionally ignored. Returns one row per affected disk. |
| [GCP Compute OTel] Firewall dropped packet spike | Alerts when the VPC firewall dropped-packet rate for a zone spikes: the peak 5-minute rate is at least 1000 packets/s and at least 5 times the median 5-minute rate over the last hour. Returns one row per affected project and zone. |
| [GCP Compute OTel] Managed instance group size drop | Alerts when a managed instance group loses at least half of its instances (and at least 2) within 30 minutes, comparing the current size with the maximum size in the window. Returns one row per affected instance group. |
| [GCP Compute OTel] Memory pressure across a zone | Alerts when multiple VMs in a zone are under memory pressure: at least 95% of guest RAM in use (balloon driver view) or sustained swap-in of at least 1 MiB/s, averaged over 15 minutes. Fleet-level by design. Returns one row per breaching project and zone. |
| [GCP Compute OTel] Clustered VM interruptions in a zone | Alerts when at least 3 distinct VMs in the same zone record an interruption (live-migration maintenance event or preemption) within 30 minutes. Single maintenance events are expected background noise and do not alert. Returns one row per affected project and zone. |

</details>

## SLO Templates
{{sloTemplates}}
