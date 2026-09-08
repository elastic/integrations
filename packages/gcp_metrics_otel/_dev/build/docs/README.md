# Google Cloud Metrics OpenTelemetry Integration

Collect [Google Cloud](https://cloud.google.com) service metrics from [Cloud Monitoring](https://cloud.google.com/monitoring/docs) using the Google Cloud Metrics OpenTelemetry Integration.

## Overview

This integration polls the Cloud Monitoring API using the [Google Cloud Monitoring (OTel) Input Package](https://www.elastic.co/docs/reference/integrations/googlecloudmonitor_input_otel) and indexes the resulting time series into a data stream per Google Cloud service.

Metrics are stored with native OTel schema — no field renaming or custom mapping is applied.

| Data stream | Dataset | Contents |
|---|---|---|
| Compute Engine | `gcp.compute.otel` | Hypervisor CPU, disk, network, firewall, memory balloon, uptime, interruption, and instance group metrics |

Additional Google Cloud services will be added as further data streams.

## Prerequisites

| Requirement | Details |
|---|---|
| **Google Cloud project** | Cloud Monitoring API enabled |
| **Credentials** | Application Default Credentials available to the collector host, authorized with `roles/monitoring.viewer` |
| **Elastic Stack** | 9.6.0+ |
| **Input package** | `googlecloudmonitor_input_otel` (installed automatically as a dependency) |

## Setup

1. **Provide credentials to the Elastic Agent host**:

   The Google Cloud Monitoring receiver has no credential fields of its own — it always resolves [Application Default Credentials (ADC)](https://cloud.google.com/docs/authentication/application-default-credentials) from the environment the collector process runs in. Use one of the following, in order of preference:

   - **Workload identity** — when the agent runs on GKE, Cloud Run, or another Google Cloud compute service, credentials are supplied automatically.
   - **Service account key file** — set `GOOGLE_APPLICATION_CREDENTIALS` on the Elastic Agent host to the path of a service account JSON key before the agent starts.
   - **`gcloud auth application-default login`** — for development and testing only.

   The credentials need at minimum the `roles/monitoring.viewer` IAM role, or an equivalent custom role granting `monitoring.timeSeries.list` and `monitoring.metricDescriptors.list`.

2. **Add the integration in Kibana**:
   - Go to **Management** → **Integrations** → search for "Google Cloud Metrics (OpenTelemetry)"
   - Click **Add Google Cloud Metrics (OpenTelemetry)**
   - Fill in:
     - **GCP Project ID**: the project to query Cloud Monitoring metrics from
     - **Metrics List**: leave as-is to collect the default Compute Engine metric set, or edit the list
     - **Collection Interval**: `300s` (default)

3. **Verify data**:
   - Discover filter `data_stream.dataset: "gcp.compute.otel"`

## Compute Engine metrics

Every metric type is prefixed with `compute.googleapis.com/`. See the [Compute Engine metrics catalog](https://cloud.google.com/monitoring/api/metrics_gcp#gcp-compute) for units, sampling periods, and resource labels.

### Default metric set

These metrics come from the hypervisor and are available for every instance without a guest agent installed.

| Category | Metric types |
|---|---|
| CPU | `instance/cpu/utilization`, `instance/cpu/usage_time`, `instance/cpu/reserved_cores`, `instance/cpu/guest_visible_vcpus`, `instance/cpu/scheduler_wait_time` |
| Disk throughput and IOPS | `instance/disk/read_bytes_count`, `instance/disk/read_ops_count`, `instance/disk/write_bytes_count`, `instance/disk/write_ops_count` |
| Disk latency and saturation | `instance/disk/average_io_latency`, `instance/disk/average_io_queue_depth`, `instance/disk/performance_status` |
| Disk capacity | `instance/disk/provisioning/iops`, `instance/disk/provisioning/throughput`, `instance/disk/provisioning/size` |
| Network | `instance/network/received_bytes_count`, `instance/network/received_packets_count`, `instance/network/sent_bytes_count`, `instance/network/sent_packets_count` |
| Firewall | `firewall/dropped_bytes_count`, `firewall/dropped_packets_count` |
| Memory balloon | `instance/memory/balloon/ram_size`, `instance/memory/balloon/ram_used`, `instance/memory/balloon/swap_in_bytes_count`, `instance/memory/balloon/swap_out_bytes_count` |
| Availability | `instance/uptime`, `instance/uptime_total`, `instance/interruption_count`, `instance_group/size` |

Memory balloon metrics are reported only for E2 machine types.

### Optional guest metrics

In-guest memory and filesystem usage are not visible to the hypervisor. Instances only report the metrics below when they run [Container-Optimized OS health monitoring](https://cloud.google.com/container-optimized-os/docs/how-to/monitoring) or the [Ops Agent](https://cloud.google.com/stackdriver/docs/solutions/agents/ops-agent). Append them to **Metrics List** once the instances emit them; until then the receiver returns empty results for these metric types.

| Category | Metric types |
|---|---|
| Memory | `guest/memory/percent_used`, `guest/memory/bytes_used` |
| Disk | `guest/disk/percent_used`, `guest/disk/bytes_used`, `guest/disk/queue_length` |
| CPU | `guest/cpu/load_1m`, `guest/cpu/runnable_task_count` |
| System | `guest/system/problem_count`, `guest/system/uptime` |

### Advanced selection

**Metric Descriptor Filters** is an alternative to naming exact metric types. Each entry is a [metric descriptor filter expression](https://cloud.google.com/monitoring/api/v3/filters#metric-descriptor-filter) resolved dynamically at startup, for example `metric.type = starts_with("compute.googleapis.com/instance/")`. Only the `project` and `metric.type` filter objects are supported.

Filters pick up new metric types automatically as Google adds them, at the cost of a less predictable collection volume and Cloud Monitoring API bill.

## Cost and quota

The receiver issues one time series query per configured metric type on every collection cycle. With the default metric set and a `300s` interval that is 29 queries every five minutes per project. Review [Cloud Monitoring pricing](https://cloud.google.com/stackdriver/pricing#monitoring-costs) and [API quotas](https://cloud.google.com/monitoring/quotas#api_quotas) before lowering the interval or widening the metric list.

## Troubleshooting

### No metrics appear

1. Check the Elastic Agent logs for `failed to find default credentials` — the collector host has no usable ADC.
2. Confirm the credentials carry `roles/monitoring.viewer` on the configured project.
3. Confirm each entry in **Metrics List** is an exact, existing metric type name. A typo yields an empty result for that metric rather than an error.
4. Allow time for the first collection cycle. Compute Engine metrics reach Cloud Monitoring with up to several minutes of ingest delay.

### Startup errors

- `"collection_interval" must be not lower than...` — raise **Collection Interval** to at least `60s`.
- `missing required field "metrics_list" or its value is empty` — add at least one entry to **Metrics List** or **Metric Descriptor Filters**.
