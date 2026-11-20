# Google Cloud Metrics OpenTelemetry Integration

Collect [Google Cloud](https://cloud.google.com) service metrics from [Cloud Monitoring](https://cloud.google.com/monitoring/docs) using the Google Cloud Metrics OpenTelemetry Integration.

## Overview

This integration polls the Cloud Monitoring API using the [Google Cloud Monitoring (OTel) Input Package](https://www.elastic.co/docs/reference/integrations/googlecloudmonitor_input_otel) and indexes the resulting time series into a data stream per Google Cloud service.

Metrics are stored with native OTel schema — no field renaming or custom mapping is applied.

| Data stream | Dataset | Contents |
|---|---|---|
| Cloud Run | `gcp.cloudrun.otel` | Request count and latency, container startup latency, instance count, CPU and memory utilization and allocation, request concurrency, billable instance time, and network throughput |
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
     - **Collection Interval**: `300s` (default)
   - Enable the data stream for each service you want to collect, and leave its **Additional Metrics** empty unless you need metric types beyond the default set.

   Each data stream's default metric set is collected automatically and does not need to be configured.

3. **Verify data**:
   - Discover filter `data_stream.dataset: "gcp.cloudrun.otel"` or `data_stream.dataset: "gcp.compute.otel"`

## Cloud Run metrics

Every metric type is prefixed with `run.googleapis.com/`. See the [Cloud Run metrics catalog](https://cloud.google.com/monitoring/api/metrics_gcp_p_z#gcp-run) and [Monitor Cloud Run](https://cloud.google.com/run/docs/monitoring) for units, sampling periods, and resource labels.

### Default metric set

The integration always collects the metric set below, which covers the golden signals for Cloud Run services: traffic, errors, latency, saturation, cold starts, and cost. Anything added to **Additional Metrics** is collected on top of this set.

| Category | Metric types |
|---|---|
| Traffic and errors | `request_count` |
| Latency | `request_latencies`, `container/startup_latencies` |
| Scale | `container/instance_count` |
| Saturation | `container/cpu/utilizations`, `container/memory/utilizations`, `container/max_request_concurrencies` |
| Cost and allocation | `container/billable_instance_time`, `container/cpu/allocation_time`, `container/memory/allocation_time` |
| Network | `container/network/received_bytes_count`, `container/network/sent_bytes_count` |

Error rates come from the `response_code` and `response_code_class` attributes on `request_count` rather than from a separate metric. `request_latencies` measures in-container time and excludes cold start, which `container/startup_latencies` reports separately. `container/instance_count` is broken down by the `state` attribute, either `active` or `idle`.

`request_latencies`, `container/startup_latencies`, `container/cpu/utilizations`, `container/memory/utilizations`, and `container/max_request_concurrencies` are distribution-valued in Cloud Monitoring and arrive as OpenTelemetry histograms, so percentiles are derived from the histogram rather than read from a precomputed p95 or p99 field.

### Jobs and worker pools

Three Cloud Run products share the `run.googleapis.com/` prefix: services (`cloud_run_revision`), jobs (`cloud_run_job`), and worker pools (`cloud_run_worker_pool`). The default set targets services. Jobs and worker pools report no `request_count` or `request_latencies`, but they do report the container CPU, memory, startup latency, and billable time metrics above.

To monitor jobs, add these to **Additional Metrics**:

| Metric type | Contents |
|---|---|
| `run.googleapis.com/job/completed_execution_count` | Completions by `result`, either success or failure |
| `run.googleapis.com/job/completed_task_attempt_count` | Task attempts and retries |
| `run.googleapis.com/job/running_executions` | Currently running executions |
| `run.googleapis.com/job/running_task_attempts` | Currently running tasks |

### Field names

Metric type names are preserved verbatim under `metrics`, including the `run.googleapis.com/` prefix and the slashes, so queries use the full path:

```
metrics.run.googleapis.com/request_count
```

`project_id`, `service_name`, `revision_name`, `location`, `configuration_name`, and `gcp.resource_type` arrive as resource attributes under `resource.attributes.*`, while metric labels such as `response_code`, `response_code_class`, and `state` are datapoint attributes under `attributes.*`.

## Compute Engine metrics

Every metric type is prefixed with `compute.googleapis.com/`. See the [Compute Engine metrics catalog](https://cloud.google.com/monitoring/api/metrics_gcp#gcp-compute) for units, sampling periods, and resource labels.

### Default metric set

The integration always collects the metric set below. These metrics come from the hypervisor and are available for every instance without a guest agent installed. Anything added to **Additional Metrics** is collected on top of this set.

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

Memory balloon metrics are reported only for E2 machine types. `instance/disk/provisioning/iops` and `instance/disk/provisioning/throughput` are reported only for Hyperdisk volumes, and `instance/interruption_count` only when a Spot VM is preempted. These return empty results on projects without those resources, which is expected rather than a misconfiguration.

### Field names

Metric type names are preserved verbatim under `metrics`, including the `compute.googleapis.com/` prefix and the slashes, so queries use the full path:

```
metrics.compute.googleapis.com/instance/cpu/utilization
```

`instance_id`, `zone`, `project_id`, and `gcp.resource_type` arrive as resource attributes under `resource.attributes.*`, while `instance_name` is a datapoint attribute under `attributes.*`.

## Cost and quota

The receiver issues one time series query per collected metric type on every collection cycle, for every enabled data stream: 29 queries for Compute Engine and 12 for Cloud Run, so 41 per project per cycle with both enabled, or every five minutes at the default interval, plus one per entry in **Additional Metrics**. Review [Cloud Monitoring pricing](https://cloud.google.com/stackdriver/pricing#monitoring-costs) and [API quotas](https://cloud.google.com/monitoring/quotas#api_quotas) before lowering **Collection Interval** or adding metrics.

## Troubleshooting

### No metrics appear

1. Check the Elastic Agent logs for `failed to find default credentials` — the collector host has no usable ADC.
2. Confirm the credentials carry `roles/monitoring.viewer` on the configured project.
3. Confirm the project actually runs the service you enabled, Compute Engine instances or Cloud Run revisions, in the region you expect.
4. Allow time for the first collection cycle. Metrics reach Cloud Monitoring with up to several minutes of ingest delay.
5. If a metric added to **Additional Metrics** is missing, confirm it is an exact, existing metric type name. A typo yields an empty result for that metric rather than an error.

### Startup errors

- `"collection_interval" must be not lower than the allowed minimum` — raise **Collection Interval** to at least `60s`.
