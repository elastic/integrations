# Temporal (OpenTelemetry)

Collect operational metrics from [Temporal Cloud](https://temporal.io/cloud/) and optionally from Temporal Worker Prometheus endpoints using the Temporal (OpenTelemetry) integration.

## Overview

This integration scrapes Prometheus-compatible metrics using the [Prometheus (OTel) Input Package](https://www.elastic.co/docs/reference/integrations/prometheus_input_otel). Metrics are collected into two data streams:

- **Cloud Metrics** (`temporal.cloud_metrics.otel`) — Temporal Cloud OpenMetrics: workflow lifecycle, task queues and polling, service latency and errors, namespace limits and throttles, schedules, and replication lag
- **SDK Metrics** (`temporal.sdk_metrics.otel`) — Worker and Temporal SDK metrics scraped from each Worker’s Prometheus endpoint (typically `/metrics`: schedule-to-start latency, activity execution, sticky cache, worker slots)

Metrics are stored with native OTel schema — no field renaming or custom mapping is applied.

## Prerequisites

| Requirement | Details |
|---|---|
| **Temporal Cloud** | Account with permission to create a Service Account |
| **API key role** | Service Account with **Metrics Read-Only** account-level role |
| **Worker / SDK (optional)** | Temporal Worker instrumented with the SDK Prometheus metrics reporter and exposing a scrape endpoint (typically `/metrics`) |
| **Elastic Stack** | 9.5.0+ |
| **Input package** | `prometheus_input_otel` (installed automatically as a dependency) |

## Setup

1. **Create a Temporal Cloud API key**:
   - Sign in to [Temporal Cloud](https://cloud.temporal.io/) as an Account Owner or Global Admin
   - Go to **Settings** → **Service Accounts** → create a Service Account with the **Metrics Read-Only** role
   - Generate an API key for that Service Account and store it securely

2. **Add the integration in Kibana**:
   - Go to **Management** → **Integrations** → search for "Temporal (OpenTelemetry)"
   - Click **Add Temporal (OpenTelemetry)**
   - Fill in:
     - **Temporal Cloud Metrics Endpoint**: `metrics.temporal.io:443` (default)
     - **Metrics Path**: `/v1/metrics` (optionally append `?namespaces=<namespace>` to filter)
     - **Temporal Cloud API Key**: paste the Metrics Read-Only API key

3. **(Optional) Enable Temporal SDK Metrics** in the same integration policy:
   - Instrument the Worker with a Temporal SDK **Prometheus** reporter so it exposes a scrape endpoint (for example `:8077/metrics`). See [Temporal SDK metrics](https://docs.temporal.io/references/sdk-metrics) and your language’s [observability docs](https://docs.temporal.io/develop/go/platform/observability).
   - Turn on the **Temporal SDK Metrics** stream
   - Set **SDK Metrics Endpoint** to each Worker Prometheus listen address.
   - **Metrics Path**: `/metrics` (default — change if your Worker exposes a different path), Scheme: `http` (default unless TLS is terminated in front of the Worker)

4. **Verify data**:
   - Cloud: Discover filter `data_stream.dataset: "temporal.cloud_metrics.otel"`
   - SDK: Discover filter `data_stream.dataset: "temporal.sdk_metrics.otel"`

## Metrics Reference

### Cloud Metrics

Metrics are scraped from:

```
GET https://metrics.temporal.io/v1/metrics
Authorization: Bearer <API_KEY>
```

Temporal Cloud aggregates metrics in one-minute windows. Each scrape returns only the most recently completed window — configure Elastic to retain history.

See the [Temporal Cloud OpenMetrics documentation](https://docs.temporal.io/cloud/metrics/openmetrics/) and [metrics reference](https://docs.temporal.io/cloud/metrics/openmetrics/metrics-reference) for the full catalog.

#### Metric Categories

| Category | Prefix / examples |
|---|---|
| Workflow lifecycle | `temporal_cloud_v1_workflow_success_count`, `*_failed_count`, `*_timeout_count`, schedule-to-close latency percentiles |
| Activity lifecycle | `temporal_cloud_v1_activity_success_count`, `*_fail_count`, activity latency percentiles |
| Task queues / polling | `temporal_cloud_v1_approximate_backlog_count`, `*_poll_success_count`, `*_poll_timeout_count`, `*_no_poller_tasks_count` |
| Service / frontend | `temporal_cloud_v1_service_request_count`, `*_service_error_count`, `*_service_latency_p99` |
| Limits / capacity | `temporal_cloud_v1_action_limit`, `*_operations_limit`, `*_poller_limit`, `*_provisioned_capacity_tru_count` |
| Schedules | `temporal_cloud_v1_schedule_action_success_count`, `*_schedule_rate_limited_count` |
| Replication | `temporal_cloud_v1_replication_lag_p50`, `*_p95`, `*_p99` |

### SDK Metrics

Worker/SDK metrics are **not** on the Temporal Cloud OpenMetrics endpoint. This integration scrapes them from each Worker’s Prometheus scrape endpoint (typically `/metrics`) after the Worker is instrumented with a Temporal SDK Prometheus reporter (for example Tally/Prometheus in Go). Configure **Metrics Path** if your Worker exposes a different path.

```
GET http://<worker-host>:<port>/metrics
```

See the [Temporal SDK metrics reference](https://docs.temporal.io/references/sdk-metrics) for the full catalog. Exact series suffixes can vary by SDK and Prometheus client (for example `_total`, `_bucket`).

#### Metric Categories

| Category | Prefix / examples |
|---|---|
| Schedule-to-start latency | `temporal_workflow_task_schedule_to_start_latency`, `temporal_activity_schedule_to_start_latency` |
| Workflow / activity execution | `temporal_workflow_completed`, `temporal_workflow_failed`, `temporal_activity_execution_latency`, `temporal_activity_succeed_endtoend_latency` |
| Worker slots / capacity | `temporal_worker_task_slots_available`, `temporal_worker_task_slots_used` |
| Sticky cache | `temporal_sticky_cache_size`, `temporal_sticky_cache_hit`, `temporal_sticky_cache_miss`, `temporal_sticky_cache_total_forced_eviction` |
| Polling | `temporal_workflow_task_queue_poll_succeed`, `temporal_activity_poll_no_task` |

All metrics (Cloud and SDK) are stored under the `metrics.*` field namespace with their original Prometheus / OpenMetrics names.

## Notes

- Worker / SDK metrics require Prometheus instrumentation on the Worker (scrape path typically `/metrics`) and this integration’s **SDK Metrics** scrape stream. They are not available from Cloud OpenMetrics alone.
- Account scrape rate limit for Temporal Cloud: 180 requests per hour (~every 20–30 seconds). Prefer a 30s–60s Cloud scrape interval.
