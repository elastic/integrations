# Temporal OpenTelemetry Integration

Collect operational metrics from [Temporal Cloud](https://temporal.io/cloud/) using the Temporal OpenTelemetry Integration.

## Overview

This integration scrapes Temporal Cloud OpenMetrics using the [Prometheus (OTel) Input Package](https://www.elastic.co/docs/reference/integrations/prometheus_input_otel) into the **Cloud Metrics** data stream (`temporal.cloud_metrics.otel`): workflow lifecycle, task queues and polling, service latency and errors, namespace limits and throttles, schedules, and replication lag.

Metrics are stored with native OTel schema — no field renaming or custom mapping is applied.

Once data starts flowing, the **[Temporal OpenTelemetry Assets](https://www.elastic.co/docs/reference/integrations/temporal_otel)** package provides a Cloud Metrics dashboard, alerting rule templates, and SLO templates.

## Prerequisites

| Requirement | Details |
|---|---|
| **Temporal Cloud** | Account with permission to create a Service Account |
| **API key role** | Service Account with **Metrics Read-Only** account-level role |
| **Elastic Stack** | 9.5.0+ |
| **Input package** | `prometheus_input_otel` (installed automatically as a dependency) |
| **Content package** | `temporal_otel` (installed automatically as a dependency) |

## Setup

1. **Create a Temporal Cloud API key**:
   - Sign in to [Temporal Cloud](https://cloud.temporal.io/) as an Account Owner or Global Admin
   - Go to **Settings** → **Service Accounts** → create a Service Account with the **Metrics Read-Only** role
   - Generate an API key for that Service Account and store it securely

2. **Add the integration in Kibana**:
   - Go to **Management** → **Integrations** → search for "Temporal(OpenTelemetry) Integration"
   - Click **Add Temporal(OpenTelemetry) Integration**
   - Fill in:
     - **Temporal Cloud Metrics Endpoint**: `metrics.temporal.io:443` (default)
     - **Metrics Path**: `/v1/metrics` (default — set query parameters in **Query Parameters**, not here)
     - **Temporal Cloud API Key**: paste the Metrics Read-Only API key

3. **Verify data**:
   - Discover filter `data_stream.dataset: "temporal.cloud_metrics.otel"`

## Filtering metrics with query parameters

Temporal Cloud's OpenMetrics endpoint accepts query parameters that scope the response —
useful for reducing scrape size and staying within Temporal's per-scrape limits.

Set them in the **Query Parameters** field in the Fleet UI, as a YAML map of parameter
name to a list of values:

```yaml
<parameter-name>:
  - <value>
  - <value>
```

Do **not** append query parameters to the **Metrics Path** field. The Prometheus receiver
places that path verbatim into `url.URL.Path`, which percent-encodes `?` and breaks the
request.

For the parameters Temporal Cloud supports and their accepted values, see the
[Temporal Cloud OpenMetrics API reference](https://docs.temporal.io/cloud/metrics/openmetrics/api-reference).

## Metrics Reference

Metrics are scraped from:

```
GET https://metrics.temporal.io/v1/metrics
Authorization: Bearer <API_KEY>
```

Temporal Cloud aggregates metrics in one-minute windows. Each scrape returns only the most recently completed window — configure Elastic to retain history. Honor scrape timestamps (`honor_timestamps: true`, enabled by default).

See the [Temporal Cloud OpenMetrics documentation](https://docs.temporal.io/cloud/metrics/openmetrics/) and [metrics reference](https://docs.temporal.io/cloud/metrics/openmetrics/metrics-reference) for the full catalog.

### Metric Categories

| Category | Prefix / examples |
|---|---|
| Workflow lifecycle | `temporal_cloud_v1_workflow_success_count`, `*_failed_count`, `*_timeout_count`, schedule-to-close latency percentiles |
| Activity lifecycle | `temporal_cloud_v1_activity_success_count`, `*_fail_count`, activity latency percentiles |
| Task queues / polling | `temporal_cloud_v1_approximate_backlog_count`, `*_poll_success_count`, `*_poll_timeout_count`, `*_no_poller_tasks_count` |
| Service / frontend | `temporal_cloud_v1_service_request_count`, `*_service_error_count`, `*_service_latency_p99` |
| Limits / capacity | `temporal_cloud_v1_action_limit`, `*_operations_limit`, `*_poller_limit`, `*_provisioned_capacity_tru_count` |
| Schedules | `temporal_cloud_v1_schedule_action_success_count`, `*_schedule_rate_limited_count` |
| Replication | `temporal_cloud_v1_replication_lag_p50`, `*_p95`, `*_p99` |

All metrics are stored under the `metrics.*` field namespace with their original OpenMetrics names.

