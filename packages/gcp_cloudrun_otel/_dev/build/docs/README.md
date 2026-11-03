# GCP Cloud Run OpenTelemetry Assets

This package contains Kibana assets for monitoring [Cloud Run](https://cloud.google.com/run) services with Google Cloud Monitoring metrics collected by the OpenTelemetry Collector.

The package is **content only**. It does not configure data collection. Use the **[Google Cloud Monitoring (OpenTelemetry)](https://www.elastic.co/docs/reference/integrations/googlecloudmonitor_input_otel)** input package (`googlecloudmonitor_input_otel`) to collect Cloud Run metrics into Elasticsearch.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage
the Elastic Stack on your own hardware.

## Setup

Install the **[Google Cloud Monitoring OpenTelemetry Input](https://www.elastic.co/docs/reference/integrations/googlecloudmonitor_input_otel)** package (`googlecloudmonitor_input_otel`) and configure it to collect Cloud Run Cloud Monitoring metrics (for example, `run.googleapis.com/request_count`). This content package provides assets that visualize data collected by that input.

When configuring the input package, set the dataset name to `gcp.cloudrun.otel` so that data is written to the `metrics-gcp.cloudrun.otel-default` data stream, which these dashboards query.

## Dashboards

| Dashboard | Description |
|-----------|-------------|
| **[GCP OTel] Cloud Run Overview** | Overview of all Cloud Run services. Golden signals across the fleet: traffic, errors, latency, saturation, and cost/allocation efficiency. |
| **[GCP OTel] Cloud Run Service Detail** | Detail view of a single Cloud Run service. Covers golden signals, capacity and saturation, cold starts, revision rollouts, and cost. |

## Alerting Rule Templates
Alert rule templates provide pre-defined configurations for creating alert rules in Kibana.

For more information, refer to the [Elastic documentation](https://www.elastic.co/docs/reference/fleet/alerting-rule-templates).

Alert rule templates require Elastic Stack version 9.6.0 or later.

**The following alert rule templates are available:**

<details>
<summary>View the alert rule templates</summary>

| Name | Description |
|---|---|
| [GCP Cloud Run OTel] High 5xx error rate by service | Fast symptom alert: fires when a Cloud Run service returns more than 5% HTTP 5xx responses over a 30-minute window with at least 50 requests. Complements the availability SLO (burn rate) by catching acute error spikes. Note: 429s from the max-instances ceiling never reach request_count and are not visible here. |
| [GCP Cloud Run OTel] High CPU utilization by service | Fires when the p95 per-instance CPU utilisation of a Cloud Run service is 90% or higher over a 30-minute window. The autoscaler targets 60% CPU; sustained readings this high mean instances are CPU-bound and scale-out is lagging or capped. |
| [GCP Cloud Run OTel] High memory utilization by service | Fires when the p95 per-instance memory utilisation of a Cloud Run service is 85% or higher over a 30-minute window. Instances that exceed the memory limit are OOM-killed, which causes HTTP 500s and cold starts. |
| [GCP Cloud Run OTel] High request latency p95 by service | Fast symptom alert: fires when the in-container request latency p95 of a Cloud Run service exceeds 2,000 ms over a 30-minute window with at least 50 measured successful (2xx/3xx) requests. Excludes cold-start time (see the startup latency rule). Complements the latency SLO. |
| [GCP Cloud Run OTel] Slow container startup (cold start) by service | Fires when the p95 container startup latency of a Cloud Run service exceeds 10 seconds across at least 3 instance starts in a 60-minute window. Slow cold starts add directly to user-visible latency (not captured by request_latencies), and requests pending longer than max(10 s, 3.5x average startup time) are rejected with HTTP 429. |

</details>

## SLO Templates
{{sloTemplates}}

