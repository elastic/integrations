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

## SLO Templates
SLO templates provide pre-defined configurations for creating SLOs in Kibana.

For more information, refer to the [Elastic documentation](https://www.elastic.co/docs/solutions/observability/incident-management/service-level-objectives-slos).

SLO templates require Elastic Stack version 9.4.0 or later.

**The following SLO templates are available:**

<details>
<summary>View the SLO templates</summary>

| Name | Description |
|---|---|
| [GCP Cloud Run OTel] Request latency under 1 second 99% rolling 30 days | Tracks the share of successful (2xx and 3xx) requests to each Google Cloud Run service that complete in under 1000 ms inside the container, from the run.googleapis.com/request_latencies histogram (milliseconds). Good events are histogram observations from 0 to 1000 ms; total events are all observations. 5xx responses are excluded because the availability SLO covers them. 1xx (WebSocket upgrade) and 4xx responses are also excluded. The objective is 99% of requests over a rolling 30-day window, per service in each GCP project and region. Limitations: request_latencies starts when a request reaches a running instance, so it excludes cold-start time (see container/startup_latencies) and time spent pending in the load balancer during scale-out. Services with long-lived streaming responses (server-sent events, gRPC streaming, HTTP/2 streams) record the whole stream duration, so exclude them or raise the threshold. GCP buckets this distribution with a growth factor of 1.1, so the 1000 ms boundary is accurate to about 5%. Tune the threshold to each service's latency budget. |
| [GCP Cloud Run OTel] Service availability 99.5% rolling 30 days | Tracks the share of requests served by each Google Cloud Run service that did not end in an HTTP 5xx response (application errors, OOM kills, startup failures, 503 infrastructure errors and 504 request timeouts). Good events are request_count where attributes.response_code_class is not 5xx; total events are all request_count across every response class. 4xx client errors count as good. The objective is 99.5% of requests over a rolling 30-day window, measured per service in each GCP project and region. Limitation: run.googleapis.com/request_count only counts requests that reached a container instance. HTTP 429s from the Cloud Run load balancer when max-instances is exhausted, and requests rejected before routing, are not counted, so this SLO is optimistic during scale-out saturation. Watch the active instance count and per-instance concurrency for a plateau under rising load, which signals the max-instances ceiling. Metrics are polled every 5 minutes and GCP adds up to about 2 minutes of visibility delay, so recent minutes can arrive late. |

</details>



