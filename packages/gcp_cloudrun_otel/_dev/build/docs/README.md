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
{{alertRuleTemplates}}

## SLO Templates
{{sloTemplates}}
