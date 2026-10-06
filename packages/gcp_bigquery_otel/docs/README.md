# GCP BigQuery OpenTelemetry Assets

This package contains Kibana assets for monitoring [BigQuery](https://cloud.google.com/bigquery) with Google Cloud Monitoring metrics collected by the OpenTelemetry Collector.

The package is **content only**. It does not configure data collection. Use the **[Google Cloud Monitoring (OpenTelemetry)](https://www.elastic.co/docs/reference/integrations/googlecloudmonitor_input_otel)** input package (`googlecloudmonitor_input_otel`) to collect BigQuery metrics into Elasticsearch.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage
the Elastic Stack on your own hardware.

## Setup

Install the **[Google Cloud Monitoring OpenTelemetry Input](https://www.elastic.co/docs/reference/integrations/googlecloudmonitor_input_otel)** package (`googlecloudmonitor_input_otel`) and configure it to collect BigQuery Cloud Monitoring metrics (for example, `bigquery.googleapis.com/query/count`). This content package provides assets that visualize data collected by that input.

When configuring the input package, set the dataset name to `gcp.bigquery.otel` so that data is written to the `metrics-gcp.bigquery.otel-default` data stream, which these dashboards query.

## Dashboards

| Dashboard | Description |
|-----------|-------------|
| **[GCP OTel] BigQuery** | Workload health across BigQuery projects. Covers slot capacity and saturation, query demand, query cost, ingestion, and storage. |
