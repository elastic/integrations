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

## Alerting Rule Templates
Alert rule templates provide pre-defined configurations for creating alert rules in Kibana.

For more information, refer to the [Elastic documentation](https://www.elastic.co/docs/reference/fleet/alerting-rule-templates).

Alert rule templates require Elastic Stack version 9.6.0 or later.

**The following alert rule templates are available:**

<details>
<summary>View the alert rule templates</summary>

| Name | Description |
|---|---|
| \[GCP BigQuery OTel\] Batch job backlog not draining | Alerts when non-interactive BigQuery jobs (batch-priority queries and load, copy, or extract jobs) have been pending in at least 90 one-minute samples of the last 2 hours without the queue draining to zero once. Batch work is expected to wait, so this is a warning-level backlog rule. One alert per project, location, and job type. |
| \[GCP BigQuery OTel\] Query bytes billed spike | Alerts when a project's query bytes billed in the last full hour (ending 5 minutes ago) are at least 3 times the larger of its hourly average over the previous day and the same hour yesterday, and at least 1 TiB. Only evaluated when the recent hour, the previous day and the same hour yesterday are each well covered by published data, so collection gaps cannot cause false spikes. Uses the low-latency query/statement_scanned_bytes_billed metric. One alert per project. |
| \[GCP BigQuery OTel\] Interactive queries queueing | Alerts when interactive-priority query jobs are pending (queued) in at least 10 one-minute samples in the last 30 minutes for a project and location. Batch-priority queueing is excluded; see the batch backlog rule. One alert per project and location. |
| \[GCP BigQuery OTel\] Reservation slot saturation | Alerts when a BigQuery reservation's reserved slot usage is at or above 95% of its autoscale maximum (slots/max_assigned) for at least 15 one-minute samples in the last 30 minutes. One alert per reservation and location. On-demand projects report no reservation capacity and never match. |

</details>

