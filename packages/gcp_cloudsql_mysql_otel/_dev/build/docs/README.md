# GCP Cloud SQL MySQL OpenTelemetry Assets

This package contains Kibana assets for monitoring [Cloud SQL for MySQL](https://cloud.google.com/sql/docs/mysql) instances with Google Cloud Monitoring metrics collected by the OpenTelemetry Collector.

The package is **content only**. It does not configure data collection. Use the **[Google Cloud Monitoring (OpenTelemetry)](https://www.elastic.co/docs/reference/integrations/googlecloudmonitor_input_otel)** input package (`googlecloudmonitor_input_otel`) to collect Cloud SQL for MySQL metrics into Elasticsearch.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage
the Elastic Stack on your own hardware.

## Setup

Install the **[Google Cloud Monitoring OpenTelemetry Input](https://www.elastic.co/docs/reference/integrations/googlecloudmonitor_input_otel)** package (`googlecloudmonitor_input_otel`) and configure it to collect Cloud SQL for MySQL Cloud Monitoring metrics (for example, `cloudsql.googleapis.com/database/mysql/queries`). This content package provides assets that visualize data collected by that input.

When configuring the input package, set the dataset name to `gcp.cloudsql_mysql.otel` so that data is written to the `metrics-gcp.cloudsql_mysql.otel-default` data stream, which these dashboards query.

Shared Cloud SQL metrics such as CPU, memory and disk are also emitted for PostgreSQL and SQL Server instances. These dashboards keep only MySQL instances, using `cloudsql.googleapis.com/database/mysql/queries` as the marker.

## Dashboards

| Dashboard | Description |
|-----------|-------------|
| **[GCP OTel] Cloud SQL MySQL Overview** | Fleet view of Cloud SQL for MySQL instances. Availability, worst-first saturation, and trends for CPU, memory, statement throughput and connections. |
| **[GCP OTel] Cloud SQL MySQL Instance Detail** | One Cloud SQL for MySQL instance. CPU, memory, disk, connections, statement throughput and replication lag. Open it from the overview. |

## Alerting Rule Templates
{{alertRuleTemplates}}

## SLO Templates
{{sloTemplates}}
