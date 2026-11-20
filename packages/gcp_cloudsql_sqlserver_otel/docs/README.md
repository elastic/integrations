# GCP Cloud SQL for SQL Server OpenTelemetry Assets

This package contains Kibana assets for monitoring [Cloud SQL for SQL Server](https://cloud.google.com/sql/docs/sqlserver) instances with Google Cloud Monitoring metrics collected by the OpenTelemetry Collector.

The package is **content only**. It does not configure data collection. Use the **[Google Cloud Monitoring (OpenTelemetry)](https://www.elastic.co/docs/reference/integrations/googlecloudmonitor_input_otel)** input package (`googlecloudmonitor_input_otel`) to collect Cloud SQL for SQL Server metrics into Elasticsearch.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage
the Elastic Stack on your own hardware.

## Setup

Install the **[Google Cloud Monitoring OpenTelemetry Input](https://www.elastic.co/docs/reference/integrations/googlecloudmonitor_input_otel)** package (`googlecloudmonitor_input_otel`) and configure it to collect Cloud SQL for SQL Server Cloud Monitoring metrics (for example, `cloudsql.googleapis.com/database/cpu/utilization`). This content package provides assets that visualize data collected by that input.

When configuring the input package, set the dataset name to `gcp.cloudsql_sqlserver.otel` so that data is written to the `metrics-gcp.cloudsql_sqlserver.otel-default` data stream, which these dashboards query.

## Dashboards

| Dashboard | Description |
|-----------|-------------|
| **[GCP OTel] Cloud SQL - SQL Server Overview** | Fleet overview of Cloud SQL for SQL Server instances. Covers availability, CPU, memory and disk saturation, batch throughput, and blocking. |
| **[GCP OTel] Cloud SQL - SQL Server Instance Detail** | Detail view of a single Cloud SQL for SQL Server instance. Covers availability, capacity, traffic and errors, connections, locking and blocking, memory and I/O, and high availability and replication. |
