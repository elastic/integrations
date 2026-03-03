# GCP Custom Metrics

The GCP Custom Metrics input package can collect custom metrics for any GCP service.

A list of metrics and services that are available, can be found in the [GCP Cloud Monitoring API](https://cloud.google.com/monitoring/api/metrics_gcp) official documentation.

The `metrics` configuration should be configured as the `metrics` fields of the [GCP `metrics` metricset](https://www.elastic.co/guide/en/beats/metricbeat/current/metricbeat-metricset-gcp-metrics.html)

This package does not contain any ingest pipeline, so no pre-ingest data processing is applied out of the box. Custom ingest pipelines can be added through the Kibana UI, to get the data in the desired format.
