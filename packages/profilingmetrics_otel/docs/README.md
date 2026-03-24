# Profilingmetrics OpenTelemetry Assets

Profilingmetrics OpenTelemetry Assets must be used with OpenTelemetry profiling data.

## Requirements

You need to run EDOT with the [profiling](https://www.elastic.co/docs/reference/edot-collector/config/configure-profiles-collection) receiver configured.

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.

## Setup

Use the [profilingmetricsconnector](https://www.elastic.co/docs/reference/edot-collector/config/configure-profiles-collection#generate-metrics-from-profiles) to generate metrics from OpenTelemetry profiling data.