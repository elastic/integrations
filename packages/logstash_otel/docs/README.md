# Logstash OpenTelemetry Metrics

## Overview

This package contains dashboards that visualize metrics exported from Logstash via the OpenTelemetry Protocol (OTLP).

Logstash can push metrics directly to any OTLP-compatible backend — including Elastic — using its built-in OpenTelemetry metrics exporter. This integration makes those metrics visible in Kibana without requiring an Elastic Agent or Beats collector.

## What metrics are included?

Logstash exports the following metric groups via OTLP:

- **Global metrics** — total events in, out, filtered, and processing duration across all pipelines; total queue depth
- **Pipeline metrics** — per-pipeline events in, out, filtered, duration, and queue push duration; pipeline configuration (workers, batch size, batch delay, queue type); current batch byte size and event count
- **Persistent queue metrics** — queue capacity, page capacity, max size, max unread events, current size, and free disk space (when `queue.type: persisted`)
- **Dead letter queue metrics** — DLQ size, max size, dropped events, and expired events
- **Plugin metrics** — per-plugin events in, out, processing duration, and queue push duration; codec encode/decode writes and duration
- **JVM metrics** — heap and non-heap memory usage, garbage collection count and time (by generation), thread count, process CPU usage and total time, uptime, and file descriptors
- **cgroup metrics** — CPU usage, CFS period and quota, and throttle statistics when running in Linux containers

All metrics carry resource attributes including `service.name`, `service.instance.id`, `host.name`, and `data_stream.dataset`.

## Prerequisites

Logstash 9.5.0 or later configured to send metrics to Elastic via OTLP.

Add the following to `logstash.yml`:

```yaml
otel.metrics.enabled: true
otel.exporter.otlp.endpoint: "https://your-deployment.apm.us-central1.gcp.cloud.es.io:443"
otel.exporter.otlp.protocol: "grpc"
otel.exporter.otlp.headers: "Authorization=ApiKey your-base64-encoded-api-key"
```

Metrics will land in the `metrics-logstash.otel-default` Elasticsearch data stream.

## How it works

Logstash pushes metrics on a configurable interval (default 10 seconds) directly to the OTLP endpoint. The dashboards in this package read from the `metrics-logstash.otel-*` data view and visualize pipeline throughput, queue health, plugin performance, and resource usage.
