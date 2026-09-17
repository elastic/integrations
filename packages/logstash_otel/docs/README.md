# Logstash OpenTelemetry Assets

## Overview

This package contains dashboards that visualize metrics exported from Logstash via the OpenTelemetry Protocol (OTLP).

Logstash metrics should be sent to the **Managed OTLP endpoint** provided by Elastic Cloud. This endpoint receives OTLP data, applies the managed ingest pipeline to normalise the metrics, and routes them into the `metrics-logstash.otel-*` data stream where these dashboards can read them.

Logstash can push metrics directly to the Managed OTLP endpoint using its built-in OpenTelemetry metrics exporter. This integration makes those metrics visible in Kibana without requiring an Elastic Agent or Beats collector.

## What metrics are included?

Logstash exports the following metric groups via OTLP:

- **Global metrics** — total events in, out, filtered, and processing duration across all pipelines; total queue depth; cumulative pipeline reload successes and failures
- **Pipeline metrics** — per-pipeline events in, out, filtered, duration, and queue push duration; pipeline configuration (workers, batch size, batch delay, queue type); current batch byte size and event count
- **Persistent queue metrics** — queue capacity, page capacity, max size, max unread events, current size, and free disk space (when `queue.type: persisted`)
- **Dead letter queue metrics** — DLQ size, max size, dropped events, and expired events
- **Plugin metrics** — per-plugin events in, out, processing duration, and queue push duration; codec encode/decode writes and duration
- **JVM metrics** — heap and non-heap memory usage, garbage collection count and time (by generation), thread count, process CPU usage and total time, uptime, and file descriptors
- **cgroup metrics** — CPU usage, CFS period and quota, and throttle statistics when running in Linux containers

All metrics carry resource attributes including `service.name`, `service.version`, `service.instance.id`, `host.name`, `logstash.http.address`, and `data_stream.dataset`.

## Dashboards

This package includes six dashboards linked together via a navigation panel.

### [Logstash Metrics OTel] Logstash Overview

Top-level fleet view across all Logstash nodes. Shows node count, total JVM heap used, events received and emitted per second, and average event latency.

### [Logstash Metrics OTel] Nodes Overview

Summary datatable of all nodes with columns for CPU usage, JVM heap %, events received and emitted, reload successes and failures, and Logstash version. Useful for comparing health across multiple instances at a glance.

### [Logstash Metrics OTel] Single Node Overview

High-level view of a single node. Shows events received and emitted per second, JVM heap usage (MB), process CPU utilization, events latency, HTTP address, version, reload counts, uptime, and a drillable list of running pipelines.

### [Logstash Metrics OTel] Single Node Advanced View

Deep-dive into a single node. Includes a node summary table (host name, HTTP address, version, events, reloads, uptime), process CPU utilization, persistent queue utilization and size, file descriptors (open, peak, max), Java thread count, and cgroup CFS and CPU performance panels (Linux containers with CFS quota only).

### [Logstash Metrics OTel] Pipelines Overview

Cross-node pipelines view filtered by node. Shows per-pipeline event throughput (received and emitted per second), average processing time per event, persistent queue utilization and size, and batch event count and byte size.

### [Logstash Metrics OTel] Single Pipeline View

Per-pipeline deep-dive. Shows event rates, persistent queue utilization, batch stats, worker utilization, and per-plugin breakdown (inputs, filters, outputs) of events received and emitted per second and average processing time.

## Prerequisites

Logstash 9.5.0 or later configured to send metrics to the Elastic Cloud Managed OTLP endpoint.

Add the following to `logstash.yml`:

```yaml
otel.metrics.enabled: true
otel.exporter.otlp.endpoint: "https://your-managed-otlp-endpoint.elastic.cloud"
otel.exporter.otlp.protocol: "grpc"
otel.exporter.otlp.headers: "Authorization=ApiKey your-base64-encoded-api-key"
```

Metrics will land in the `metrics-logstash.otel-default` Elasticsearch data stream.

## How it works

Logstash pushes metrics on a configurable interval (default 10 seconds) directly to the OTLP endpoint. The dashboards in this package read from the `metrics-logstash.otel-*` data view and visualize pipeline throughput, queue health, plugin performance, and resource usage.
