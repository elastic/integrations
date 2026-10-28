# InfluxDB OpenTelemetry Assets

InfluxDB is an open-source time series database built for high-write-throughput workloads such as infrastructure monitoring, application metrics, IoT sensor data, and real-time analytics. These assets provide dashboards, alert rules, and SLO templates for monitoring InfluxDB instances using OpenTelemetry metrics, covering the HTTP API, storage engine, query controller, task scheduler, and Go runtime.

## Compatibility

The InfluxDB OpenTelemetry assets have been tested with InfluxDB 2.x and OpenTelemetry Collector v0.145.0, using metrics scraped from InfluxDB instances exposing Prometheus-format metrics at `/metrics`.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Setup

### Prerequisites

InfluxDB 2.x exposes Prometheus-format metrics at `/metrics` by default. Ensure the metrics endpoint is reachable from your OpenTelemetry Collector (or Elastic Agent with the Prometheus input). No additional service-side configuration is required.

### Configuration

Configure your OpenTelemetry Collector or Elastic Agent to scrape InfluxDB metrics and export them to Elasticsearch with `mapping.mode: otel`. The following example uses the Prometheus receiver to scrape InfluxDB's `/metrics` endpoint:

| Placeholder | Description | Example |
|-------------|-------------|---------|
| `<INFLUXDB_HOST>` | Hostname or IP of the InfluxDB instance | `localhost` |
| `<INFLUXDB_METRICS_PORT>` | Port where InfluxDB exposes metrics (default 8086 for HTTP) | `8086` |
| `<ES_ENDPOINT>` | Elasticsearch endpoint for the `elasticsearch` exporter | `https://your-deployment.es.us-central1.gcp.cloud.es.io:443` |
| `<ES_API_KEY>` | API key or credentials for Elasticsearch | `${env:ES_API_KEY}` |

```yaml
receivers:
  prometheus/influxdb:
    config:
      scrape_configs:
        - job_name: influxdb
          metrics_path: /metrics
          static_configs:
            - targets: ["<INFLUXDB_HOST>:<INFLUXDB_METRICS_PORT>"]
processors:

  cumulativetodelta: 

  resource:
    attributes:
      - key: data_stream.dataset
        value: influxdb
        action: upsert

exporters:
  elasticsearch/otel:
    endpoints: ["<ES_ENDPOINT>"]
    api_key: "<ES_API_KEY>"
    mapping:
      mode: otel

service:
  pipelines:
    metrics/influxdb:
      receivers: [prometheus/influxdb]
      processors: [resource, cumulativetodelta]
      exporters: [elasticsearch/otel]
```

> **Note**: Ensure the scrape target matches the InfluxDB instance(s) you want to monitor. For multiple instances, add additional targets or use service discovery.

## Reference

### Metrics

Refer to the [InfluxDB internals metrics documentation](https://docs.influxdata.com/influxdb/v2.7/reference/internals/metrics/) for details on the metrics exposed at `/metrics`. The Prometheus receiver scrapes these metrics and the Elasticsearch exporter maps them to the `metrics-influxdb.otel-*` index pattern used by the dashboards, alert rules, and SLO templates.

## Dashboards

| Dashboard | Description |
|-----------|-------------|
| **[InfluxDB OTel] Overview** | High-level overview of InfluxDB health: instance capacity, HTTP traffic, query controller load, storage health, and Go runtime. |
| **[InfluxDB OTel] HTTP & Storage** | HTTP API traffic, write/query throughput, storage health (WAL, cache, compaction), and writer metrics. |
| **[InfluxDB OTel] Query & Tasks** | Query controller load, memory budget, stage durations, task scheduler execution, and task executor saturation. |

## Alert rules

| Alert | Trigger | Severity |
|-------|---------|----------|
| **[InfluxDB OTel] Scrape target down** | Scrape target unreachable (up=0) for the evaluation window | Critical |
| **[InfluxDB OTel] WAL write errors** | WAL write error counter increased during the evaluation window | Critical |
| **[InfluxDB OTel] Shard write errors** | Shard write error counter increased during the evaluation window | Critical |
| **[InfluxDB OTel] Cache write errors** | Cache write error counter increased during the evaluation window | Critical |
| **[InfluxDB OTel] Dropped writes** | Shard or cache dropped writes increased during the evaluation window | Critical |
| **[InfluxDB OTel] Storage writer timeouts** | Storage writer timeout counter increased during the evaluation window | High |
| **[InfluxDB OTel] HTTP API high error rate** | HTTP API non-2XX error rate exceeds 5% over the evaluation window | High |
| **[InfluxDB OTel] Query controller saturated** | Query queueing high (>=5) or query controller memory budget exhausted (<10MB) | High |
| **[InfluxDB OTel] Task execution failures** | Task execution failure counter increased during the evaluation window | Medium |
| **[InfluxDB OTel] Compaction queue backlog** | Compaction queue depth exceeds 10 | Medium |
| **[InfluxDB OTel] Go goroutine leak suspected** | Goroutine count exceeds 10000 | Warning |

## SLO templates

> **Note**: SLO templates require Elastic Stack version 9.4.0 or later.

| SLO | Target | Window | Description |
|-----|--------|--------|-------------|
| **[InfluxDB OTel] HTTP API request latency 99.5% rolling 30 days** | 99.5% | 30-day rolling | Proportion of HTTP API requests completing within 200 ms. |
| **[InfluxDB OTel] Query controller execution latency 99.5% rolling 30 days** | 99.5% | 30-day rolling | Proportion of Flux query executions completing within 5 seconds. |
