# IBM WebSphere Application Server OpenTelemetry Assets

IBM WebSphere Application Server (WAS) Traditional is a Java EE application server that hosts enterprise web applications, web services, and middleware.

These assets provide dashboards, alert rules, and SLO templates built on metrics collected by the OpenTelemetry Prometheus receiver from the WebSphere PMI metrics endpoint. They cover servlet performance, thread and connection pool health, JVM resource utilization, transaction processing, and session management.

## Compatibility

The IBM WebSphere Application Server OpenTelemetry assets have been tested with:

- OpenTelemetry Collector Prometheus receiver with EDOT Collector v9.2.1
- OpenTelemetry Collector Prometheus receiver with OpenTelemetry Collector Contrib v0.146.1

WebSphere Application Server tested against:

- WebSphere Application Server Traditional 9.0.5.x

The metrics are exposed by the WebSphere Performance Monitoring Infrastructure (PMI) using the bundled `metrics.ear` application at the `/metrics` endpoint.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage
the Elastic Stack on your own hardware.

## Setup

### Prerequisites

WebSphere Application Server must have the Performance Monitoring Infrastructure (PMI) metrics endpoint enabled. This is provided by the `metrics.ear` application bundled with WAS Traditional. To verify it is working, access the `/metrics` endpoint on your WebSphere server:

```bash
curl http://<WAS_HOST>:<WAS_PORT>/metrics
```

You should see Prometheus-formatted metrics output. If the endpoint is not available, deploy the `metrics.ear` application through the WebSphere administrative console and ensure PMI monitoring is enabled at the desired level.

### Configuration

You can use the [OpenTelemetry Collector](https://opentelemetry.io/docs/collector/) or the [EDOT Collector](https://www.elastic.co/docs/current/en/edot-collector/) to collect metrics from WebSphere Application Server.

Replace the following placeholders in the configuration below:

- `<WAS_HOST>` — The hostname or IP address of the WebSphere Application Server instance (for example, `websphere.example.com`)
- `<WAS_PORT>` — The port on which the `/metrics` endpoint is exposed (for example, `9080`)
- `<SCRAPE_INTERVAL>` — How frequently to scrape metrics (for example, `10s`)
- `<ES_ENDPOINT>` — Your Elasticsearch endpoint URL (for example, `https://my-deployment.es.us-east-1.aws.elastic.cloud:443`)
- `${env:ES_API_KEY}` — An Elasticsearch API key with write permissions, provided using the `ES_API_KEY` environment variable

```yaml
receivers:
  prometheus/websphere:
    config:
      scrape_configs:
        - job_name: "websphere"
          scrape_interval: <SCRAPE_INTERVAL>
          metrics_path: /metrics
          static_configs:
            - targets: ["<WAS_HOST>:<WAS_PORT>"]

exporters:
  elasticsearch/otel:
    endpoint: <ES_ENDPOINT>
    api_key: ${env:ES_API_KEY}
    mapping:
      mode: otel

service:
  pipelines:
    metrics:
      receivers: [prometheus/websphere]
      exporters: [elasticsearch/otel]
```

## Reference

### Metrics

The metrics collected from WebSphere Application Server are defined by the WebSphere Performance Monitoring Infrastructure (PMI). Refer to the [Prometheus receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/prometheusreceiver/README.md) documentation for details on the collector receiver configuration.

The PMI metrics endpoint exposes metrics covering servlets, thread pools, connection pools, sessions, transactions, JVM runtime, JAX-WS web services, dynamic caching, and more. All metrics are scraped as Prometheus metrics and land in the `metrics-websphere.otel-default` data stream.

## Dashboards

| Dashboard | Description |
|-----------|-------------|
| **[WebSphere OTel] Overview** | High-level view of WebSphere Application Server health covering servlet throughput, thread and connection pool saturation, JVM resource utilization, and transaction health. |
| **[WebSphere OTel] Servlet Performance** | Deep dive into servlet request processing: throughput, latency, errors, and per-URI breakdown across WebSphere applications. |
| **[WebSphere OTel] Resource Pools** | Thread pool and connection pool health monitoring including utilization, hung threads, waiting threads, faults, and pool sizing. |
| **[WebSphere OTel] JVM Health** | JVM runtime health including heap and non-heap memory, CPU utilization, thread counts, class loading, transactions, and session management. |

## Alert rules

| Alert | Trigger | Severity |
|-------|---------|----------|
| **[WebSphere OTel] WebContainer thread pool saturation** | WebContainer thread pool utilization exceeds 85% | Critical |
| **[WebSphere OTel] Hung threads detected** | Any hung threads detected across thread pools | Critical |
| **[WebSphere OTel] Session capacity exhausted** | New sessions are being rejected due to session limit | Critical |
| **[WebSphere OTel] Servlet error rate elevated** | Servlet error rate exceeds 5% of total requests | High |
| **[WebSphere OTel] Connection pool faults** | Connection pool timeout faults detected | High |
| **[WebSphere OTel] Transaction timeouts** | Transaction timeouts detected, indicating slow backends or deadlocks | High |
| **[WebSphere OTel] Connection pool high utilization** | Average connection pool utilization exceeds 85% | Warning |
| **[WebSphere OTel] JVM heap memory pressure** | JVM heap utilization exceeds 85% | Warning |

## SLO templates

> **Note**: SLO templates require Elastic Stack version 9.4.0 or later.

| SLO | Target | Window | Description |
|-----|--------|--------|-------------|
| **[WebSphere OTel] Average servlet response time 99.5% rolling 30 days** | 99.5% | 30-day rolling | Ensures 99.5% of 1-minute intervals have average per-request latency below 2 seconds over a rolling 30-day period. |
| **[WebSphere OTel] Servlet error rate 99.5% rolling 30 days** | 99.5% | 30-day rolling | Ensures 99.5% of 1-minute intervals have a servlet error rate below 1% over a rolling 30-day period. |
