# Envoy Proxy OpenTelemetry Assets

Envoy Proxy is a high-performance L3/L4/L7 network proxy for cloud-native applications, commonly deployed as an edge proxy, service mesh sidecar, or API gateway. This content pack provides Kibana dashboards, alert rules, and SLO templates for Envoy metrics ingested via the OpenTelemetry StatsD receiver, covering proxy health, downstream traffic and errors, upstream cluster status, memory, and TLS certificate expiry.

## Compatibility

The Envoy Proxy OpenTelemetry assets have been tested with OpenTelemetry StatsD receiver v0.146.0 or later.

Envoy tested against:

- Envoy 1.28, 1.29, 1.30

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Setup

### Prerequisites

Configure Envoy to emit StatsD metrics to the OpenTelemetry Collector. Add a StatsD stats sink to your Envoy bootstrap configuration and point it at the collector's StatsD receiver endpoint:

```yaml
stats_sinks:
  - name: envoy.stat_sinks.statsd
    typed_config:
      "@type": type.googleapis.com/envoy.config.metrics.v3.StatsdSink
      tcp_cluster_name: statsd_exporter
```

You must also ensure the cluster `statsd_exporter` (or your chosen name) resolves to the host and port where the OpenTelemetry Collector's StatsD receiver is listening (default UDP port 8125). Envoy emits metrics in StatsD format; the collector aggregates and exports them to Elasticsearch.

### Configuration

Configure the OpenTelemetry Collector or Elastic Distribution of OpenTelemetry Collector (EDOT) with the StatsD receiver and the Elasticsearch exporter. The following example shows a minimal pipeline.

Placeholders:

- `<ES_ENDPOINT>` — Your Elasticsearch endpoint (e.g. `https://my-deployment.es.us-central1.gcp.cloud.es.io:443`).
- `<ES_API_KEY>` — API key or credential for authenticating to Elasticsearch. Prefer `${env:ES_API_KEY}` and set the variable at runtime.

```yaml
receivers:
  statsd:
    endpoint: 0.0.0.0:8125
    aggregation_interval: 60s

exporters:
  elasticsearch/otel:
    endpoints:
      - <ES_ENDPOINT>
    api_key: <ES_API_KEY>
    mapping:
      mode: otel

service:
  pipelines:
    metrics:
      receivers:
        - statsd
      exporters:
        - elasticsearch/otel
```

> **Note**: Ensure the collector is reachable from Envoy on the configured StatsD port (8125 by default). If Envoy and the collector run on different hosts, configure the Envoy cluster for the StatsD sink to use the collector's host and port.

## Reference

### Metrics

The StatsD receiver ingests metrics that Envoy emits in StatsD format. Metric names follow Envoy's hierarchical naming (e.g. `envoy.cluster.<cluster_name>.upstream_cx_total`, `envoy.http.<stat_prefix>.downstream_rq_2xx`). Refer to the [StatsD receiver documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/statsdreceiver/README.md) for receiver configuration, and to [Envoy's statistics documentation](https://www.envoyproxy.io/docs/envoy/latest/configuration/observability/statistics/statistics) for metric semantics and naming.

## Dashboards

| Dashboard | Description |
|-----------|-------------|
| **[Envoy Proxy] Overview** | Proxy health, downstream traffic, and upstream status at a glance. |
| **[Envoy Proxy] Downstream & HTTP** | Downstream traffic, latency, HTTP metrics, and connection handling. |
| **[Envoy Proxy] Upstream & Proxy Health** | Server health, memory, listener manager, and cluster lifecycle. |

## Alert rules

| Alert | Trigger | Severity |
|-------|---------|----------|
| **[Envoy OTel] Server not live** | `server.live` is less than 1 over the evaluation window. | Critical |
| **[Envoy OTel] Server state not LIVE** | `server.state` is not 0 (LIVE) over the evaluation window. | Critical |
| **[Envoy OTel] High memory pressure** | Allocated memory exceeds 90% of heap size over the evaluation window. | High |
| **[Envoy OTel] Warming clusters stuck** | Warming clusters count remains greater than 0 for the evaluation window. | High |
| **[Envoy OTel] Listeners warming** | Listeners warming count remains greater than 0 for the evaluation window. | High |
| **[Envoy OTel] High downstream error rate** | Non-2xx response rate exceeds 5% for completed requests. | High |
| **[Envoy OTel] Certificate expiring soon** | First TLS certificate expires in fewer than 7 days. | Warning |

## SLO templates

> **Note**: SLO templates require Elastic Stack version 9.4.0 or later.

| SLO | Target | Window | Description |
|-----|--------|--------|-------------|
| **[Envoy OTel] Downstream request availability 99.5% rolling 30 days** | 99.5% | 30-day rolling | Proportion of downstream HTTP requests that complete with 2xx versus total completed requests. |
