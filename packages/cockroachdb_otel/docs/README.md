# CockroachDB OpenTelemetry Assets

CockroachDB is a distributed SQL database that provides serializable ACID transactions, horizontal scalability, and survivability across failures. It exposes a PostgreSQL-compatible wire protocol and stores data in a distributed, sorted key-value map.

The CockroachDB OpenTelemetry assets provide dashboards, alert rules, and SLO templates for cluster availability, storage engine health, KV layer performance, SQL execution, and node capacity. Metrics are collected by the OpenTelemetry Collector `prometheusreceiver` scraping CockroachDB's Prometheus-compatible metrics endpoint.

## Compatibility

The CockroachDB OpenTelemetry assets have been tested with:

- OpenTelemetry Collector Contrib `prometheusreceiver` v0.146.0
- Elastic Distribution of OpenTelemetry (EDOT) Collector v9.2.1

CockroachDB tested against:

- CockroachDB v24.3

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Setup

### Prerequisites

CockroachDB exposes a Prometheus-compatible metrics endpoint on each node by default. No additional service-side configuration is required. The metrics are available at `http://<host>:<port>/_status/vars` or `http://<host>:<port>/metrics`. The default HTTP port is 8080 (configurable via `--http-addr`).

### Configuration

Install and configure the upstream OpenTelemetry Collector or Elastic Distribution of OpenTelemetry (EDOT) Collector to scrape CockroachDB metrics and export them to Elasticsearch. Replace the following placeholders in the configuration:

- `<COCKROACHDB_HOST>` — Hostname or IP of the CockroachDB node (for example `localhost` or `cockroachdb-node.example.com`)
- `<COCKROACHDB_PORT>` — Port of the metrics endpoint (default `8080`)
- `<ES_ENDPOINT>` — Elasticsearch endpoint (for example, `https://elasticsearch.example.com:9200`)
- `ES_API_KEY` — Elasticsearch API key (environment variable; the YAML uses `${env:ES_API_KEY}`)

```yaml
receivers:
  prometheus/cockroachdb:
    config:
      scrape_configs:
        - job_name: cockroachdb
          metrics_path: /_status/vars
          scrape_interval: 15s
          static_configs:
            - targets: ['<COCKROACHDB_HOST>:<COCKROACHDB_PORT>']

exporters:
  elasticsearch/otel:
    endpoint: <ES_ENDPOINT>
    api_key: ${env:ES_API_KEY}
    mapping:
      mode: otel

service:
  pipelines:
    metrics:
      receivers: [prometheus/cockroachdb]
      exporters: [elasticsearch/otel]
```

> **Note**: For multi-node clusters, add each node to the `targets` array, for example: `['node1:8080', 'node2:8080', 'node3:8080']`. The dashboards and alerts filter by `resource.attributes.service.instance.id`, which the prometheusreceiver derives from the scrape target address.

## Reference

### Metrics

Refer to the [prometheusreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/prometheusreceiver/README.md) documentation and [CockroachDB's Prometheus endpoint](https://www.cockroachlabs.com/docs/stable/prometheus-endpoint) for details on available metrics. CockroachDB exposes thousands of metrics covering the storage engine (Pebble), KV layer (Raft, ranges, admission control), SQL layer, transactions, and system resources.

## Dashboards

| Dashboard | Description |
|-----------|-------------|
| **[CockroachDB OTel] Cluster Overview** | Critical cluster health: availability, replication status, liveness, and node-level summary metrics. |
| **[CockroachDB OTel] Storage Engine** | Pebble storage engine health: L0 files, write stalls, write amplification, disk capacity, and compaction metrics. |
| **[CockroachDB OTel] KV Layer** | KV layer health: Raft processing, admission control saturation, RPC latency, clock skew, and intent resolution. |
| **[CockroachDB OTel] SQL Layer** | SQL performance: query throughput, error rate, transaction commits/aborts, contention, and connection count. |
| **[CockroachDB OTel] Node Capacity** | Node resource utilization: CPU, memory, Go GC pressure, file descriptors, and goroutine count. |

## Alert rules

| Alert | Trigger | Severity |
|-------|---------|----------|
| **[CockroachDB OTel] Unavailable ranges** | One or more ranges lack Raft quorum and cannot serve reads or writes | Critical |
| **[CockroachDB OTel] Storage write stalls** | Pebble write stalls detected; all writes to the store are blocked | Critical |
| **[CockroachDB OTel] Scrape target down** | Metrics scrape target unreachable; node may be down | Critical |
| **[CockroachDB OTel] Replica circuit breaker tripped** | One or more replicas stopped serving to avoid hanging | Critical |
| **[CockroachDB OTel] Under-replicated ranges** | Ranges below replication factor; cluster vulnerable to further failures | High |
| **[CockroachDB OTel] Liveness heartbeat failures** | Node liveness heartbeat failures detected; node may be losing liveness | High |
| **[CockroachDB OTel] Clock skew high** | Mean clock offset exceeds 400 ms; may cause transaction restarts | High |
| **[CockroachDB OTel] Disk capacity low** | Store capacity available below 10% | High |
| **[CockroachDB OTel] SQL error rate high** | SQL execution error rate exceeds 5% | High |
| **[CockroachDB OTel] Memory utilisation high** | Process RSS exceeds 85% of host memory | Medium |
| **[CockroachDB OTel] CPU utilisation high** | CPU usage exceeds 85% | Medium |
| **[CockroachDB OTel] Admission control slots exhausted** | KV admission slots at or above 95% utilisation | Medium |
| **[CockroachDB OTel] L0 sublevels high (pre-stall)** | L0 sublevels exceed 20; early warning before write stalls | Medium |
| **[CockroachDB OTel] Raft log behind** | Raft log entries behind exceed 1000; replication lag | Medium |

## SLO templates

| SLO | Target | Window | Description |
|-----|--------|--------|-------------|
| **[CockroachDB OTel] Unavailable ranges 99.5% rolling 30 days** | 99.5% | 30-day rolling | Cluster availability: 99.5% of 1-minute intervals have zero unavailable ranges. |
| **[CockroachDB OTel] Under-replicated ranges 99.5% rolling 30 days** | 99.5% | 30-day rolling | Replication health: 99.5% of 1-minute intervals have zero under-replicated ranges. |
| **[CockroachDB OTel] Write stalls 99.5% rolling 30 days** | 99.5% | 30-day rolling | Storage engine health: 99.5% of 1-minute intervals have zero new write stalls. |
| **[CockroachDB OTel] SQL execution success rate 99.5% rolling 30 days** | 99.5% | 30-day rolling | SQL reliability: 99.5% of statement executions complete successfully. |
