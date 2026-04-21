# Apache CouchDB OpenTelemetry Assets

Apache CouchDB is an open-source NoSQL document database that exposes a RESTful HTTP API for all operations. This content pack provides dashboards, alert rules, and SLO templates for CouchDB metrics collected using the OpenTelemetry CouchDB receiver, covering latency, traffic, errors, and saturation.

## Compatibility

The CouchDB OpenTelemetry assets have been tested with:

OpenTelemetry CouchDB receiver v0.145.0

- CouchDB 3.5.1

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Setup

### Prerequisites

The CouchDB receiver scrapes metrics from the `/_node/{node-name}/_stats/couchdb` endpoint. Ensure CouchDB is running and the collector host can reach it. Create a CouchDB user with read access to the stats endpoint, or use an existing admin account. No additional CouchDB configuration is required — the stats API is enabled by default.

### Configuration

Configure the OpenTelemetry Collector (or Elastic Distribution of OpenTelemetry Collector) to receive CouchDB metrics and export them to Elasticsearch. Use the following placeholders in the configuration:

- `<COUCHDB_ENDPOINT>` — CouchDB base URL (for example, `http://localhost:5984`).
- `<COUCHDB_USERNAME>` — CouchDB username for authentication.
- `<COUCHDB_PASSWORD>` — CouchDB password. Use `env:COUCHDB_PASSWORD` and set the variable in your environment.
- `<ES_ENDPOINT>` — Elasticsearch ingest endpoint (for example, `https://elasticsearch:9200`).
- `<ES_API_KEY>` — Elasticsearch API key for authentication. Prefer `env:ES_API_KEY` and set the variable in your environment.

```yaml
receivers:
  couchdb:
    endpoint: <COUCHDB_ENDPOINT>
    username: <COUCHDB_USERNAME>
    password: ${env:COUCHDB_PASSWORD}
    collection_interval: 10s

exporters:
  elasticsearch/otel:
    endpoints: [<ES_ENDPOINT>]
    api_key: ${env:ES_API_KEY}
    mapping:
      mode: otel

service:
  pipelines:
    metrics:
      receivers: [couchdb]
      exporters: [elasticsearch/otel]
```

## Reference

### Metrics

Refer to the [metadata.yaml](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/couchdbreceiver/metadata.yaml) of the OpenTelemetry CouchDB receiver for details on available metrics.

## Dashboards

| Dashboard | Description |
|-----------|-------------|
| **[CouchDB OTel] Overview** | Overview of Apache CouchDB health and performance: request latency, HTTP traffic, error rates, database operations, view reads, and resource saturation (file descriptors, open databases). |

## Alert rules

| Alert | Trigger | Severity |
|-------|---------|----------|
| **[CouchDB OTel] Conflict storm (elevated 409 responses)** | 409 response rate exceeds 10/s per node, indicating write contention on same documents. | Medium |
| **[CouchDB OTel] File descriptor exhaustion risk** | Open file descriptors exceed 1000 per node. | Critical |
| **[CouchDB OTel] High 5xx server error rate** | 5xx responses exceed 5% of total responses per node. | Critical |
| **[CouchDB OTel] High average request time (latency)** | Average request time exceeds 1000 ms per node. | High |
| **[CouchDB OTel] High error rate (4xx and 5xx)** | Error responses (4xx + 5xx) exceed 10% of total per node. | High |
| **[CouchDB OTel] Open databases count high** | Open databases exceed 100 per node. | Medium |

## SLO templates

> **Note**: SLO templates require Elastic Stack version 9.4.0 or later.

| SLO | Target | Window | Description |
|-----|--------|--------|-------------|
| **[CouchDB OTel] Average request latency 99.5% rolling 30 days** | 99.5% | 30-day rolling | Tracks that average request latency stays below 200 ms for 99.5% of 1-minute intervals. |
| **[CouchDB OTel] File descriptor headroom 99.5% rolling 30 days** | 99.5% | 30-day rolling | Tracks that open file descriptors stay below 1000 for 99.5% of 1-minute intervals. |
