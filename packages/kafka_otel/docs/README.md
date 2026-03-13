# Kafka OpenTelemetry Assets

Apache Kafka is a distributed event streaming platform used for building real-time data pipelines and streaming applications. This content pack provides dashboards, alert rules, and SLO templates that use metrics from the OpenTelemetry Collector `kafkametricsreceiver` to monitor broker availability, replication health, consumer lag, and consumer group membership.

## Compatibility

The Kafka OpenTelemetry assets have been tested with OpenTelemetry Kafka Metrics receiver v0.145.0.

Apache Kafka tested against:

- Apache Kafka 2.8.x, 3.x

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Setup

### Prerequisites

The [`kafkametricsreceiver`](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/kafkametricsreceiver/documentation.md) scrapes Kafka cluster metadata over the native Kafka protocol. Ensure your OpenTelemetry Collector can reach at least one Kafka broker. No service-side configuration is required; Kafka exposes the required metadata by default.

### Configuration

Configure the OpenTelemetry Collector (or Elastic Observability Data Collection Agent with the Kafka receiver) to collect Kafka metrics and export them to Elasticsearch. The `elasticsearch/otel` exporter with `mapping.mode: otel` ensures metrics are stored in the `metrics-kafkametricsreceiver.otel-*` data stream used by the content pack.

Placeholders used in the configuration:

| Placeholder | Description | Example |
|-------------|-------------|---------|
| `<KAFKA_BROKERS>` | Kafka broker address; for clusters, add multiple list items under `brokers` | `localhost:9092` |
| `<ES_ENDPOINT>` | Elasticsearch endpoint URL | `https://my-deployment.es.us-central1.gcp.cloud.es.io:443` |
| `<ES_API_KEY>` | Elasticsearch API key for authentication | Use `env:ES_API_KEY` and set the variable in your environment |

```yaml
receivers:
  kafkametrics:
    brokers:
      - "<KAFKA_BROKERS>"
    protocol_version: "2.8.0"
    collection_interval: 10s
    initial_delay: 1s
    scrapers:
      - brokers
      - topics
      - consumers

processors:
  batch:
    timeout: 10s
    send_batch_size: 1000

  memory_limiter:
    check_interval: 1s
    limit_mib: 512
    spike_limit_mib: 128

exporters:
  elasticsearch/otel:
    endpoints: ["<ES_ENDPOINT>"]
    api_key: "${env:ES_API_KEY}"
    mapping:
      mode: otel
    metrics_dynamic_index:
      enabled: true

service:
  pipelines:
    metrics:
      receivers: [kafkametrics]
      processors: [memory_limiter, batch]
      exporters: [elasticsearch/otel]
```

> **Note**: If you run multiple collectors against different Kafka clusters, set `resource.attributes.service.instance.id` via the `resource` processor so dashboards and alerts can filter by instance.

## Reference

### Metrics

Refer to the [documentation.md](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/kafkametricsreceiver/documentation.md) of the OpenTelemetry Kafka Metrics receiver for details on available metrics.


## Dashboards

| Dashboard | Description |
|-----------|-------------|
| **[Kafka OTel] Overview** | Broker count, replication health, consumer group summary, and topic topology. |
| **[Kafka OTel] Consumer Groups** | Detailed consumer lag, offset tracking, per-partition lag breakdown, and consumer group membership. |
| **[Kafka OTel] Topics & Partitions** | Topic and partition metrics including partition counts, offsets, and retained message volume. |
| **[Kafka OTel] Replication Health** | Partition replication status, under-replicated partitions, and replica sync status. |

## Alert rules

| Alert | Trigger | Severity |
|-------|---------|----------|
| **[Kafka OTel] Broker count dropped** | Broker count falls below expected threshold (default 2) for an instance. | Critical |
| **[Kafka OTel] Under-replicated partitions** | One or more partitions have replicas out of sync with the leader. | Critical |
| **[Kafka OTel] Consumer group has zero members** | A consumer group has no active members and consumption has halted. | High |
| **[Kafka OTel] High consumer group lag sum** | Lag sum for a group-topic exceeds threshold (default 50,000 messages). | High |
| **[Kafka OTel] High per-partition lag** | Per-partition lag exceeds threshold (default 10,000 messages) for any group-topic-partition. | Medium |

## SLO templates

| SLO | Target | Window | Budgeting | Description |
|-----|--------|--------|-----------|-------------|
| **[Kafka OTel] Replication health 99.5% rolling 30 days** | 99.5% | 30-day rolling | Timeslices (1m) | Tracks that partition replicas remain fully in sync. A timeslice is good when the ratio of in-sync replicas to total replicas is 100% across all partitions. Under-replicated partitions indicate broker failures, network issues, or overload. |
| **[Kafka OTel] Consumer lag below threshold 99.5% rolling 30 days** | 99.5% | 30-day rolling | Timeslices (1m) | Tracks that the maximum aggregate consumer lag (`kafka.consumer_group.lag_sum`) stays below 50,000 messages per consumer-group-topic. Sustained lag growth indicates consumers falling behind producers and increases end-to-end processing delay. Threshold should be tuned per workload. |
| **[Kafka OTel] Consumer group availability 99.5% rolling 30 days** | 99.5% | 30-day rolling | Occurrences | Tracks that all monitored consumer groups have at least one active member. Groups with zero members are offline and not consuming. Uses a good/total document count approach — good events are documents where `kafka.consumer_group.members >= 1`. |


