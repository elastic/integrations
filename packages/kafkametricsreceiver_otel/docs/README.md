# Kafka Metrics from OpenTelemetry Collector

The Kafka Metrics OpenTelemetry Assets content package provides out-of-the-box dashboards for visualizing Kafka cluster health metrics collected via the [kafkametricsreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/kafkametricsreceiver).

Use this package to monitor your Kafka infrastructure including brokers, topics, partitions, and consumer groups. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference metrics when troubleshooting performance issues.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

1. **Compatibility**: This integration is compatible with systems running the upstream OpenTelemetry Collector or EDOT Collector with the kafkametricsreceiver component.

2. **Permissions**: The collector requires network access to your Kafka brokers. The Kafka user configured in the receiver must have permission to describe cluster, topics, and consumer groups.

3. **Kafka brokers**: You need one or more Kafka brokers accessible from the collector host.

## Setup

1. Install and configure the EDOT Collector or upstream Collector to export metrics to Elasticsearch:

```yaml
receivers:
  kafkametrics:
    brokers:
      - localhost:9092
    protocol_version: 2.0.0
    scrapers:
      - brokers
      - topics
      - consumers
    collection_interval: 30s

exporters:
  debug:
    verbosity: detailed
  elasticsearch/otel:
    endpoint: https://localhost:9200
    user: <userid>
    password: <password>
    mapping:
      mode: otel
    metrics_dynamic_index:
      enabled: true

service:
  pipelines:
    metrics:
      receivers: [kafkametrics]
      exporters: [debug, elasticsearch/otel]
```

2. Use this configuration to run the collector.

## Metrics reference

### Default Metrics

The kafkametricsreceiver collects the following metrics by default:

| Metric | Description |
|--------|-------------|
| `kafka.brokers` | Number of brokers in the cluster |
| `kafka.topic.partitions` | Number of partitions in topic |
| `kafka.partition.current_offset` | Current offset of partition of topic |
| `kafka.partition.oldest_offset` | Oldest offset of partition of topic |
| `kafka.partition.replicas` | Number of replicas for partition of topic |
| `kafka.partition.replicas_in_sync` | Number of synchronized replicas of partition |
| `kafka.consumer_group.lag` | Current approximate lag of consumer group at partition of topic |
| `kafka.consumer_group.lag_sum` | Current approximate sum of consumer group lag across all partitions |
| `kafka.consumer_group.members` | Count of members in the consumer group |
| `kafka.consumer_group.offset` | Current offset of the consumer group at partition of topic |
| `kafka.consumer_group.offset_sum` | Sum of consumer group offset across partitions of topic |

### Optional Metrics

The following metrics can be enabled by configuring the receiver:

| Metric | Description |
|--------|-------------|
| `kafka.broker.log_retention_period` | Log retention time of a broker |
| `kafka.topic.log_retention_period` | Log retention period of a topic |
| `kafka.topic.log_retention_size` | Log retention size of a topic in bytes |
| `kafka.topic.min_insync_replicas` | Minimum in-sync replicas of a topic |
| `kafka.topic.replication_factor` | Replication factor of a topic |

For a complete list of all available metrics and their detailed descriptions, refer to the [kafkametricsreceiver documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/kafkametricsreceiver/documentation.md) in the upstream OpenTelemetry Collector repository.
