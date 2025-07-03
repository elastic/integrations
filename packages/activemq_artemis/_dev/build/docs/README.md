# ActiveMQ Artemis Integration

## Overview

Apache [ActiveMQ Artemis](https://activemq.apache.org/components/artemis/) is a high-performance, asynchronous messaging system that provides excellent throughput and features for the next generation of messaging applications. It is the next generation message broker from Apache ActiveMQ with a completely different architecture and codebase. ActiveMQ Artemis is a full-featured, enterprise-grade messaging platform that supports multiple protocols (AMQP, MQTT, OpenWire, STOMP) and provides clustering, high availability, and management capabilities.

Use the ActiveMQ Artemis integration to:

- Collect metrics related to brokers, queues, addresses, acceptors, and cluster configurations.
- Create visualizations to monitor, measure and analyze the usage trend and key data, and derive business insights.
- Create alerts to reduce the MTTD and also the MTTR by referencing relevant metrics when troubleshooting an issue.

## Data streams

The ActiveMQ Artemis integration collects metrics data.

Metrics give you insight into the statistics of the ActiveMQ Artemis. The `Metric` data streams collected by the ActiveMQ Artemis integration are `acceptor`, `address`, `broker`, `cluster`, and `queue` so that the user can monitor and troubleshoot the performance of the ActiveMQ Artemis instance.

Data streams:
- `acceptor`: Collects information related to the network acceptors configuration and connection statistics.
- `address`: Collects information related to the address statistics including message routing and delivery.
- `broker`: Collects information related to the broker statistics including memory usage, message processing, and connection management.
- `cluster`: Collects information related to the cluster configuration and node statistics.
- `queue`: Collects information related to the queue statistics including message counts, consumer information, and processing rates.

Note:
- Users can monitor and see the metrics inside the ingested documents for ActiveMQ Artemis in the `metrics-*` index pattern from `Discover`.

## Compatibility

This integration has been tested against ActiveMQ Artemis 2.28.0 (independent from the operating system).

## Prerequisites

You need Elasticsearch to store and search your data and Kibana to visualize and manage it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended or self-manage the Elastic Stack on your hardware.

## Setup

For step-by-step instructions on how to set up an integration, see the [Getting Started](https://www.elastic.co/guide/en/starting-with-the-elasticsearch-platform-and-its-solutions/current/getting-started-observability.html) guide.

## Validation

After the integration is successfully configured, clicking on the Assets tab of the ActiveMQ Artemis Integration should display a list of available dashboards. Click on the dashboard available for your configured data stream. It should be populated with the required data.

## Troubleshooting

If `host.ip` is shown conflicted under `metrics-*` data view, then this issue can be solved by [reindexing](https://www.elastic.co/guide/en/elasticsearch/reference/current/tsds-reindex.html) the `Acceptor`, `Address`, `Broker`, `Cluster`, and `Queue` data stream's indices.

## Metrics

### Acceptor Metrics

Acceptors are responsible for accepting client connections and managing the network protocols. Metrics provide insights into connection statistics, protocol usage, and network performance.

{{event "acceptor"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "acceptor"}}

### Address Metrics

Addresses in ActiveMQ Artemis represent destinations for messages. Metrics provide insights into message routing, delivery statistics, and address-specific performance data.

{{event "address"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "address"}}

### Broker Metrics

The broker is the core messaging engine of ActiveMQ Artemis. Metrics provide insights into broker-wide statistics such as memory usage, message processing rates, connection management, and overall system performance.

{{event "broker"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "broker"}}

### Cluster Metrics

Cluster metrics provide insights into the distributed messaging configuration and node-to-node communication statistics when ActiveMQ Artemis is deployed in a clustered environment.

{{event "cluster"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "cluster"}}

### Queue Metrics

Queues are FIFO (first-in, first-out) pipelines of messages produced and consumed by brokers and clients. Metrics show statistics of exchanged messages, consumers, producers, and queue-specific performance data.

{{event "queue"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "queue"}}