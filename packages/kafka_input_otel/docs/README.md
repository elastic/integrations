# Kafka OpenTelemetry Input Package

## Overview

The Kafka OpenTelemetry Input Package enables collection of OTLP-encoded logs, metrics, and traces from Kafka-compatible brokers — including Azure Event Hub — using the [kafkareceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/kafkareceiver).

### How it works

This package configures the OpenTelemetry kafkareceiver in the EDOT (Elastic Distribution of OpenTelemetry) collector to consume messages from Kafka topics. Each signal type (logs, metrics, traces) reads from its own topic, allowing you to selectively enable only the signals you need.

Data flow:

```
Producers (OTel SDK/Collector) → Kafka / Event Hub → kafkareceiver → Elastic Agent → Elasticsearch
```

Messages must be encoded in OTLP format (`otlp_json` or `otlp_proto`). Producers typically use an OTel Collector with a [kafkaexporter](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/exporter/kafkaexporter) to write OTLP-encoded messages to the broker.

## Requirements

- Elastic Agent with EDOT collector (kafkareceiver is a Core component since v0.148.0)
- A Kafka-compatible broker (Apache Kafka 1.0+ or Azure Event Hub)
- OTLP-encoded messages on the Kafka topics (`otlp_json` or `otlp_proto`)

### Encoding limitation

EDOT's kafkareceiver only supports `otlp_json` and `otlp_proto` encodings. Other encodings (raw, json, avro) are not available. This means producers must encode messages in OTLP format before publishing to the broker.

## Azure Event Hub Setup

Azure Event Hub exposes a Kafka-compatible endpoint. To use this package with Event Hub:

1. **Create an Event Hubs namespace** with the Kafka protocol enabled (Standard or Premium tier).

2. **Create Event Hubs** (one per signal type you want to collect):
   - e.g. `otlp-logs`, `otlp-metrics`, `otlp-traces`

3. **Get the connection string** from the Event Hubs namespace → Shared access policies → your policy → Connection string–primary key.

4. **Configure the package:**
   - **Broker Address:** `<namespace>.servicebus.windows.net:9093`
   - **SASL Mechanism:** `PLAIN`
   - **SASL Username:** `$ConnectionString`
   - **SASL Password:** the full connection string from step 3
   - **TLS:** enabled (required)
   - **Kafka Protocol Version:** `2.1.0` (maximum supported by Event Hub)

5. **Consumer groups:** Event Hub provides a built-in `$Default` consumer group. Create additional consumer groups in the Azure portal if needed.

### Kafka concept mapping

| Kafka | Event Hub |
|-------|-----------|
| Cluster | Namespace |
| Topic | Event Hub |
| Partition | Partition |
| Consumer Group | Consumer Group |
| Offset | Offset |

## Plain Kafka Setup

For standard Apache Kafka clusters:

1. **Configure the package:**
   - **Broker Address:** `<broker-host>:<port>` (e.g. `kafka-broker:9092`)
   - **SASL Mechanism:** `PLAIN`, `SCRAM-SHA-256`, or `SCRAM-SHA-512`
   - **SASL Username/Password:** your Kafka credentials
   - **TLS:** enable if your cluster requires it
   - **Kafka Protocol Version:** match your Kafka cluster version

2. **Topics:** provide the topic names where OTLP-encoded messages are published.

## Configuration

### Signal Topics

Each signal type is optional. Enable a signal by providing its topic name:

| Setting | Description |
|---------|-------------|
| **Logs Topic** | Topic for OTLP log messages |
| **Metrics Topic** | Topic for OTLP metric messages |
| **Traces Topic** | Topic for OTLP trace messages |

At least one topic must be provided.

### Consumer Groups

A default consumer group applies to all signals. You can override per signal type:

| Setting | Default | Description |
|---------|---------|-------------|
| **Consumer Group** | `$Default` | Default for all signal types |
| **Logs Consumer Group Override** | — | Override for logs topic |
| **Metrics Consumer Group Override** | — | Override for metrics topic |
| **Traces Consumer Group Override** | — | Override for traces topic |

## Reference

- [kafkareceiver documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/kafkareceiver)
- [kafkaexporter documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/exporter/kafkaexporter)
- [EDOT Collector components](https://github.com/elastic/elastic-agent/blob/main/docs/reference/edot-collector/components.md)
- [Azure Event Hub Kafka endpoint](https://learn.microsoft.com/en-us/azure/event-hubs/azure-event-hubs-kafka-overview)
