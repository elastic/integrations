{{- generatedHeader }}
# Kafka OpenTelemetry Input Package

## Overview

The Kafka OpenTelemetry Input Package enables consumption of telemetry data (logs, metrics, and traces) from Apache Kafka using the [Kafka receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/kafkareceiver) from the OpenTelemetry Collector Contrib project.

This receiver is designed to consume OTLP-formatted telemetry data that has been published to Kafka topics, making it useful for pipeline architectures where Kafka serves as an intermediary buffer for observability data.

## How it works

This package configures the Kafka receiver in the EDOT (Elastic Distribution of OpenTelemetry) collector, which:

1. Connects to one or more Kafka brokers
2. Subscribes to configured topics for each signal type (logs, metrics, traces)
3. Consumes and decodes messages using the specified encoding format
4. Forwards the telemetry data to Elastic Agent for processing and indexing in Elasticsearch

## Configuration

### Core Settings

| Setting | Description | Default |
|---------|-------------|---------|
| Brokers | List of Kafka broker addresses | `localhost:9092` |
| Consumer Group ID | Consumer group for message consumption | `otel-collector` |

### Signal-Specific Settings

Each signal type (logs, metrics, traces) can be configured independently:

| Setting | Description | Default |
|---------|-------------|---------|
| Topics | Kafka topics to consume from | Signal-specific defaults |
| Encoding | Message encoding format | `otlp_proto` |
| Exclude Topics | Regex patterns to exclude topics | None |

**Default Topics:**
- Logs: `otlp_logs`
- Metrics: `otlp_metrics`
- Traces: `otlp_spans`

### Supported Encodings

**All signals:** `otlp_proto`, `otlp_json`

**Traces only:** `jaeger_proto`, `jaeger_json`, `zipkin_proto`, `zipkin_json`, `zipkin_thrift`

**Logs only:** `raw`, `text`, `json`, `azure_resource_logs`

### Authentication

The receiver supports multiple authentication methods:

- **SASL:** PLAIN, SCRAM-SHA-256, SCRAM-SHA-512, AWS MSK IAM
- **Kerberos:** Username/password or keytab-based authentication
- **TLS:** Client certificate authentication with optional CA verification

### Advanced Settings

For the full list of available settings, refer to the upstream [Kafka receiver documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/kafkareceiver).

## Troubleshooting

### Connection Issues

1. Verify that the broker addresses are correct and reachable
2. Check that the Kafka cluster is running and accepting connections
3. Ensure network connectivity between the collector and Kafka brokers

### Authentication Failures

1. Verify SASL credentials are correct
2. For Kerberos, ensure the keytab or credentials are valid
3. For TLS, verify certificate paths and that certificates are not expired

### Message Decoding Errors

1. Ensure the encoding setting matches the actual message format
2. Verify that producers are sending correctly formatted messages
3. Check Kafka topic configuration for compatibility

### Consumer Group Issues

1. Ensure the consumer group ID is unique if running multiple collectors
2. Check for consumer group rebalancing issues in Kafka logs
3. Verify that the initial offset setting matches your requirements

## System testing (development)

System tests use a telemetrygen + OTel Collector setup to produce OTLP data into Kafka, which the Elastic Agent's Kafka receiver then consumes.

### Architecture

```
telemetrygen  -->  otelcol (OTLP recv + Kafka exporter)  -->  Kafka  -->  Elastic Agent (Kafka receiver)  -->  Elasticsearch
```

- **telemetrygen**: Emits logs, metrics, and traces via OTLP gRPC. Uses the [telemetrygen](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/cmd/telemetrygen) tool from opentelemetry-collector-contrib.
- **otelcol**: OpenTelemetry Collector Contrib with OTLP receiver and Kafka exporter. Receives from telemetrygen and writes to Kafka topics `otlp_logs`, `otlp_metrics`, `otlp_spans`.
- **Kafka**: Broker (KRaft mode) that buffers telemetry before the Agent consumes it.
- **Elastic Agent**: Runs the Kafka input (Kafka receiver). Test config uses `initial_offset: earliest` so the Agent reads from the start of topics after telemetrygen has produced data.

### Running system tests

```bash
elastic-package stack up -d
cd packages/kafka_input_otel
elastic-package test system
```

Deployment files are in `_dev/deploy/docker/`: `docker-compose.yml` (orchestrates otelcol, telemetrygen, and Kafka), `otelcol/config.yml`, `telemetrygen/` (Dockerfile, entrypoint.sh), and `kraft/` (Kafka in KRaft mode). Telemetrygen is built locally when the ghcr.io image is unavailable.

## Further Reading

- [Kafka Receiver Documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/kafkareceiver)
- [OpenTelemetry Collector Documentation](https://opentelemetry.io/docs/collector/)
- [Apache Kafka Documentation](https://kafka.apache.org/documentation/)
