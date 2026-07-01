{{- generatedHeader }}
# Defend for Containers (OpenTelemetry)

## Overview

The Defend for Containers (OpenTelemetry) input package enables Elastic Agent to receive Defend for Containers telemetry using the [OpenTelemetry Protocol (OTLP)](https://opentelemetry.io/docs/specs/otlp/) over gRPC and HTTP. The data is delivered as OTLP logs and routed into an Elasticsearch dataset.

The package uses the upstream [OTLP Receiver](https://github.com/open-telemetry/opentelemetry-collector/tree/main/receiver/otlpreceiver) from the OpenTelemetry Collector.

## How it works

This package configures the OTLP receiver in the EDOT (Elastic Distribution of OpenTelemetry) Collector managed by Elastic Agent. Data flows as follows:

1. An OTLP-compatible source sends logs to the receiver over gRPC or HTTP.
2. The EDOT Collector inside Elastic Agent receives and processes the telemetry.
3. Elastic Agent forwards the data to Elasticsearch for indexing and analysis.

The receiver listens on two endpoints:

- **gRPC** on `localhost:4317` (default)
- **HTTP** on `localhost:4318` (default)

## Configuration

| Setting | Description | Default |
|---------|-------------|---------|
| gRPC Endpoint | Address and port to listen on for OTLP gRPC connections | `localhost:4317` |
| HTTP Endpoint | Address and port to listen on for OTLP HTTP connections | `localhost:4318` |
| Data Stream Dataset | Dataset to write data to | `cloud_defend.logs` |

Each configured instance of this input writes to a single dataset, selected with the `Data Stream Dataset` variable. To route Defend for Containers telemetry into both supported datasets — `cloud_defend.logs` and `cloud_defend.file` — configure two instances of the input, one per dataset.

For the complete list of receiver settings, refer to the [OTLP Receiver documentation](https://github.com/open-telemetry/opentelemetry-collector/tree/main/receiver/otlpreceiver).

## Reference

### Inputs used
{{ inputDocs }}

### Further reading

- [OTLP Receiver Documentation](https://github.com/open-telemetry/opentelemetry-collector/tree/main/receiver/otlpreceiver)
- [OpenTelemetry Collector Documentation](https://opentelemetry.io/docs/collector/)
