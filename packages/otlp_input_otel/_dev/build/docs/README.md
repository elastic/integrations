# OTLP Receiver OpenTelemetry Input Package

## Overview

The OTLP Receiver OpenTelemetry Input Package enables Elastic Agent to receive logs, metrics, and traces using the [OpenTelemetry Protocol (OTLP)](https://opentelemetry.io/docs/specs/otlp/) over gRPC and HTTP. This allows Elastic Agent to function as a managed OpenTelemetry Collector, accepting telemetry from any OTLP-compatible SDK or collector.

The package uses the upstream [OTLP Receiver](https://github.com/open-telemetry/opentelemetry-collector/tree/main/receiver/otlpreceiver) from the OpenTelemetry Collector.

## How it works

This package configures the OTLP receiver in the EDOT (Elastic Distribution of OpenTelemetry) Collector managed by Elastic Agent. The receiver listens for incoming OTLP data on two endpoints:

- **gRPC** on `localhost:4317` (default)
- **HTTP** on `localhost:4318` (default)

Incoming telemetry is processed and forwarded to Elasticsearch for indexing and analysis.

## Supported signal types

| Signal   | Default  | Description                                      |
|----------|----------|--------------------------------------------------|
| Logs     | Enabled  | Log records from applications and infrastructure |
| Metrics  | Enabled  | Metric data points and time series               |
| Traces   | Enabled  | Distributed traces and spans                     |

## Configuration

For a complete list of configurations refer to the [OTLP Receiver documentation](https://github.com/open-telemetry/opentelemetry-collector/tree/main/receiver/otlpreceiver).

### Receiving data from multiple hosts

The package adds host information with the [resource detection processor](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/resourcedetectionprocessor) and its `system` detector. By default, it only fills in host attributes, such as `host.name`, that the incoming data doesn't already carry. Attributes that OTLP clients send are kept. So when Elastic Agent receives data from applications on other hosts, each service appears under its own host in Kibana, not under the host that runs Elastic Agent.

To overwrite the attributes sent by clients with the host information of the Elastic Agent host, enable **Override resource attributes with Agent host information** (`resourcedetection_override`). Before version 0.3.0 of this package, this was the default behavior.

## Sample event

{{ event }}
