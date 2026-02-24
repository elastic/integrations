# Jaeger OpenTelemetry Input Package

## Overview
The Jaeger OpenTelemetry Input Package for Elastic enables collection of trace data in [Jaeger](https://www.jaegertracing.io/) format over **gRPC** using the [jaegerreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/jaegerreceiver).

**Requirements:** Kibana 9.4.0 or later (traces support), Elastic Agent with Elastic Distribution of OpenTelemetry (EDOT).

### How it works
This package receives trace data from Jaeger clients and agents by configuring the Jaeger gRPC receiver in the Input Package, which then gets applied to the jaegerreceiver present in the Elastic Distribution of OpenTelemetry (EDOT) collector, which then forwards the data to Elastic Agent. The Elastic Agent processes and enriches the data before sending it to Elasticsearch for indexing and analysis.

### Protocols
Traces are received over gRPC (required) and optionally Thrift HTTP.

| Setting       | Default          | Description                    |
|---------------|------------------|--------------------------------|
| **gRPC endpoint** | localhost:14250 | Listen address for Jaeger gRPC |
| **Thrift HTTP endpoint** | — | Optional. When set, enables Thrift HTTP (e.g. localhost:14268) for Jaeger agent compatibility |
| **Enable TLS** | false | Use TLS for secure gRPC connections |
| **TLS Certificate File** | — | Path to server certificate |
| **TLS Key File** | — | Path to server private key |
| **TLS Client CA File** | — | Path to CA for client verification (mTLS) |

For protocol options, TLS/mTLS advanced configuration, and UDP protocols (thrift), refer to the [Jaeger Receiver README](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/jaegerreceiver/README.md) in the upstream OpenTelemetry Collector Contrib repository.
