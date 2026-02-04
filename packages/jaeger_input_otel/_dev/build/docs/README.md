# Jaeger OpenTelemetry Input Package

## Overview
The Jaeger OpenTelemetry Input Package for Elastic enables collection of trace data in [Jaeger](https://www.jaegertracing.io/) format over **gRPC** using the [jaegerreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/jaegerreceiver).

### How it works
This package receives trace data from Jaeger clients and agents by configuring the Jaeger gRPC receiver in the Input Package, which then gets applied to the jaegerreceiver present in the Elastic Distribution of OpenTelemetry (EDOT) collector, which then forwards the data to Elastic Agent. The Elastic Agent processes and enriches the data before sending it to Elasticsearch for indexing and analysis.

### gRPC protocol
Traces are received over the Jaeger gRPC protocol only.

| Setting       | Default          | Description                    |
|---------------|------------------|--------------------------------|
| **gRPC endpoint** | localhost:14250 | Listen address for Jaeger gRPC |

For protocol options, TLS, and advanced configuration, refer to the [Jaeger Receiver README](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/jaegerreceiver/README.md) in the upstream OpenTelemetry Collector Contrib repository.
