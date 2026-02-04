# Jaeger OpenTelemetry Input Package

## Overview
The Jaeger OpenTelemetry Input Package for Elastic enables collection of trace data in [Jaeger](https://www.jaegertracing.io/) format through OpenTelemetry protocols using the [jaegerreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/jaegerreceiver).

### How it works
This package receives trace data from Jaeger clients and agents by configuring the Jaeger receiver in the Input Package, which then gets applied to the jaegerreceiver present in the Elastic Distribution of OpenTelemetry (EDOT) collector, which then forwards the data to Elastic Agent. The Elastic Agent processes and enriches the data before sending it to Elasticsearch for indexing and analysis.

### Supported protocols
The Jaeger receiver supports four protocols; at least one must be enabled. Each supports an optional `endpoint` configuration:

| Protocol | Default endpoint | Configurable in package |
|----------|------------------|-------------------------|
| **gRPC** | localhost:14250 | Enable/disable, endpoint |
| **Thrift HTTP** | localhost:14268 | Enable/disable, endpoint |
| **Thrift Binary UDP** | localhost:6832 | Enable/disable, endpoint, queue_size, max_packet_size, workers, socket_buffer_size |
| **Thrift Compact UDP** | localhost:6831 | Enable/disable, endpoint, queue_size, max_packet_size, workers, socket_buffer_size |

UDP protocols (Thrift Binary and Thrift Compact) support additional server options:

- **queue_size** (default 1000) – max not yet handled requests
- **max_packet_size** (default 65,000) – max UDP packet size in bytes
- **workers** (default 10) – number of workers consuming the queue
- **socket_buffer_size** (default 0) – buffer size of the connection socket in bytes (0 = no buffer)

gRPC is enabled by default. Enable Thrift protocols and adjust UDP options in the integration policy or via Fleet.

## Traces reference
For protocol options, TLS, and advanced configuration, refer to the [Jaeger Receiver README](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/jaegerreceiver/README.md) in the upstream OpenTelemetry Collector Contrib repository.
