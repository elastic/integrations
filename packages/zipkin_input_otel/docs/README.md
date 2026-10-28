# Zipkin OpenTelemetry Input Package

## Overview
The Zipkin OpenTelemetry Input Package for Elastic enables collection of trace data from applications instrumented with [Zipkin](https://zipkin.io/) through OpenTelemetry protocols using the [zipkinreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/zipkinreceiver#zipkin-receiver).

### How it works
This package receives Zipkin trace data (V1 and V2 JSON/Protobuf formats) by configuring the Zipkin receiver in the Input Package, which then gets applied to the zipkinreceiver present in the EDOT collector, which then forwards the data to Elastic Agent. The Elastic Agent processes and enriches the data before sending it to Elasticsearch for indexing and analysis.

## Configuration

For the full list of settings exposed for the receiver and examples, refer to the [Zipkin Receiver documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/zipkinreceiver).

## Troubleshooting

If you encounter issues:

1. Verify the endpoint is accessible and not blocked by a firewall.
2. Ensure applications are sending Zipkin-formatted traces to the configured endpoint (default: `http://<host>:9411`).
3. Check the Elastic Agent logs for any receiver errors.

## Traces reference
For more details about the Zipkin receiver and its configuration options, refer to the [Zipkin Receiver documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/zipkinreceiver) in the upstream OpenTelemetry Collector repository.
