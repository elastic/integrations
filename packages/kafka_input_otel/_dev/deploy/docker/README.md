# Docker scenario

System tests use a custom Go generator + OTel Collector setup to produce OTLP data into Kafka, which the Elastic Agent's Kafka receiver then consumes.

## Architecture

```
generator  -->  otelcol (OTLP recv + Kafka exporter)  -->  Kafka  -->  Elastic Agent (Kafka receiver)  -->  Elasticsearch
```

- **generator**: Custom Go binary (under `generator/`) that sends 1000 logs, metrics, and traces in parallel via OTLP gRPC. Polls the otelcol health endpoint (`otelcol:13133`) and starts sending once it responds healthy. Modelled on the `otlp_input_otel` generator but without the SIGHUP mechanism (which cannot be used here as the signal would target the Kafka broker container, not the generator).
- **otelcol**: OpenTelemetry Collector Contrib with OTLP receiver and dual Kafka exporter. Receives from the generator and writes to six Kafka topics: `otlp_logs`, `otlp_metrics`, `otlp_spans` (`otlp_proto` encoding) and `otlp_logs_json`, `otlp_metrics_json`, `otlp_spans_json` (`otlp_json` encoding).
- **Kafka**: Broker (KRaft mode) that buffers telemetry before the Agent consumes it.
- **Elastic Agent**: Runs the Kafka input (Kafka receiver). Test configs use `initial_offset: earliest` so the Agent reads from the start of topics after the generator has produced data.
