#!/bin/sh
# Wait for otelcol to be ready, then emit telemetry via telemetrygen.
# Data flows: telemetrygen -> otelcol -> Kafka -> Agent.
# Uses initial_offset: earliest so the Agent reads from the start of topics after telemetrygen produces data.

set -e
echo "Waiting for otelcol OTLP endpoint..."
sleep 10
echo "Sending telemetry..."

# Sending logs, metrics and traces. However, only logs are asserted in the system test.
telemetrygen logs \
  --otlp-insecure \
  --otlp-endpoint otelcol:4317 \
  --logs 20 \
  --otlp-attributes='service.name="telemetrygen"' \
  && telemetrygen metrics \
  --otlp-insecure \
  --otlp-endpoint otelcol:4317 \
  --metrics 20 \
  --otlp-attributes='service.name="telemetrygen"' \
  && exec telemetrygen traces \
  --otlp-insecure \
  --otlp-endpoint otelcol:4317 \
  --traces 20 \
  --otlp-attributes='service.name="telemetrygen"'
