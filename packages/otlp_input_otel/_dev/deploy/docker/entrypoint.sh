#!/bin/sh
# Wait for SIGHUP from elastic-package (agent ready) before sending metrics.
# See: service_notify_signal in system test config.
ready=0
trap 'ready=1' HUP
while [ "$ready" -eq 0 ]; do sleep 0.5; done
exec telemetrygen metrics \
  --otlp-insecure \
  --otlp-endpoint elastic-agent:4317 \
  --metrics 10 \
  --otlp-attributes='service.name="telemetrygen"'
