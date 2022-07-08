# Elastic Package Registry

This integration collects metrics from Elastic Package Registry (EPR).
There is one data stream:

- metrics: Telemetry data from the /metrics API.

## Compatibility

This integration requires EPR >= 1.10.0.

## Metrics

Elastic Package Registry can provide Prometheus metrics in the `/metrics` endpoint.
You can verify that metrics are enabled by making an HTTP request to:
`http://localhost:9000/metrics` on your package registry instance.

{{ fields "metrics" }}
