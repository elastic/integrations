# Elastic Package Registry

This integration collects metrics from Elastic Package Registry (EPR).
There is one data stream:

- metrics: Telemetry data from the /metrics API.

In order to enable this telemetry in your EPR instance, you must set the metrics
address parameter. Or, as an alternative, set the environment variable
`EPR_METRICS_ADDRESS`. As an example:

```bash
package-registry -metrics-address 0.0.0.0:9000

export EPR_METRICS_ADDRESS="0.0.0.0:9000" ; package-regsitry
```

Remember to expose the port used in the above setting (e.g. 9000) in your deployments
(k8s, docker-compose, etc.).

## Compatibility

This integration requires EPR >= 1.10.0.

## Metrics

Elastic Package Registry can provide Prometheus metrics in the `/metrics` endpoint.
You can verify that metrics endpoint is enabled by making an HTTP request to:
`http://localhost:9000/metrics` on your package registry instance.

There are two different data streams to split the different metrics available:

### Elastic Package Registry (EPR)

Metrics related to the Elastic Package Registry application itself:

{{ fields "metrics" }}

### Go metrics

Metrics related to the Go processes:

{{ fields "gometrics" }}
