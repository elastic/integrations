# Elastic Package Registry

This integration collects metrics from [Elastic Package Registry](https://github.com/elastic/package-registry).
There is one data stream:

- metrics: Telemetry data from the `/metrics` endpoint.

In order to enable this telemetry in your Elastic Package Registry instance, you must set the metrics
address parameter. Or, as an alternative, set the environment variable
`EPR_METRICS_ADDRESS`. As an example:

```bash
package-registry -metrics-address 0.0.0.0:9000

EPR_METRICS_ADDRESS="0.0.0.0:9000" package-regsitry
```

Remember to expose the port used in the above setting (e.g. 9000) in your deployments:
k8s, docker-compose, etc..

## Compatibility

This integration requires Elastic Package Registry version >= 1.10.0.

## Metrics

Elastic Package Registry can provide Prometheus metrics in the `/metrics` endpoint.
You can verify that metrics endpoint is enabled by making an HTTP request to
`http://localhost:9000/metrics` on your package registry instance.


### Elastic Package Registry metrics

{{ fields "metrics" }}

{{ event "metrics" }}
