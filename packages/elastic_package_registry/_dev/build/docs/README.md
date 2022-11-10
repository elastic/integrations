# Elastic Package Registry

This Elastic Package Registry integration collects metrics from your [Elastic Package Registry](https://github.com/elastic/package-registry) service.

For example, you could use the data from this integration to know the status of your services. For instance, how many packages are indexed, what version
are running your services, or if there are too many requests with 404 or 500 code status.

## Data streams

The Elastic Package Registry collects one type of data stream: metrics.

- metrics: Telemetry data from the `/metrics` endpoint that give you insight into the state of the services.
  See more details in the [Metrics reference](#metrics-reference).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

This integration also requires Elastic Package Registry version >= 1.10.0.

## Setup

In order to enable this telemetry in your Elastic Package Registry instance, you must set the metrics
address parameter. Or, as an alternative, set the environment variable
`EPR_METRICS_ADDRESS`. As an example:

```bash
package-registry -metrics-address 0.0.0.0:9000

EPR_METRICS_ADDRESS="0.0.0.0:9000" package-regsitry
```

Remember to expose the port used in the above setting (e.g. 9000) in your deployments:
k8s, docker-compose, etc..

For step-by-step instructions on how to set up an integration, see the
{{ url "getting-started-observability" "Getting started" }} guide.

## Metrics reference

### Metrics

Elastic Package Registry can provide Prometheus metrics in the `/metrics` endpoint.
You can verify that metrics endpoint is enabled by making an HTTP request to
`http://localhost:9000/metrics` on your package registry instance.

{{ fields "metrics" }}

#### Example

{{ event "metrics" }}

