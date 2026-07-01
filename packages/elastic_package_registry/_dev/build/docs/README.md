{{- generatedHeader }}
# Elastic Package Registry

## Overview

The Elastic Package Registry integration collects metrics from your [Elastic Package Registry](https://github.com/elastic/package-registry) service.

Use the data from this integration to monitor the status of your services — for example, how many packages are indexed, which versions your services are running, or whether there are too many requests with 404 or 500 status codes.

### Compatibility

This integration is compatible with Elastic Package Registry version 1.10.0 and later.

### How it works

The integration uses the [Prometheus input](https://www.elastic.co/docs/reference/integrations/prometheus_input) to collect metrics from the `/metrics` endpoint exposed by the Elastic Package Registry service.

## What data does this integration collect?

The Elastic Package Registry integration collects the following type of data:

- **Metrics**: Telemetry data from the `/metrics` endpoint that gives you insight into the state of the services. See [Metrics](#metrics) for details.

## What do I need to use this integration?

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the Elastic Package Registry metrics endpoint and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Set up steps in Elastic Package Registry

To enable telemetry in your Elastic Package Registry instance, set the metrics address parameter. Alternatively, set the `EPR_METRICS_ADDRESS` environment variable:

```bash
package-registry -metrics-address 0.0.0.0:9000

EPR_METRICS_ADDRESS="0.0.0.0:9000" package-registry
```

Remember to expose the port used in the above setting (for example, 9000) in your deployments: k8s, docker-compose, and so on.

### Set up steps in Kibana

For step-by-step instructions on how to set up an integration, see the
{{ url "getting-started-observability" "Getting started" }} guide.

### Validation

Verify that the metrics endpoint is enabled by making an HTTP request to `http://localhost:9000/metrics` on your package registry instance.

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Inputs used

This integration uses the `prometheus_input` package. The following input is used:

{{ inputDocs }}

### Data streams

#### Metrics

The `metrics` data stream provides Prometheus metrics from the `/metrics` endpoint of the Elastic Package Registry service.

##### Metrics fields

{{ fields "metrics" }}

##### Metrics sample event

{{ event "metrics" }}

{{ ilm }}

{{ transform }}
