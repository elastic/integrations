# Docker OpenTelemetry Input Package

## Overview

The Docker OpenTelemetry Input Package for Elastic enables collection of telemetry data from Docker containers through OpenTelemetry protocols using the [dockerstats receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/dockerstatsreceiver). It provides comprehensive metrics about container resource usage including CPU, memory, network, and block I/O statistics.

### How it works

This package receives telemetry data from the Docker daemon by configuring the Docker endpoint in the Input Package, which then gets applied to the `docker_stats` receiver present in the EDOT collector, which then forwards the data to Elastic Agent. The Elastic Agent processes and enriches the data before sending it to Elasticsearch for indexing and analysis. Once the data arrives into Elasticsearch, its corresponding [Docker OpenTelemetry Assets Package](https://www.elastic.co/docs/reference/integrations/docker_otel) gets auto installed and the dashboards light up.

## Requirements

- Access to the Docker daemon socket (default: `unix:///var/run/docker.sock` on Linux and `npipe:////./pipe/docker_engine` on Windows)
- Docker API version greater than or equal to the one defined in [Docker Stats Receiver Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/dockerstatsreceiver). Also, the API version must be supported by the Docker Engine being monitored.

## Compatibility

This integration uses the OpenTelemetry dockerstats receiver which is currently in **alpha** stability. The configuration and metrics may change between versions.

## Setup

For step-by-step instructions on how to set up an integration, see the {{ url "getting-started-observability" "Getting started" }} guide.

## Configuration

The following configuration options are available:

### Docker Endpoint
The endpoint of the Docker daemon. If not specified, the receiver uses `unix:///var/run/docker.sock` on Linux.
For remote Docker hosts, you can use TCP endpoints like `tcp://docker-host:2375`.

### Excluded Images
A list of container image names to exclude from metrics collection. Supports wildcards.
Example:
```yaml
- "nginx:*"
- "redis:latest"
```

### API Version
The Docker API version to use. Default is `"1.44"`.
Note that for Docker Engine v29, API version `"1.44"` or higher must be used.

### Initial Delay
Defines how long this receiver waits before starting. Default is `1s`.

### Container Labels to Metric Labels
Map container labels to metric resource attributes. This allows you to add custom dimensions to your metrics based on container labels.
Example:
```yaml
my.container.label: my_metric_label
app.version: version
```

### Environment Variables to Metric Labels
Map container environment variables to metric resource attributes.
Example:
```yaml
MY_ENV_VAR: my_metric_label
APP_VERSION: version
```


### Metrics

For a complete list of all available metrics, including their types, descriptions, and default enabled status, refer to the [Docker Stats Receiver documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/dockerstatsreceiver/documentation.md) in the upstream OpenTelemetry Collector repository.

The `metrics` configuration allows you to enable optional metrics or disable default metrics.

For example, to enable per-CPU usage metrics (which are disabled by default):

```yaml
metrics:
  container.cpu.usage.percpu:
    enabled: true
```


## Additional Resources

- [OpenTelemetry dockerstats receiver documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/dockerstatsreceiver)
- [Docker Stats API documentation](https://docs.docker.com/engine/api/v1.43/#tag/Container/operation/ContainerStats)
- [Elastic Observability documentation](https://www.elastic.co/guide/en/observability/current/index.html)
