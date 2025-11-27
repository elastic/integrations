# Docker Container Stats (OpenTelemetry)

This integration collects Docker container metrics using the OpenTelemetry Collector's [dockerstats receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/dockerstatsreceiver).

## Overview

Docker Container Stats are collected via the `docker_stats` receiver. It collects container metrics from the Docker daemon using the Docker Stats API. It provides comprehensive metrics about container resource usage including CPU, memory, network, and block I/O statistics.

## Requirements

- Docker API version 1.25 or higher
- Access to the Docker daemon socket (default: `unix:///var/run/docker.sock` on linux and `npipe:////./pipe/docker_engine` on Windows)

## Compatibility

This integration uses the OpenTelemetry dockerstats receiver which is currently in **alpha** stability. The configuration and metrics may change between versions.

## Metrics

This integration collects the following types of metrics:

### CPU Metrics

- Total CPU usage (nanoseconds)
- Kernel mode CPU usage (nanoseconds)
- User mode CPU usage (nanoseconds)
- CPU limit

### Memory Metrics

- Memory usage (bytes)
- Memory limit (bytes)
- Memory cache (bytes)
- Memory RSS (bytes)

### Network Metrics

- Bytes received/transmitted
- Packets received/transmitted
- Receive/transmit errors
- Receive/transmit dropped packets

### Block I/O Metrics

- Bytes read/written
- Read/write operations

### Metadata

- Container ID
- Container name
- Image name
- Container runtime

## Advanced Configuration

### Docker Endpoint

The endpoint of the Docker daemon. Default is `unix:///var/run/docker.sock`.

For remote Docker hosts, you can use TCP endpoints like `tcp://docker-host:2375`.

### Excluded Images

A list of container image names to exclude from metrics collection. Supports wildcards.

Example:
```
- "nginx:*"
- "redis:latest"
```

### API Version

The Docker API version to use. Default is `1.25` (the minimum supported version).

### Per-Core CPU Metrics

When enabled, provides CPU metrics broken down by individual CPU cores. Default is `false`.

**Note:** Enabling this option can significantly increase the number of metrics collected.

### Container Labels to Metric Labels

Map container labels to metric resource attributes. This allows you to add custom dimensions to your metrics based on container labels.

Example YAML format:
```yaml
my.container.label: my_metric_label
app.version: version
```

### Environment Variables to Metric Labels

Map container environment variables to metric resource attributes.

Example YAML format:
```yaml
MY_ENV_VAR: my_metric_label
APP_VERSION: version
```

## Additional Resources

- [OpenTelemetry dockerstats receiver documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/dockerstatsreceiver)
- [Docker Stats API documentation](https://docs.docker.com/engine/api/v1.43/#tag/Container/operation/ContainerStats)
- [Elastic Observability documentation](https://www.elastic.co/guide/en/observability/current/index.html)
