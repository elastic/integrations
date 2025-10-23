# Docker Stats (OpenTelemetry)

This integration collects Docker container metrics using the OpenTelemetry Collector's [dockerstats receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/dockerstatsreceiver).

## Overview

The Docker Stats receiver collects container metrics from the Docker daemon using the Docker Stats API. It provides comprehensive metrics about container resource usage including CPU, memory, network, and block I/O statistics.

## Requirements

- Docker API version 1.22 or higher
- Access to the Docker daemon socket (default: `unix:///var/run/docker.sock`)
- Not supported on Darwin/Windows platforms
- OpenTelemetry Collector integration enabled in your Elastic Agent

## Compatibility

This integration uses the OpenTelemetry dockerstats receiver which is currently in **alpha** stability. The configuration and metrics may change between versions.

## Configuration

### Collection Interval

How often to collect metrics from Docker containers. Default is `10s`.

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

### Timeout

Timeout for Docker API requests. Default is `5s`.

### API Version

The Docker API version to use. Default is `1.22` (the minimum supported version).

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

## Example Configuration

```yaml
receivers:
  dockerstats:
    collection_interval: 10s
    endpoint: unix:///var/run/docker.sock
    excluded_images:
      - "nginx:*"
    timeout: 5s
    api_version: "1.22"
    provide_per_core_cpu_metrics: false

service:
  pipelines:
    metrics:
      receivers:
        - dockerstats
```

## Troubleshooting

### Permission Denied

If you see "permission denied" errors, ensure the Elastic Agent has access to the Docker socket. You may need to add the agent user to the `docker` group:

```bash
sudo usermod -aG docker elastic-agent
```

### No Metrics Collected

- Verify Docker is running: `docker ps`
- Check the Docker endpoint configuration
- Ensure the API version is compatible with your Docker installation
- Review Elastic Agent logs for errors

### High Cardinality

If you're experiencing high cardinality issues:

- Disable per-core CPU metrics
- Use the `excluded_images` option to filter out noisy containers
- Be selective with container labels and environment variables mapped to metric labels

## Additional Resources

- [OpenTelemetry dockerstats receiver documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/dockerstatsreceiver)
- [Docker Stats API documentation](https://docs.docker.com/engine/api/v1.43/#tag/Container/operation/ContainerStats)
- [Elastic Observability documentation](https://www.elastic.co/guide/en/observability/current/index.html)
