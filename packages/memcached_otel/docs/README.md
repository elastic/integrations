# Memcached metrics from OpenTelemetry Collector

The Memcached OTel integration collects metrics from [Memcached](https://memcached.org/) servers using the OpenTelemetry Collector's [Memcached Receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/memcachedreceiver).

Use the Memcached OTel integration to visualize cache performance, memory utilization, and operational health of your Memcached instances. The dashboard displays metrics collected via the `stats` command by the OpenTelemetry Collector.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

1. **Compatibility**: This integration is compatible with systems running the upstream OpenTelemetry Collector Contrib distribution with the Memcached receiver enabled.

2. **Permissions required**: The collector requires network access to the Memcached server's TCP port (default: 11211).

3. **Kibana version**: Version 9.2 or later is required (dashboards use ES|QL TS command).

## Setup

1. Install and configure the EDOT Collector or upstream OpenTelemetry Collector Contrib to export metrics to Elasticsearch:

```yaml
receivers:
  memcached:
    endpoint: localhost:11211
    collection_interval: 60s
exporters:
  debug:
    verbosity: detailed
  elasticsearch/otel:
    endpoint: https://localhost:9200
    user: <userid>
    password: <password>
    mapping:
      mode: otel
    metrics_dynamic_index:
      enabled: true

service:
  pipelines:
    metrics:
      receivers: [memcached]
      exporters: [debug, elasticsearch/otel]
```

2. Use this configuration to run the collector.

## Metrics reference

### Memcached metrics

All metrics are enabled by default.

| Metric | Type | Unit | Description | Attributes |
|--------|------|------|-------------|------------|
| `memcached.bytes` | Gauge | `By` | Current bytes used to store items | - |
| `memcached.commands` | Sum | `{commands}` | Commands processed | `command` |
| `memcached.connections.current` | Sum | `{connections}` | Active open connections | - |
| `memcached.connections.total` | Sum | `{connections}` | Total connections opened since server start | - |
| `memcached.cpu.usage` | Sum | `s` | Accumulated CPU processing time | `state` |
| `memcached.current_items` | Sum | `{items}` | Items currently stored in the cache | - |
| `memcached.evictions` | Sum | `{evictions}` | Cache item evictions | - |
| `memcached.network` | Sum | `By` | Data transferred across network | `direction` |
| `memcached.operation_hit_ratio` | Gauge | `%` | Hit ratio (0.0 to 100.0) for operations | `operation` |
| `memcached.operations` | Sum | `{operations}` | Request outcomes | `type`, `operation` |
| `memcached.threads` | Sum | `{threads}` | Threads used by the memcached instance | - |

### Metric Attributes

| Attribute | Values | Description |
|-----------|--------|-------------|
| `command` | `get`, `set`, `flush`, `touch` | Command type |
| `state` | `system`, `user` | CPU usage state |
| `direction` | `sent`, `received` | Network direction |
| `operation` | `increment`, `decrement`, `get` | Operation type |
| `type` | `hit`, `miss` | Request outcome type |

### Resource Attributes

| Attribute | Description |
|-----------|-------------|
| `host.name` | Memcached host name |

For a complete list of all available metrics and their detailed descriptions, refer to the [Memcached Receiver documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/memcachedreceiver/documentation.md) in the upstream OpenTelemetry Collector repository.
