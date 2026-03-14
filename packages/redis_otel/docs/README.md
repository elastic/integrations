# Redis metrics from OpenTelemetry Collector

The Redis metrics from Redis OTel integration allows you to monitor [Redis](https://redis.io/), a high-performance in-memory data store used as a database, cache, message broker, and streaming engine.

Use the Redis OTel integration to analyze performance metrics from your Redis instances. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference metrics when troubleshooting performance issues.

For example, if you want to monitor memory usage, client connections, or command throughput of your Redis server, you can use the [Redis Receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/redisreceiver) to collect metrics such as `redis.memory.used`, `redis.clients.connected`, or `redis.commands`, and then the Redis OTel integration to visualize these metrics in Kibana dashboards, set up alerts for high memory usage, or troubleshoot by analyzing metric trends.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

1. **Compatibility and supported versions**: This integration is compatible with systems running either [EDOT Collector](https://www.elastic.co/docs/reference/opentelemetry/quickstart/) or vanilla upstream Collector and Redis server. This integration has been tested with OTEL collector version [v0.129.0](https://github.com/open-telemetry/opentelemetry-collector/tree/v0.129.0), EDOT collector version [9.0](https://www.elastic.co/docs/reference/opentelemetry/compatibility/collectors), and Redis version 7.x.

2. **Permissions required**: The collector requires access to the Redis server endpoint. When running the collector, make sure you have the appropriate permissions to connect to Redis.

3. **Redis configuration**: Redis must be accessible on the configured endpoint. For password-protected instances, provide the appropriate credentials in the collector configuration.

## Setup

1. Ensure your Redis server is running and accessible.

2. Install and configure the EDOT Collector or upstream Collector to export metrics to Elasticsearch, as shown in the following example:

```yaml
receivers:
  redis:
    endpoint: "localhost:6379"
    collection_interval: 10s
processors:
  resourcedetection:
    detectors: ["system", "ec2"]
exporters:
  debug:
    verbosity: detailed
  elasticsearch/otel:
    endpoints: https://localhost:9200
    user: <userid>
    password: <pwd>
    mapping:
      mode: otel
    metrics_dynamic_index:
      enabled: true
service:
  pipelines:
    metrics:
      receivers: [redis]
      processors: [resourcedetection]
      exporters: [debug, elasticsearch/otel]
```

Use this configuration to run the collector.

The `resourcedetection` processor is required to get the host information for the dashboard.

## Metrics reference

### Redis metrics

The [Redis receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/redisreceiver/documentation.md) collects performance metrics from Redis. Key metrics include:

| Metric Name | Description | Type | Attributes |
|-------------|-------------|------|------------|
| `redis.clients.blocked` | Clients pending on a blocking call | Sum | - |
| `redis.clients.connected` | Client connections (excluding replicas) | Sum | - |
| `redis.clients.max_input_buffer` | Largest input buffer among connections | Gauge | - |
| `redis.clients.max_output_buffer` | Longest output list among connections | Gauge | - |
| `redis.commands` | Processed commands per second | Gauge | - |
| `redis.commands.processed` | Total server commands executed | Sum | - |
| `redis.connections.received` | Total accepted connections | Sum | - |
| `redis.connections.rejected` | Connections denied due to maxclients | Sum | - |
| `redis.cpu.time` | CPU consumed since server start | Sum | `state` |
| `redis.db.avg_ttl` | Average keyspace keys TTL | Gauge | `db` |
| `redis.db.expires` | Keys with expiration in keyspace | Gauge | `db` |
| `redis.db.keys` | Total keyspace keys | Gauge | `db` |
| `redis.keys.evicted` | Keys removed due to maxmemory limit | Sum | - |
| `redis.keys.expired` | Total key expiration events | Sum | - |
| `redis.keyspace.hits` | Successful key lookups | Sum | - |
| `redis.keyspace.misses` | Failed key lookups | Sum | - |
| `redis.latest_fork` | Duration of most recent fork operation | Gauge | - |
| `redis.memory.fragmentation_ratio` | Ratio between RSS and used memory | Gauge | - |
| `redis.memory.lua` | Memory used by Lua engine | Gauge | - |
| `redis.memory.peak` | Peak memory consumption | Gauge | - |
| `redis.memory.rss` | Memory allocated as viewed by OS | Gauge | - |
| `redis.memory.used` | Bytes allocated by Redis allocator | Gauge | - |
| `redis.net.input` | Total network bytes read | Sum | - |
| `redis.net.output` | Total network bytes written | Sum | - |
| `redis.rdb.changes_since_last_save` | Modifications since last dump | Sum | - |
| `redis.replication.backlog_first_byte_offset` | Master offset of replication backlog | Gauge | - |
| `redis.replication.offset` | Server's current replication offset | Gauge | - |
| `redis.slaves.connected` | Number of connected replicas | Sum | - |
| `redis.uptime` | Seconds since server start | Sum | - |

### Metric Attributes

| Attribute | Values | Description |
|-----------|--------|-------------|
| `state` | `sys`, `sys_children`, `sys_main_thread`, `user`, `user_children`, `user_main_thread` | CPU state |
| `db` | `db0`, `db1`, etc. | Database index |

These metrics provide insights into:
- **Memory usage and performance** through memory metrics including fragmentation ratio
- **Client activity** via connection counts and buffer sizes
- **Command throughput** using commands per second and total processed
- **Cache effectiveness** through keyspace hit/miss ratios
- **Key lifecycle** via eviction and expiration statistics
- **Network I/O** through input/output byte counters
- **Replication health** using replication offset and connected replicas

For a complete list of all available metrics and their detailed descriptions, refer to the [Redis Receiver documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/redisreceiver/documentation.md) in the upstream OpenTelemetry Collector repository.
