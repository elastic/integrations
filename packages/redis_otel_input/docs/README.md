# Redis OpenTelemetry Input Package 

## Overview
The Redis OpenTelemetry Input Package for Elastic enables collection of telemetry data from Redis database servers through OpenTelemetry protocols using the [redisreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/redisreceiver).


### How it works
This package receives telemetry data from Redis servers by configuring the Redis endpoint and credentials in the Input Package, which then gets applied to the redisreceiver present in the EDOT collector, which then forwards the data to Elastic Agent. The Elastic Agent processes and enriches the data before sending it to Elasticsearch for indexing and analysis.


## Requirements

- Redis 3.0+ (any version supporting INFO command)
- Network connectivity from the Elastic Agent to the Redis server
- For authentication: Redis password or Redis ACL credentials (Redis 6.0+)


## Configuration Options

### Connection Settings
| Setting | Required | Default | Description |
|---------|----------|---------|-------------|
| Endpoint | Yes | `localhost:6379` | The Redis server endpoint (host:port) |
| Username | No | - | Redis ACL username (requires Redis 6.0+) |
| Password | No | - | Redis password |
| Transport | No | `tcp` | Network to use for connecting (`tcp` or `unix`) |

### TLS Settings
| Setting | Required | Default | Description |
|---------|----------|---------|-------------|
| Disable TLS | No | `true` | Set to false to enable TLS connections |
| Skip TLS Verification | No | `false` | Set to true to skip certificate verification |
| TLS CA File | No | - | Path to CA certificate file |
| TLS Certificate File | No | - | Path to client certificate file |
| TLS Key File | No | - | Path to client key file |
| TLS Server Name Override | No | - | Override server name for TLS verification |

### Collection Settings
| Setting | Required | Default | Description |
|---------|----------|---------|-------------|
| Collection Interval | No | `10s` | Time between each metric collection |
| Initial Delay | No | `1s` | Delay before starting collection |


## Metrics reference
For a complete list of all available metrics and their detailed descriptions, refer to the [Redis Receiver documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/redisreceiver/documentation.md) in the upstream OpenTelemetry Collector repository.
