# Apache HTTP Server OpenTelemetry Input Package 

## Overview
The Apache HTTP Server OpenTelemetry Input Package for Elastic enables collection of telemetry data from Apache web servers through OpenTelemetry protocols using the [apachereceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/apachereceiver).


### How it works
This package receives telemetry data from Apache HTTP servers by configuring the Apache status endpoint in the Input Package, which then gets applied to the apachereceiver present in the EDOT collector, which then forwards the data to Elastic Agent. The Elastic Agent processes and enriches the data before sending it to Elasticsearch for indexing and analysis. Once the data arrives into Elasticsearch, its corresponding [Apache OpenTelemetry Assets Package](https://www.elastic.co/docs/reference/integrations/apache_otel) gets auto installed and the dashboards light up.


## Requirements

- Apache HTTP Server 2.4.13+
- The `mod_status` module must be enabled and accessible


## Configuration Options

### Connection Settings
| Setting | Required | Default | Description |
|---------|----------|---------|-------------|
| Endpoint | Yes | `http://localhost:8080/server-status?auto` | The URL of the Apache server-status endpoint |
| Proxy URL | No | - | Proxy URL to use for HTTP requests |

### Collection Settings
| Setting | Required | Default | Description |
|---------|----------|---------|-------------|
| Collection Interval | No | `10s` | Time between each metric collection |
| Initial Delay | No | `1s` | Delay before starting collection |

### HTTP Client Settings
| Setting | Required | Default | Description |
|---------|----------|---------|-------------|
| HTTP Timeout | No | `10s` | HTTP request timeout |
| Read Buffer Size | No | - | Read buffer size for HTTP client transport (in bytes) |
| Write Buffer Size | No | - | Write buffer size for HTTP client transport (in bytes) |
| Max Idle Connections | No | - | Maximum number of idle (keep-alive) connections across all hosts |
| Max Idle Connections Per Host | No | - | Maximum idle (keep-alive) connections per host |
| Max Connections Per Host | No | - | Maximum total connections per host. Zero means no limit |
| Idle Connection Timeout | No | - | Maximum time an idle connection will remain idle before closing (e.g., 90s) |
| Disable Keep-Alives | No | `false` | Set to true to disable HTTP keep-alives |

### TLS Settings
| Setting | Required | Default | Description |
|---------|----------|---------|-------------|
| Disable TLS | No | `false` | Set to true to disable TLS |
| Skip TLS Verification | No | `false` | Set to true to skip certificate verification |
| TLS CA File | No | - | Path to CA certificate file |
| TLS Certificate File | No | - | Path to client certificate file |
| TLS Key File | No | - | Path to client key file |
| TLS Server Name Override | No | - | Override server name for TLS verification |


## Metrics reference
For a complete list of all available metrics and their detailed descriptions, refer to the [Apache Receiver documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/apachereceiver/documentation.md) in the upstream OpenTelemetry Collector repository.
