# MySQL OpenTelemetry Input Package 

## Overview
The MySQL OpenTelemetry Input Package for Elastic enables collection of telemetry data from MySQL database servers through OpenTelemetry protocols using the [mysqlreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/mysqlreceiver).


### How it works
This package receives telemetry data from MySQL servers by configuring the MySQL endpoint and credentials in the Input Package, which then gets applied to the mysqlreceiver present in the EDOT collector, which then forwards the data to Elastic Agent. The Elastic Agent processes and enriches the data before sending it to Elasticsearch for indexing and analysis. Once the data arrives into Elasticsearch, its corresponding [MySQL OpenTelemetry Assets Package](https://www.elastic.co/docs/reference/integrations/mysql_otel) gets auto installed and the dashboards light up.


## Requirements

- MySQL 8.0+ or MariaDB 10.11+
- A MySQL user with permissions to execute `SHOW GLOBAL STATUS`
- For query sample collection, the `performance_schema` must be enabled


## Configuration Options

### Connection Settings
| Setting | Required | Default | Description |
|---------|----------|---------|-------------|
| Endpoint | Yes | `localhost:3306` | The MySQL server endpoint (host:port) |
| Username | Yes | `root` | MySQL username |
| Password | No | - | MySQL password |
| Database | No | - | Specific database to collect metrics from (all if not set) |
| Transport | No | `tcp` | Network to use for connecting |
| Allow Native Passwords | No | `true` | Allow native password authentication |

### TLS Settings
| Setting | Required | Default | Description |
|---------|----------|---------|-------------|
| Disable TLS | No | `false` | Set to true to disable TLS connections |
| Skip TLS Verification | No | `false` | Set to true to skip certificate verification |
| TLS Server Name Override | No | - | Override the ServerName in TLSConfig |
| TLS CA File | No | - | Path to CA certificate file for verifying the server certificate |
| TLS Certificate File | No | - | Path to client certificate file for mTLS authentication |
| TLS Key File | No | - | Path to client key file for mTLS authentication |

### Collection Settings
| Setting | Required | Default | Description |
|---------|----------|---------|-------------|
| Collection Interval | No | `10s` | Time between each metric collection |
| Initial Delay | No | `1s` | Delay before starting collection |

### Statement Events Settings
| Setting | Required | Default | Description |
|---------|----------|---------|-------------|
| Digest Text Limit | No | `120` | Maximum length of digest text |
| Time Limit | No | `24h` | Maximum time since statements were observed |
| Limit | No | `250` | Maximum number of statement event records |

### Query Sample Collection Settings
| Setting | Required | Default | Description |
|---------|----------|---------|-------------|
| Max Rows Per Query | No | `100` | Maximum rows to collect per scrape |

### Top Query Collection Settings
| Setting | Required | Default | Description |
|---------|----------|---------|-------------|
| Lookback Time | No | `60` | Time window (seconds) for top queries |
| Max Query Sample Count | No | `1000` | Maximum records to fetch per run |
| Top Query Count | No | `200` | Maximum active queries to report |
| Collection Interval | No | `60s` | Interval for top query emission |
| Query Plan Cache Size | No | `1000` | Cache size for query plan results |
| Query Plan Cache TTL | No | `1h` | TTL for cached query plans |


## Metrics reference
For a complete list of all available metrics and their detailed descriptions, refer to the [MySQL Receiver documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/mysqlreceiver/documentation.md) in the upstream OpenTelemetry Collector repository.
