# MySQL OpenTelemetry Input Package

## Overview

The MySQL OpenTelemetry Input Package for Elastic enables collection of metrics and logs from MySQL database servers through OpenTelemetry protocols using the [mysqlreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/mysqlreceiver).

### How it works

This package receives telemetry data from MySQL servers by configuring the MySQL endpoint and credentials in the Input Package, which then gets applied to the mysqlreceiver present in the EDOT collector, which then forwards the data to Elastic Agent. The Elastic Agent processes and enriches the data before sending it to Elasticsearch for indexing and analysis. Once the data arrives into Elasticsearch, its corresponding [MySQL OpenTelemetry Assets Package](https://www.elastic.co/docs/reference/integrations/mysql_otel) gets auto installed and the dashboards light up.

The package collects both **metrics** (from `SHOW GLOBAL STATUS` and InnoDB tables) and **logs** (query samples and top queries). Log events include:
- **`db.server.query_sample`** (enabled by default): Current running database statements
- **`db.server.top_query`** (when top query collection is configured): Queries that consumed the most CPU

## Requirements

- MySQL 8.0+ or MariaDB 10.11+
- A MySQL user with permissions to run `SHOW GLOBAL STATUS`
- For query sample collection, the `performance_schema` must be enabled

### MySQL requirements for log collection

To collect log events (query samples and top queries), configure MySQL as follows:

| Parameter | Value | Description |
|-----------|-------|-------------|
| `performance_schema` | Enabled | Required for log collection |
| `max_digest_length` | 4096 | Recommended maximum length of digest text |
| `performance_schema_max_digest_length` | 4096 | Recommended maximum length of digest text on performance schema |
| `performance_schema_max_sql_text_length` | 4096 | Recommended maximum length of SQL text |

Also grant the MySQL user access to the performance schema:

```sql
GRANT SELECT ON performance_schema.* TO <your-user>@'%';
```

## Configuration

For the full list of settings exposed for the receiver and examples, refer to the [configuration](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/mysqlreceiver#configuration) section.

## Metrics and logs reference

For a complete list of all available metrics, log events, and their detailed descriptions, refer to the [MySQL Receiver documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/mysqlreceiver/documentation.md) in the upstream OpenTelemetry Collector repository.
