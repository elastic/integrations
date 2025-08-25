# MYSQL metrics for OpenTelemetry Collector

The MySQL metrics from MySQL OTEL receiver allows you to monitor [MySQL](https://www.mysql.com), an open-source Relational Database Management System (RDBMS) that enables users to store, manage, and retrieve structured data efficiently.

The MySQL OpenTelemetry assets provide a visual representation of MySQL metrics collected via OpenTelemetry ([MySQL receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/mysqlreceiver)), enabling you to monitor database performance and troubleshoot issues effectively in real time.

## Compatibility

The content pack has been tested with [OpenTelemetry MySQL receiver v0.129.0](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.129.0/receiver/mysqlreceiver/README.md).

Databases tested against:
- MySQL 8.0, 9.4
- MariaDB 10.11, 11.8

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Setup

1. Install and configure the EDOT Collector or upstream Collector to export metrics to ElasticSearch, as shown in the following example:

```yaml
receivers:
  mysql:
    endpoint: localhost:3306
    username: <MYSQL_USER>
    password: <MYSQL_PASSWORD>
    database: <your database name>
    collection_interval: 10s
    initial_delay: 1s
    statement_events:
      digest_text_limit: 120
      time_limit: 24h
      limit: 250
    metrics:
      mysql.query.client.count:
        enabled: true
      mysql.client.network.io:
        enabled: true
      mysql.commands:
        enabled: true
      mysql.max_used_connections:
        enabled: true
      mysql.connection.errors:
        enabled: true
      mysql.table_open_cache:
        enabled: true
      mysql.replica.sql_delay:
        enabled: true
      mysql.replica.time_behind_source:
        enabled: true
exporters:
  debug:
    verbosity: detailed
  elasticsearch/otel:
    endpoints: https://elasticsearch:9200
    user: <userid>
    password: <pwd>
    mapping:
      mode: otel
    metrics_dynamic_index:
      enabled: true
service:
  pipelines:
    metrics:
      exporters: [debug, elasticsearch/otel]
      receivers: [mysql]
```

Use this configuration to run the collector.

The following metrics should be enabled in the `mysqlreceiver` configuration for the dashboards to be populated:

For Database Overview dashboard:
```yaml
mysql.query.client.count:
  enabled: true
mysql.client.network.io:
  enabled: true
mysql.commands:
  enabled: true
mysql.max_used_connections:
  enabled: true
mysql.connection.errors:
  enabled: true
mysql.table_open_cache:
  enabled: true
```

For Replica Status dashboard:
```yaml
mysql.replica.sql_delay:
  enabled: true
mysql.replica.time_behind_source:
  enabled: true
```

## Metrics reference

### MySQL metrics

Please refer to [the documentation of the OpenTelemetry's MySQL receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/mysqlreceiver/documentation.md).
