# MySQL integration for OpenTelemetry Collector

This integration allows you to monitor [MySQL](https://www.mysql.com), an open-source Relational Database Management System (RDBMS) that enables users to store, manage, and retrieve structured data efficiently.

The MySQL OpenTelemetry assets provide a visual representation of MySQL metrics and logs collected via the [OpenTelemetry MySQL receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/v0.129.0/receiver/mysqlreceiver), enabling you to monitor database performance and troubleshoot issues effectively in real time.

## Compatibility

The MySQL OpenTelemetry assets have been tested with [OpenTelemetry MySQL receiver v0.129.0](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.129.0/receiver/mysqlreceiver/README.md).

Databases tested against:
- MySQL 8.0, 9.4
- MariaDB 10.11, 11.8

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Setup

### Prerequisites

The MySQL user configured for monitoring requires the following minimum permissions:

```sql
GRANT SELECT ON performance_schema.* TO '<MYSQL_USER>'@'%';
```

To collect replication metrics (`mysql.replica.sql_delay`, `mysql.replica.time_behind_source`), additional permissions are required:

**MySQL:**
```sql
GRANT REPLICATION CLIENT ON *.* TO '<MYSQL_USER>'@'%';
```

**MariaDB:**
```sql
GRANT REPLICA MONITOR ON *.* TO '<MYSQL_USER>'@'%';
```

### Configuration

Install and configure the upstream OpenTelemetry Collector to export metrics to Elasticsearch. The configuration below uses separate receivers for primary and replica instances since replication metrics are only available on replicas.

```yaml
receivers:
  mysql/primary:
    endpoint: <MYSQL_PRIMARY_ENDPOINT>
    username: <MYSQL_USER>
    password: <MYSQL_PASSWORD>
    collection_interval: 10s
    statement_events:
      digest_text_limit: 120
      time_limit: 24h
      limit: 250
    query_sample_collection:
      max_rows_per_query: 100
    top_query_collection:
      collection_interval: 30s
      lookback_time: 60
      max_query_sample_count: 1000
      top_query_count: 100
    events:
      db.server.query_sample:
        enabled: true
      db.server.top_query:
        enabled: true
    metrics:
      mysql.connection.count:
        enabled: true
      mysql.connection.errors:
        enabled: true
      mysql.max_used_connections:
        enabled: true
      mysql.query.count:
        enabled: true
      mysql.query.client.count:
        enabled: true
      mysql.query.slow.count:
        enabled: true
      mysql.commands:
        enabled: true
      mysql.client.network.io:
        enabled: true
      mysql.table.io.wait.count:
        enabled: true
      mysql.table.io.wait.time:
        enabled: true
      mysql.index.io.wait.count:
        enabled: true
      mysql.index.io.wait.time:
        enabled: true
      mysql.table.lock_wait.read.count:
        enabled: true
      mysql.table.lock_wait.read.time:
        enabled: true
      mysql.table.lock_wait.write.count:
        enabled: true
      mysql.table.lock_wait.write.time:
        enabled: true
      mysql.table.size:
        enabled: true
      mysql.table.rows:
        enabled: true
      mysql.table.average_row_length:
        enabled: true
      mysql.statement_event.count:
        enabled: true
      mysql.statement_event.wait.time:
        enabled: true
      mysql.table_open_cache:
        enabled: true
      mysql.joins:
        enabled: true
      mysql.page_size:
        enabled: true
      mysql.mysqlx_worker_threads:
        enabled: true

  mysql/replica:
    endpoint: <MYSQL_REPLICA_ENDPOINT>
    username: <MYSQL_USER>
    password: <MYSQL_PASSWORD>
    collection_interval: 10s
    metrics:
      mysql.replica.time_behind_source:
        enabled: true
      mysql.replica.sql_delay:
        enabled: true

exporters:
  elasticsearch/otel:
    endpoint: <ES_ENDPOINT>
    api_key: <ES_API_KEY>
    mapping:
      mode: otel

service:
  pipelines:
    metrics:
      receivers: [mysql/primary, mysql/replica]
      exporters: [elasticsearch/otel]
    logs:
      receivers: [mysql/primary]
      exporters: [elasticsearch/otel]
```

> **Note:** If you don't have a replica instance, remove the `mysql/replica` receiver and its reference from the metrics pipeline.

## Reference

### Metrics

Please refer to the [metadata.yaml](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.129.0/receiver/mysqlreceiver/metadata.yaml) of the OpenTelemetry MySQL receiver for details on available metrics.

### Logs

Please refer to the [documentation.md](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.129.0/receiver/mysqlreceiver/documentation.md) of the OpenTelemetry MySQL receiver for details on log collection.
