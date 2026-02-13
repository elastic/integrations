# MySQL OpenTelemetry Assets

This package allows you to monitor [MySQL](https://www.mysql.com), an open-source Relational Database Management System (RDBMS) that enables users to store, manage, and retrieve structured data efficiently.

The MySQL OpenTelemetry assets provide a visual representation of MySQL metrics and logs collected using the [OpenTelemetry MySQL receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/v0.145.0/receiver/mysqlreceiver), enabling you to monitor database performance and troubleshoot issues effectively in real time.

## Compatibility

The MySQL OpenTelemetry assets have been tested with [OpenTelemetry MySQL receiver v0.145.0](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.145.0/receiver/mysqlreceiver/README.md).

Databases tested against:
- MySQL 8.0, 9.4
- MariaDB 10.11, 11.8

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Setup

### Prerequisites

The MySQL user configured for monitoring requires different permissions depending on which metrics you want to collect:

**For basic metrics (connections, buffer pool, handlers, etc.):**
- Ability to execute `SHOW GLOBAL STATUS` (available by default to database users)

**For query samples and statement events:**
```sql
GRANT SELECT ON performance_schema.* TO '<MYSQL_USER>'@'%';
```

**For table statistics metrics (`mysql.table.size`, `mysql.table.rows`):**
```sql
GRANT SELECT ON information_schema.TABLES TO '<MYSQL_USER>'@'%';
```

**For replication metrics (`mysql.replica.sql_delay`, `mysql.replica.time_behind_source`):**

MySQL:
```sql
GRANT REPLICATION CLIENT ON *.* TO '<MYSQL_USER>'@'%';
```

MariaDB:
```sql
GRANT REPLICA MONITOR ON *.* TO '<MYSQL_USER>'@'%';
```

**Recommended: Grant all permissions for complete monitoring:**
```sql
GRANT SELECT ON performance_schema.* TO '<MYSQL_USER>'@'%';
GRANT SELECT ON information_schema.TABLES TO '<MYSQL_USER>'@'%';
GRANT REPLICATION CLIENT ON *.* TO '<MYSQL_USER>'@'%';  -- MySQL only
-- OR for MariaDB:
-- GRANT REPLICA MONITOR ON *.* TO '<MYSQL_USER>'@'%';
```

### Configuration

Install and configure the upstream OpenTelemetry Collector or Elastic Distribution of OpenTelemetry (EDOT) Collector to export metrics to Elasticsearch. The configuration below uses separate receivers for primary and replica instances because replication metrics are only available on replicas.

Replace the following placeholders in the configuration:
- `<MYSQL_PRIMARY_ENDPOINT>`: MySQL primary instance endpoint (format: `host:port`, e.g., `localhost:3306` or `mysql-primary.example.com:3306`)
- `<MYSQL_REPLICA_ENDPOINT>`: MySQL replica instance endpoint (format: `host:port`, e.g., `mysql-replica.example.com:3306`)
- `<MYSQL_USER>`: MySQL username configured with required permissions
- `<MYSQL_PASSWORD>`: MySQL user password
- `<ES_ENDPOINT>`: Elasticsearch endpoint (e.g., `https://elasticsearch.example.com:9200`)
- `<ES_API_KEY>`: Elasticsearch API key for authentication

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
      mysql.client.network.io:
        enabled: true
      mysql.connection.errors:
        enabled: true
      mysql.max_used_connections:
        enabled: true
      mysql.query.client.count:
        enabled: true
      mysql.query.count:
        enabled: true
      mysql.query.slow.count:
        enabled: true
      mysql.table.rows:
        enabled: true
      mysql.table.size:
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

Refer to the [metadata.yaml](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.145.0/receiver/mysqlreceiver/metadata.yaml) of the OpenTelemetry MySQL receiver for details on available metrics.

### Logs

Refer to the [documentation.md](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.145.0/receiver/mysqlreceiver/documentation.md) of the OpenTelemetry MySQL receiver for details on log collection.
