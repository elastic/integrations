# PostreSQL OpenTelemetry Assets

The PostreSQL OpenTelemetry integration allows you to monitor [PostgreSQL](https://www.postgresql.org/) servers and to collect key metrics to track database health and performance. PostgresSQL gathers and aggregates these metrics internally using its built-in statistics collector, which exposes the data through predefined views. For example:
- `pg_stat_database` view provides one row per database containing aggregate statistics such as the number of transactions committed and rolled back, tuples read and written, block read/write counts, deadlocks, and time spent in I/O operations. 
- `pg_stat_statements` provides one row per normalized SQL statement executed on the server. Each row includes metrics such as the number of times the query has been run, total execution time, number of rows returned/affected, shared/local block hits, and I/O statistics. This view is invaluable for identifying slow or expensive queries and understanding workload patterns.

The OpenTelemetry ([PostgreSQL Receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/postgresqlreceiver)) queries these views under the hood to extract metrics and events, making them available in a structured form for analysis. The PostgreSQL OpenTelemetry assets then provide a visual representation of these collected metrics in Kibana, helping you monitor and explore database activity and performance.

## Compatibility

The content pack has been tested with [PostgreSQL OpenTelemetry Receiver v0.130.0](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.130.0/receiver/iisreceiver/README.md) and PostgreSQL server version 16.4.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Some metrics require the `pg_stat_statements` [module](https://www.postgresql.org/docs/current/pgstatstatements.html#PGSTATSTATEMENTS). The module tracks the execution statistics for all the SQL statements. To enable it, add the module to the `shared_preload_libraries` parameter in the `postgres.conf` file and then **restart the server** for the settings to take effect.

Additionally, certain metrics and events must be explicitly enabled in the configuration. See the sample collector configuration in the next section, and refer to the receiver documentation for a complete list of supported metrics and events.


## Setup

Install and configure the EDOT Collector or upstream OTel Collector to export metrics to ElasticSearch, as shown in the following example:

```yaml
postgresql:
    endpoint: localhost:5432
    transport: tcp
    username: <database_user>
    password: <database_password>
    metrics:
      postgresql.database.locks:
        enabled: true
      postgresql.tup_updated:
        enabled: true
      postgresql.tup_returned:
        enabled: true
      postgresql.tup_fetched:
        enabled: true
      postgresql.tup_inserted:
        enabled: true
      postgresql.tup_deleted:
        enabled: true
      postgresql.blks_hit:
        enabled: true
      postgresql.blks_read:
        enabled: true
    events:
      db.server.top_query:
        enabled: true 
       
exporters:
  debug:
    verbosity: detailed
  elasticsearch/otel:
    endpoint: https://localhost:9200
	user: <userid>
	password: <pwd>
    mapping:
      mode: otel 
    metrics_dynamic_index:
      enabled: true
  
service:
  pipelines:
    metrics:
      receivers: [postgresql]
      exporters: [debug, elasticsearch/otel]
    logs:
      receivers: [postgresql]
      exporters: [debug, elasticsearch/otel]
```

Note: This configuration defines two pipelines — one for metrics and one for logs (events) from the PostgreSQL receiver.

- Metrics are ingested into the metrics-* data view in Elasticsearch.
- Events (logs) are ingested into the logs-* data view in Elasticsearch.

## Metrics reference

### PostgreSQL metrics

Refer to [the documentation of the OpenTelemetry's PostgreSQL receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/postgresqlreceiver/documentation.md).
