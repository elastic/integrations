## Overview

The PostreSQL OpenTelemetry integration allows you to monitor [PostgreSQL](https://www.postgresql.org/) servers and to collect telemetry data to track database health and performance. 

### Compatibility

The integration package has been tested with [PostgreSQL OpenTelemetry Receiver v0.130.0](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/postgresqlreceiver/README.md) and PostgreSQL server version 16.4.

### How it works

PostgreSQL gathers and aggregates information about server activity using its built-in statistics collector which exposes the data through predefined views. For example `pg_stat_database` and `pg_stat_statements`. For a complete and up-to-date list of the statistics views and metrics collected, refer to the PostgreSQL Receiver [documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/postgresqlreceiver). For detailed explanations of what each statistics view means, check the official documentation for the [statistics collector](https://www.postgresql.org/docs/current/monitoring-stats.html#MONITORING-STATS) and [pg_stat_statements](https://www.postgresql.org/docs/current/pgstatstatements.html). 

## What data does this integration collect?

The integration provides assets in Kibana that visually represent the collected metrics and events, helping you monitor and explore database activity and performance.

## What do I need to use this integration?

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Some metrics require the `pg_stat_statements` [module](https://www.postgresql.org/docs/current/pgstatstatements.html#PGSTATSTATEMENTS). The module tracks the execution statistics for all the SQL statements. To enable it, add the module to the `shared_preload_libraries` parameter in the `postgres.conf` file and then **restart the server** for the settings to take effect.

Additionally, certain metrics and events must be explicitly enabled in the configuration. Check the sample collector configuration in the next section, and refer to the receiver documentation for a complete list of supported metrics and events.


## How do I deploy this integration

### Onboard and configure

Install and configure the upstream OTel Collector to export metrics to Elasticsearch, as shown in the following example:

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

For the full list of settings exposed for the receiver, refer to the [configuration](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/postgresqlreceiver#configuration) section.

### Validation

To verify that the PostgreSQL OpenTelemetry integration is working:

1. Check Collector Logs
Ensure the OpenTelemetry Collector is running and the postgresqlreceiver is enabled. You should see logs confirming metric collection from your PostgreSQL instance.

2. Check Dashboards
Open **Kibana → Dashboards** and confirm that the PostgreSQL OpenTelemetry Metrics dashboard populates with the collected data.

## Reference

### PostgreSQL metrics and events reference

Refer to the OpenTelemetry PostgreSQL receiver's [documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/postgresqlreceiver/documentation.md) for the complete list of metrics and events collected.
