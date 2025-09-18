## Overview

The Microsoft SQL Server OpenTelemetry integration tracks the performance and health of your SQL Server instances. It collects key system and database metrics such as user connections, buffer pool usage, SQL compilations and recompilations, transaction rates, blocking activity, I/O performance etc.  

With Elasticsearch and Kibana, you can store, search, and visualize these metrics, enabling proactive monitoring, alerting, and capacity planning for your SQL Server deployments.

### Compatibility

The integration package has been tested with [SQLServer OpenTelemetry Receiver v0.130.0](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver0/sqlserverreceiver/README.md) and Microsoft SQL server version 15.0.2000.5.

### How it works

The Microsoft SQL Server OpenTelemetry Receiver collects metrics from a SQL Server instance using two primary methods:

- **Windows Performance Counters** – Used for system-level metrics. These counters are only available when the receiver is running on Windows. See [sys.dm_os_performance_counters (Transact-SQL)](https://learn.microsoft.com/en-us/sql/relational-databases/system-dynamic-management-views/sys-dm-os-performance-counters-transact-sql) for more details.

- **SQL Queries (DMVs and system views)** – The receiver executes lightweight queries against SQL Server Dynamic Management Views (DMVs) and system views, such as `sys.dm_exec_requests`, and `sys.databases`. These queries provide data related to database and query performance, memory usage and database states. See [Dynamic Management Views and Functions (Transact-SQL)](https://learn.microsoft.com/sql/relational-databases/system-dynamic-management-views/system-dynamic-management-views) for more details.

> **Note:** Make sure to run the collector as administrator in order to collect all performance counters for metrics.

## What data does this integration collect?

The integration collects metrics that provide visibility into SQL Server's functionality, from data persistence to query optimization, indexes, and resource pooling. It comes with pre-built assets in Kibana that visually represent the collected metrics and events, helping you monitor and explore database activity and performance.

## What do I need to use this integration?

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

To use the Microsoft SQL Server OpenTelemetry integration, the collector must connect with a SQL Server login that has sufficient privileges to query system views and dynamic management views (DMVs).

If using a `sysadmin` login (e.g., sa), no additional configuration is required. `sysadmin` already has access to all DMVs and system views used by the receiver.

For non-sysadmin login, specific permissions must be granted explicitly. For example:

```sql
CREATE LOGIN otel WITH PASSWORD = '<password>';
USE master;
CREATE USER otel FOR LOGIN otel;

GRANT VIEW SERVER STATE TO otel;
GRANT SELECT ON sys.dm_os_performance_counters TO otel;
```

Additionally, certain metrics and events must be explicitly enabled in the configuration. Check the sample collector configuration in the next section, and refer to the receiver documentation for a complete list of supported metrics and events.


## How do I deploy this integration

### Onboard and configure

Install and configure the upstream OTel Collector to export metrics to Elasticsearch, as shown in the following example:

```yaml
sqlserver:
    collection_interval: 10s             
    username: <username>
    password: <password>
    server: 0.0.0.0
    port: <port>
    metrics:
      sqlserver.processes.blocked:              
        enabled: true
      sqlserver.database.count:
        enabled: true  
    events:
      db.server.query_sample:
        enabled: true
      db.server.top_query:
        enabled: true
    top_query_collection:                   
      lookback_time: 60                     
      max_query_sample_count: 1000          
      top_query_count: 200                  
      collection_interval: 60s              
    query_sample_collection:           
      max_rows_per_query: 100               
    
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
      receivers: [sqlserver]
      exporters: [debug, elasticsearch/otel]
    logs:
      receivers: [sqlserver]
      exporters: [debug, elasticsearch/otel]
```

Note: This configuration defines two pipelines — one for metrics and one for logs (events) from the SQL Server receiver.

- Metrics are ingested into the metrics-* data view in Elasticsearch.
- Events (logs) are ingested into the logs-* data view in Elasticsearch.

For the full list of settings exposed for the receiver, refer to the [configuration](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/sqlserverreceiver#configuration) section.

### Validation

To verify that the Microsoft SQL Server OpenTelemetry integration is working:

1. Check Collector Logs
Ensure the OpenTelemetry Collector is running and the `sqlserverreceiver` is enabled. You should see logs confirming metric collection from your SQL Server instance.

2. Check Dashboards
Open **Kibana → Dashboards** and confirm that the Microsoft SQL Server OpenTelemetry Metrics dashboard populates with the collected data.

## Reference

### SQL Server metrics and events reference

Refer to the OpenTelemetry SQL Server receiver's [documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/sqlserverreceiver/documentation.md) for the complete list of metrics and events collected.