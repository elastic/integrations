# GCP Cloud SQL MySQL OpenTelemetry Assets

This package contains Kibana assets for monitoring [Cloud SQL for MySQL](https://cloud.google.com/sql/docs/mysql) instances with Google Cloud Monitoring metrics collected by the OpenTelemetry Collector.

The package is **content only**. It does not configure data collection. Use the **[Google Cloud Monitoring (OpenTelemetry)](https://www.elastic.co/docs/reference/integrations/googlecloudmonitor_input_otel)** input package (`googlecloudmonitor_input_otel`) to collect Cloud SQL for MySQL metrics into Elasticsearch.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage
the Elastic Stack on your own hardware.

## Setup

Install the **[Google Cloud Monitoring OpenTelemetry Input](https://www.elastic.co/docs/reference/integrations/googlecloudmonitor_input_otel)** package (`googlecloudmonitor_input_otel`) and configure it to collect Cloud SQL for MySQL Cloud Monitoring metrics (for example, `cloudsql.googleapis.com/database/mysql/queries`). This content package provides assets that visualize data collected by that input.

When configuring the input package, set the dataset name to `gcp.cloudsql_mysql.otel` so that data is written to the `metrics-gcp.cloudsql_mysql.otel-default` data stream, which these dashboards query.

Shared Cloud SQL metrics such as CPU, memory and disk are also emitted for PostgreSQL and SQL Server instances. These dashboards keep only MySQL instances, using `cloudsql.googleapis.com/database/mysql/queries` as the marker.

## Dashboards

| Dashboard | Description |
|-----------|-------------|
| **[GCP OTel] Cloud SQL MySQL Overview** | Fleet view of Cloud SQL for MySQL instances. Availability, partial downtime, CPU, memory and disk saturation, instance state and fleet queries per second over time, an instance list with region, free disk and failed logins, and top 10 instance trends for CPU, memory, disk, connections, queries per second and slow queries. |
| **[GCP OTel] Cloud SQL MySQL Instance Detail** | One Cloud SQL for MySQL instance. Instance metadata with queries per second, slow query, buffer pool hit and connection usage KPIs, then availability, capacity against quotas, traffic and errors (slow queries, lock waits, deadlocks), connections and threads, I/O and cache, and replication. Open it from the overview. |

## Alerting Rule Templates
Alert rule templates provide pre-defined configurations for creating alert rules in Kibana.

For more information, refer to the [Elastic documentation](https://www.elastic.co/docs/reference/fleet/alerting-rule-templates).

Alert rule templates require Elastic Stack version 9.6.0 or later.

These templates use the Kibana Alerting v2 engine, so you need to enable the [experimental alerting system](https://www.elastic.co/docs/explore-analyze/alerting/experimental-alerting-system/get-started/setup) in Kibana before you can create rules from them. Alerts are grouped per Cloud SQL instance (`database_id`), and only MySQL instances are evaluated.

**The following alert rule templates are available:**

<details>
<summary>View the alert rule templates</summary>

| Name | Description |
|---|---|
| [GCP Cloud SQL MySQL OTel] Connections near the max_connections limit | Alerts when open connections to a Cloud SQL for MySQL instance (database/network/connections) are at least 90% of its max_connections setting (database/mysql/max_connections) in every observed minute of the last 10 minutes, with at least 3 minutes observed. At 100%, MySQL refuses new connections with 'Too many connections'. connection_usage_pct is the latest value, computed like the Connection usage % panel. Requiring every observed minute ignores single spikes and the partly filled newest minute. |
| [GCP Cloud SQL MySQL OTel] Disk nearly full | Alerts when a Cloud SQL for MySQL instance has used at least 90% of its data disk (database/disk/bytes_used over database/disk/quota) in every observed minute of the last 10 minutes, with at least 3 minutes observed. Google recommends keeping at least 20% free. A full disk stops writes and replication and can take the instance offline. With automatic storage increase, the quota grows in permanent steps and the alert recovers once usage falls below 90% of the new quota. disk_used_pct is the latest value, computed like the Max disk % panel. |
| [GCP Cloud SQL MySQL OTel] Failed connection surge | Alerts when at least 10% of connection attempts to a Cloud SQL for MySQL instance failed over the last 15 minutes (database/mysql/aborted_connects_count over database/mysql/connections_count, computed like the Failed logins % column) and there was an average of at least 1 failed attempt per minute. The volume guard stops a single failure on an idle instance from alerting. Typical causes are rotated or wrong credentials, missing privileges, handshake timeouts, refusals at max_connections and brute-force attempts. This is a short-window, high-threshold signal for sudden breakage, not a long-term quality objective. |
| [GCP Cloud SQL MySQL OTel] High CPU utilization | Alerts when the average CPU utilization of a Cloud SQL for MySQL instance over the last 15 minutes is at least 90% of its reserved vCPUs (the sample-weighted mean of database/cpu/utilization, with at least 5 samples). At this level, statements queue for CPU and query latency rises. Values above 100% are possible. The 15-minute average absorbs short spikes and allows for the 3-5 minute delivery delay. |
| [GCP Cloud SQL MySQL OTel] High memory utilization | Alerts when the average memory utilization of a Cloud SQL for MySQL instance over the last 15 minutes is at least 95% of its memory quota (the sample-weighted mean of database/memory/utilization, with at least 5 samples). A warm InnoDB buffer pool keeps memory high but flat, which is normal. This threshold sits above that steady state, close to the point where MySQL risks an out-of-memory restart. |
| [GCP Cloud SQL MySQL OTel] High replication lag on read replica | Alerts when a Cloud SQL for MySQL read replica has been at least 300 seconds (5 minutes) behind its primary (database/replication/replica_lag) in every observed minute of the last 10 minutes, with at least 3 minutes observed. Replica reads are stale, and promoting the replica would lose recent transactions. network_lag_s is the binary log transport delay and apply_lag_s is the rest, which is spent applying changes on the replica. Negative lag means replication is inactive, which the 'Replication broken on read replica' rule covers. Set the threshold to your read-staleness or recovery point objective. |
| [GCP Cloud SQL MySQL OTel] InnoDB deadlocks and lock wait timeouts | Alerts when statements on a Cloud SQL for MySQL instance fail on row locks at an average of at least 1 per minute over the last 15 minutes. Failures are deadlocks (database/mysql/innodb/deadlocks_count, where a transaction was rolled back) plus lock wait timeouts (lock_timeout_count, where a statement gave up after innodb_lock_wait_timeout). Rates are per reported minute, so gaps and duplicate points don't skew them. Each failure is an application error unless the client retries. |
| [GCP Cloud SQL MySQL OTel] Instance metrics not reporting | Alerts when a Cloud SQL for MySQL instance that reported metrics in the last 2 hours has sent no Cloud SQL metric for at least 20 minutes, about four times the normal 3-5 minute delivery delay. The other rules can't evaluate an instance that has no data, so this rule is what catches a stopped collector, failing Cloud Monitoring API access or a deleted instance. The alert recovers when data resumes, or after 2 hours of silence, once the instance leaves the window. One missing data point never triggers it. |
| [GCP Cloud SQL MySQL OTel] Instance not serving | Alerts when a Cloud SQL for MySQL instance is not serving: its latest reported state is MAINTENANCE, FAILED, SUSPENDED or UNKNOWN_STATE, or it is RUNNING but database/up is 0, and it was down in at least 3 observed minutes of the 10-minute window. Instances stopped by their owner (RUNNABLE) or being created (PENDING_CREATE) are ignored. The 10-minute window allows for the 3-5 minute Cloud Monitoring delivery delay, and the 3-minute persistence leaves short restarts and failovers to the 'Instance restarted or failed over' rule. One alert per instance (database_id); outage_type separates planned maintenance from unplanned outages. |
| [GCP Cloud SQL MySQL OTel] Instance restarted or failed over | Alerts when a Cloud SQL for MySQL instance restarted or failed over within the last 15 minutes. That means an automatic failover request was recorded, or a minute with less than 55 seconds of uptime (database/uptime; 59-61 s is collection jitter) was followed by a full minute, so the instance went down and came back. Restarts while the instance reported MAINTENANCE are treated as planned and ignored. Ongoing outages are covered by the 'Instance not serving' rule. The alert stays active while the event is inside the window, then recovers. The 15-minute window and 5-minute schedule make sure each event is evaluated at least once, despite the 3-5 minute delivery delay. |
| [GCP Cloud SQL MySQL OTel] Replication broken on read replica | Alerts when replication on a Cloud SQL for MySQL read replica is stopped. That means the latest replication I/O thread state is No or Connecting, the SQL thread state is No, or replication lag is negative (replication inactive), and the same signal was broken in at least 3 observed minutes of the last 10 minutes. Brief I/O reconnects during primary restarts are ignored. last_io_errno and last_sql_errno are reported for diagnosis but don't trigger the alert on their own, because a stopped thread already shows as No or Connecting. A broken replica serves increasingly stale data and is unsafe to promote. Only instances that report replication series are evaluated. |

</details>

## SLO Templates
SLO templates provide pre-defined configurations for creating SLOs in Kibana.

For more information, refer to the [Elastic documentation](https://www.elastic.co/docs/solutions/observability/incident-management/service-level-objectives-slos).

SLO templates require Elastic Stack version 9.4.0 or later.

**The following SLO templates are available:**

<details>
<summary>View the SLO templates</summary>

| Name | Description |
|---|---|
| [GCP Cloud SQL MySQL OTel] Slow query ratio 99% rolling 30 days | Tracks the share of SQL statements on each Cloud SQL for MySQL instance that finish within the instance's long_query_time threshold: database/mysql/queries minus database/mysql/slow_queries_count, divided by database/mysql/queries, the same definition as the Slow query % dashboard panel. The objective is that at least 99% of statements over a rolling 30-day window are not slow. When the error budget burns, applications are waiting seconds for query results, typically because of missing indexes, query plan regressions, lock waits, or CPU and memory pressure. What counts as slow depends on each instance's long_query_time flag (10 seconds by default), so lower that flag to match your latency expectations. Instances that intentionally run long reporting or batch statements may need a lower target or should be excluded. The filter requires a MySQL statement metric to be present, so the SLO only creates instances for MySQL databases and never for other Cloud SQL engines in the same data stream. Cloud Monitoring data reaches Elasticsearch 3-5 minutes late, so set the SLO sync delay to at least 5m when you create it. |

</details>


