# GCP Cloud SQL for SQL Server OpenTelemetry Assets

This package contains Kibana assets for monitoring [Cloud SQL for SQL Server](https://cloud.google.com/sql/docs/sqlserver) instances with Google Cloud Monitoring metrics collected by the OpenTelemetry Collector.

The package is **content only**. It does not configure data collection. Use the **[Google Cloud Monitoring (OpenTelemetry)](https://www.elastic.co/docs/reference/integrations/googlecloudmonitor_input_otel)** input package (`googlecloudmonitor_input_otel`) to collect Cloud SQL for SQL Server metrics into Elasticsearch.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage
the Elastic Stack on your own hardware.

## Setup

Install the **[Google Cloud Monitoring OpenTelemetry Input](https://www.elastic.co/docs/reference/integrations/googlecloudmonitor_input_otel)** package (`googlecloudmonitor_input_otel`) and configure it to collect Cloud SQL for SQL Server Cloud Monitoring metrics (for example, `cloudsql.googleapis.com/database/cpu/utilization`). This content package provides assets that visualize data collected by that input.

When configuring the input package, set the dataset name to `gcp.cloudsql_sqlserver.otel` so that data is written to the `metrics-gcp.cloudsql_sqlserver.otel-default` data stream, which these dashboards query.

## Dashboards

| Dashboard | Description |
|-----------|-------------|
| **[GCP OTel] Cloud SQL - SQL Server Overview** | Fleet overview of Cloud SQL for SQL Server instances. Covers availability, CPU, memory and disk saturation, batch throughput, and blocking. |
| **[GCP OTel] Cloud SQL - SQL Server Instance Detail** | Detail view of a single Cloud SQL for SQL Server instance. Covers availability, capacity, traffic and errors, connections, locking and blocking, memory and I/O, and high availability and replication. |

## Alerting Rule Templates
Alert rule templates provide pre-defined configurations for creating alert rules in Kibana.

For more information, refer to the [Elastic documentation](https://www.elastic.co/docs/reference/fleet/alerting-rule-templates).

Alert rule templates require Elastic Stack version 9.6.0 or later.

**The following alert rule templates are available:**

<details>
<summary>View the alert rule templates</summary>

| Name | Description |
|---|---|
| [GCP Cloud SQL SQL Server OTel] Blocking or lock waits high | Alerts when a SQL Server instance has sessions blocked at every sample over 15 minutes (processes_blocked never drops to 0, i.e. a persistent blocking chain), or lock waits average at least 5 seconds each with at least 30 lock waits in the window, for 2 consecutive checks. Built on SQL Server-only metrics. Grouped by database_id. |
| [GCP Cloud SQL SQL Server OTel] CPU saturated with runnable task queue | Alerts when the average CPU utilization of a SQL Server instance is at or above 90% of its reserved vCPUs over 15 minutes and, at the same time, the SQL Server scheduler run queue (runnable_tasks summed across schedulers) averages at least 1 task, for 3 consecutive checks. High CPU with an empty run queue is a busy but healthy server and does not fire. Requires at least 5 minutes of samples and applies the SQL Server engine marker. Grouped by database_id. |
| [GCP Cloud SQL SQL Server OTel] Deadlocks detected | Alerts when a SQL Server instance records 5 or more deadlocks within 15 minutes. SQL Server resolves each deadlock by killing a victim transaction, so the application receives an error. SQL Server-only metric, so no engine marker is needed. Grouped by database_id; the locked resource types involved are listed. |
| [GCP Cloud SQL SQL Server OTel] Disk utilization high | Alerts when the latest disk utilization of a SQL Server instance is at or above 90% of its disk quota for 2 consecutive checks. A full disk stops writes and can take the instance down. Uses the latest per-minute value in a 15-minute window and the SQL Server engine marker. Grouped by database_id. |
| [GCP Cloud SQL SQL Server OTel] Failed or anomalous connection attempts | Alerts when a SQL Server instance has 100 or more failed connection attempts in 15 minutes, or any connection attempt that Cloud SQL flagged as anomalous (e.g. brute-force login). Failed logins indicate misconfigured credentials after a rotation or deploy, or an attack. Applies the SQL Server engine marker. Grouped by database_id. |
| [GCP Cloud SQL SQL Server OTel] HA failover occurred or standby unavailable | Alerts when a high-availability (regional) SQL Server instance requested an automatic failover in the last 15 minutes, or its latest available_for_failover sample is 0 (the standby cannot take over), for 2 consecutive checks. Both metrics are reported only for HA instances, so zonal instances never alert. Applies the SQL Server engine marker. Grouped by database_id. |
| [GCP Cloud SQL SQL Server OTel] Instance down or not running | Alerts when a SQL Server instance's latest `up` sample is 0 or its latest `instance_state` is not RUNNING (MAINTENANCE, RUNNABLE/stopped, SUSPENDED, FAILED, UNKNOWN_STATE, PENDING_CREATE). The current state is resolved from the last 15 minutes; the SQL Server engine marker (page_life_expectancy reported) is evaluated over the 24-hour rule window so a just-stopped instance stays in scope. Requires 3 consecutive breaching runs (about 6 minutes). An instance stopped or deleted for more than 24 hours drops out of scope and recovers. Returns up to 100 instances, grouped by database_id. |
| [GCP Cloud SQL SQL Server OTel] Instance restarted | Alerts when a SQL Server instance restarted within the last 30 minutes, detected as an `uptime` sample of 0 < uptime < 55 seconds (the first partial minute after a start). Unexpected restarts usually mean a crash or an out-of-memory condition; Google maintenance and owner-initiated restarts also fire. The SQL Server engine marker is evaluated over the 24-hour rule window. Each restart keeps the alert active for about 30 minutes, then it recovers. Grouped by database_id. |
| [GCP Cloud SQL SQL Server OTel] Memory pressure (grants pending or buffer pool churn) | Alerts when a SQL Server instance shows memory pressure over 15 minutes: queries waiting for workspace memory (memory_grants_pending averages at least 1), page life expectancy staying below a memory-size-scaled floor (300 s per 4 GiB of instance memory) for the whole window without warming up (growing at least 30 s per minute, as after a restart), or the buffer cache hit ratio averaging below 90%. Requires at least 5 samples, for 2 consecutive checks. Instances with less than 1 GB of memory are excluded. Built on SQL Server-only metrics. Grouped by database_id. |
| [GCP Cloud SQL SQL Server OTel] Read replica lag high or replication stopped | Alerts when a SQL Server read replica stays at least 120 seconds behind its primary for the whole 15-minute window (minimum lag at or above the threshold, with at least 5 samples), or its latest replica_lag sample is negative (replication inactive), for 2 consecutive checks. replica_lag is only reported on replica instances, so primaries are never evaluated. Applies the SQL Server engine marker. Grouped by the replica's database_id. |

</details>

## SLO Templates
{{sloTemplates}}
