# GCP Cloud SQL for PostgreSQL OpenTelemetry Assets

This package contains Kibana assets for monitoring [Cloud SQL for PostgreSQL](https://cloud.google.com/sql/docs/postgres) instances with Google Cloud Monitoring metrics collected by the OpenTelemetry Collector.

The package is **content only**. It does not configure data collection. Use the **[Google Cloud Monitoring (OpenTelemetry)](https://www.elastic.co/docs/reference/integrations/googlecloudmonitor_input_otel)** input package (`googlecloudmonitor_input_otel`) to collect Cloud SQL for PostgreSQL metrics into Elasticsearch.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage
the Elastic Stack on your own hardware.

## Setup

Install the **[Google Cloud Monitoring OpenTelemetry Input](https://www.elastic.co/docs/reference/integrations/googlecloudmonitor_input_otel)** package (`googlecloudmonitor_input_otel`) and configure it to collect Cloud SQL for PostgreSQL Cloud Monitoring metrics (for example, `cloudsql.googleapis.com/database/cpu/utilization`). This content package provides assets that visualize data collected by that input.

When configuring the input package, set the dataset name to `gcp.cloudsql_postgresql.otel` so that data is written to the `metrics-gcp.cloudsql_postgresql.otel-default` data stream, which these dashboards query.

## Dashboards

| Dashboard | Description |
|-----------|-------------|
| **[GCP OTel] Cloud SQL PostgreSQL Overview** | Overview of all Cloud SQL for PostgreSQL instances. Availability, saturation (CPU, memory, disk, connections), throughput, and transaction ID wraparound risk across the fleet. |
| **[GCP OTel] Cloud SQL PostgreSQL Instance Detail** | Detail view of a single Cloud SQL for PostgreSQL instance. Covers availability, capacity, traffic and errors, connections, I/O and cache, vacuum and wraparound, and Query Insights. |

## SLO Templates
SLO templates provide pre-defined configurations for creating SLOs in Kibana.

For more information, refer to the [Elastic documentation](https://www.elastic.co/docs/solutions/observability/incident-management/service-level-objectives-slos).

SLO templates require Elastic Stack version 9.4.0 or later.

**The following SLO templates are available:**

<details>
<summary>View the SLO templates</summary>

| Name | Description |
|---|---|
| [GCP Cloud SQL PostgreSQL OTel] Buffer cache hit ratio 95% rolling 30 days | Tracks how efficiently each Cloud SQL for PostgreSQL instance serves block reads from shared buffers instead of disk. Good events are blocks read from the buffer cache and total events are blocks read from the buffer cache plus disk, both summed from the PostgreSQL-only DELTA metric cloudsql.googleapis.com/database/postgresql/blocks_read_count (per-minute counts by attributes.source, summed across databases). The objective is that 95% of block reads hit the cache over a rolling 30-day window. A falling hit ratio means more disk I/O and slower queries, usually from undersized memory (tier), a working set that outgrows shared_buffers, or inefficient full scans. Caveats: the right ratio depends heavily on the workload. OLTP instances typically stay well above 99%, while analytics or batch-scan workloads can be legitimately lower, so treat 95% as a starting point to tune. 'disk' reads include reads served by the OS page cache, so this measures PostgreSQL buffer efficiency, not physical I/O. The SLO only uses PostgreSQL-only metrics, so no engine marker is needed. It has no data while the instance is stopped or down and does not measure availability; instance-down alerts cover that. Cloud Monitoring data reaches Elasticsearch 3-5 minutes late, so set the SLO sync delay to at least 5m when you create it. |
| [GCP Cloud SQL PostgreSQL OTel] Transaction commit ratio 98% rolling 30 days | Tracks the share of PostgreSQL transactions that commit rather than roll back on each Cloud SQL for PostgreSQL instance. Good events are committed transactions and total events are committed plus rolled-back transactions, both summed from the PostgreSQL-only DELTA metric cloudsql.googleapis.com/database/postgresql/transaction_count (per-minute counts, summed across databases). The objective is that 98% of transactions commit over a rolling 30-day window. A rising rollback share usually means application errors, serialization or constraint failures, statement timeouts or aborted transactions. Caveats: rollbacks are not always failures. Connection-pool resets (for example SQLAlchemy reset-on-return) and read-only sessions that end in ROLLBACK can keep the ratio permanently low with no user impact, so check the baseline and tune the target per workload. The SLO only uses PostgreSQL-only metrics, so no engine marker is needed. It has no data while the instance is stopped or down and does not measure availability; instance-down alerts cover that. Cloud Monitoring data reaches Elasticsearch 3-5 minutes late, so set the SLO sync delay to at least 5m when you create it. |

</details>



## Alerting Rule Templates
Alert rule templates provide pre-defined configurations for creating alert rules in Kibana.

For more information, refer to the [Elastic documentation](https://www.elastic.co/docs/reference/fleet/alerting-rule-templates).

Alert rule templates require Elastic Stack version 9.6.0 or later.

**The following alert rule templates are available:**

<details>
<summary>View the alert rule templates</summary>

| Name | Description |
|---|---|
| \[GCP Cloud SQL PostgreSQL OTel\] CPU utilization high | Alerts when the average CPU utilization of a PostgreSQL instance is at or above 90% of its reserved vCPUs over 15 minutes, for 3 consecutive checks (about 25 minutes sustained). Sustained CPU saturation increases query latency for all clients. Applies the PostgreSQL engine marker. Grouped by database_id. |
| \[GCP Cloud SQL PostgreSQL OTel\] Deadlocks detected | Alerts when a PostgreSQL database records 5 or more deadlocks within 15 minutes. PostgreSQL resolves each deadlock by aborting one transaction, so a burst means application requests are failing because of conflicting lock ordering. PostgreSQL-only metric, so no engine marker is needed. Grouped by database_id and database. |
| \[GCP Cloud SQL PostgreSQL OTel\] Disk utilization high | Alerts when the latest disk utilization of a PostgreSQL instance is at or above 90% of its disk quota for 2 consecutive checks. A full disk stops writes. Uses the latest per-minute value in a 15-minute window and the PostgreSQL engine marker. Grouped by database_id. |
| \[GCP Cloud SQL PostgreSQL OTel\] HA failover occurred or standby unavailable | Alerts when a high-availability (regional) PostgreSQL instance requested an automatic failover in the last 15 minutes, or its latest available_for_failover sample is 0 (the standby cannot take over), for 2 consecutive checks. Optional metrics: both are reported only for HA instances, so zonal instances never alert. Applies the PostgreSQL engine marker. Grouped by database_id. |
| \[GCP Cloud SQL PostgreSQL OTel\] Instance down or not running | Alerts when a PostgreSQL instance's latest `up` sample is 0 or its latest `instance_state` is not RUNNING (MAINTENANCE, RUNNABLE/stopped, SUSPENDED, FAILED, UNKNOWN_STATE, PENDING_CREATE). The current state is resolved from the last 15 minutes; the PostgreSQL engine marker is evaluated over the 24-hour rule window so a just-stopped instance stays in scope. Requires 3 consecutive breaching runs (about 6 minutes) to ride out short maintenance blips. An instance stopped or deleted for more than 24 hours drops out of scope and recovers. Returns up to 100 instances, grouped by database_id. |
| \[GCP Cloud SQL PostgreSQL OTel\] Instance restarted | Alerts when a PostgreSQL instance restarted within the last 30 minutes, detected as an `uptime` sample of 0 \< uptime \< 55 seconds (the first partial minute after a start). Unexpected restarts usually mean an OOM kill or crash; Google maintenance and owner-initiated restarts also fire and are labelled as such in the guide. The engine marker is evaluated over the 1-hour rule window. Each restart keeps the alert active for about 30 minutes, then it recovers. Grouped by database_id. |
| \[GCP Cloud SQL PostgreSQL OTel\] Memory utilization high | Alerts when the average memory utilization (excluding buffer/cache) of a PostgreSQL instance is at or above 90% over 15 minutes, for 2 consecutive checks. Sustained memory pressure precedes OOM restarts. Requires at least 5 samples and applies the PostgreSQL engine marker. Grouped by database_id. Instances with less than 1 GB of memory (shared-core db-f1-micro) are excluded because they report memory pinned at the quota. |
| \[GCP Cloud SQL PostgreSQL OTel\] Vacuum blocked by old transaction | Alerts when the age of the oldest transaction not yet vacuumed stays at or above 100 million transactions for the whole 30-minute window, per holder type (running, prepared, replication_slot, replica). This is a leading indicator of bloat and transaction ID wraparound, and the holder type says what to end or drop. The unit is a transaction count, not seconds. PostgreSQL-only metric, so no engine marker is needed. Grouped by database_id and blocker type. |
| \[GCP Cloud SQL PostgreSQL OTel\] Read replica lag high | Alerts when a PostgreSQL read replica stays at least 120 seconds behind its primary for the whole 15-minute window (minimum lag at or above the threshold), for 2 consecutive checks. Optional metric: replica_lag is only reported on replica instances, so the rule is silent for instances without replicas. Requires at least 5 lag samples and applies the PostgreSQL engine marker: the replica reports num_backends, or its PostgreSQL primary reports replica_byte_lag for it (replicas that report no PostgreSQL metrics stay covered while the primary reports). MySQL and SQL Server replicas match neither. Grouped by the replica's database_id. |
| \[GCP Cloud SQL PostgreSQL OTel\] Transaction ID wraparound risk | Alerts when transaction ID utilization of a PostgreSQL instance reaches 70% (about 1.5 billion XIDs since the last freeze), the threshold Google suggests for this metric; Google's recommender flags instances at 80%. Near 100%, PostgreSQL forces a read-only shutdown to prevent wraparound. Uses the window peak over 30 minutes; PostgreSQL-only metric, so no engine marker is needed. Some replicas do not report this metric and are not covered. Grouped by database_id. |

</details>

