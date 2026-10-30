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
{{sloTemplates}}

## Alerting Rule Templates
Alert rule templates provide pre-defined configurations for creating alert rules in Kibana.

For more information, refer to the [Elastic documentation](https://www.elastic.co/docs/reference/fleet/alerting-rule-templates).

Alert rule templates require Elastic Stack version 9.6.0 or later.

**The following alert rule templates are available:**

<details>
<summary>View the alert rule templates</summary>

| Name | Description |
|---|---|
| \[GCP Cloud SQL PostgreSQL OTel\] CPU utilization high | Alerts when the average CPU utilization of a PostgreSQL instance is at or above 90% of its reserved vCPUs, averaged over the 15-minute rule window, for 3 consecutive checks. Sustained CPU saturation increases query latency for all clients. Applies the PostgreSQL engine marker. Grouped by database_id. |
| \[GCP Cloud SQL PostgreSQL OTel\] Deadlocks detected | Alerts when a PostgreSQL database records 5 or more deadlocks within 15 minutes. PostgreSQL resolves each deadlock by aborting one transaction, so a burst means application requests are failing because of conflicting lock ordering. PostgreSQL-only metric, so no engine marker is needed. Grouped by database_id and database. |
| \[GCP Cloud SQL PostgreSQL OTel\] Disk utilization high | Alerts when the latest disk utilization of a PostgreSQL instance is at or above 90% of its disk quota for 2 consecutive checks. A full disk stops writes. Uses the latest per-minute value in a 15-minute window and the PostgreSQL engine marker. Grouped by database_id. |
| \[GCP Cloud SQL PostgreSQL OTel\] HA standby not available for failover | Alerts when the latest available_for_failover sample of a high-availability (regional) PostgreSQL instance is 0 (the standby cannot take over), for 2 consecutive checks. For fleets with HA instances: available_for_failover is only reported for HA instances, so zonal instances never alert, and if no HA instance has ever reported, the field is unmapped and the rule fails with an "Unknown column" error. Automatic failover events (auto_failover_request_count) are not used because that metric only appears around failovers; a failover can show here while the standby is rebuilt. Applies the PostgreSQL engine marker. Grouped by database_id. |
| \[GCP Cloud SQL PostgreSQL OTel\] Instance down or not running | Alerts when a PostgreSQL instance's latest `up` sample is 0 or its latest `instance_state` is not RUNNING (MAINTENANCE, RUNNABLE/stopped, SUSPENDED, FAILED, UNKNOWN_STATE). Instances that have not reported num_backends in the 24-hour window, such as instances still being created (PENDING_CREATE), are out of scope. The current state is resolved from the last 15 minutes; the PostgreSQL engine marker is evaluated over the 24-hour rule window so a just-stopped instance stays in scope. Requires 3 consecutive breaching runs to ride out short maintenance blips. An instance stopped or deleted for more than 24 hours drops out of scope and recovers. Returns up to 100 instances, grouped by database_id. |
| \[GCP Cloud SQL PostgreSQL OTel\] Instance restarted | Alerts when a PostgreSQL instance started again within the last 30 minutes, detected as a partial `uptime` minute (0 \< uptime \< 58 seconds; running minutes read 59-61) followed by a full minute. The last partial minute before a stop is not counted, and starts within 10 minutes of an owner stop (RUNNABLE) are skipped because the instance down rule covers the stop. Unexpected restarts usually mean an OOM kill or crash; Google maintenance restarts also fire. The engine marker is evaluated over the 1-hour rule window. Each restart keeps the alert active for about 30 minutes, then it recovers. Grouped by database_id. |
| \[GCP Cloud SQL PostgreSQL OTel\] Memory utilization high | Alerts when the average memory utilization (excluding buffer/cache) of a PostgreSQL instance is at or above 90%, averaged over the 15-minute rule window, for 2 consecutive checks. Sustained memory pressure precedes OOM restarts. Requires at least 5 samples and applies the PostgreSQL engine marker. Grouped by database_id. Instances that report a memory quota under 1 GB (shared-core db-f1-micro) are excluded because they report memory pinned at the quota; instances without memory/quota data are still evaluated. |
| \[GCP Cloud SQL PostgreSQL OTel\] Vacuum blocked by old transaction | Alerts when the age of the oldest transaction not yet vacuumed stays at or above 100 million transactions in every sample of the 30-minute rule window, per holder type (running, prepared, replication_slot, replica). This is a leading indicator of bloat and transaction ID wraparound, and the holder type says what to end or drop. The unit is a transaction count, not seconds. PostgreSQL-only metric, so no engine marker is needed. Grouped by database_id and blocker type. |
| \[GCP Cloud SQL PostgreSQL OTel\] Read replica lag high | Alerts when a PostgreSQL read replica stays at least 120 seconds behind its primary in every sample of the 15-minute rule window, for 2 consecutive checks. For fleets with read replicas whose primaries are collected too: the rule needs replica_lag (reported by the replica) and replica_byte_lag with attributes.replica_name (reported by its PostgreSQL primary). Until all three have been collected, they are unmapped and the rule fails with an "Unknown column" error; it does not apply to that fleet. Requires at least 5 lag samples and applies the PostgreSQL engine marker: the replica reports num_backends, or its PostgreSQL primary reports replica_byte_lag for it (replicas that report no PostgreSQL metrics stay covered while the primary reports). MySQL and SQL Server replicas match neither. Grouped by the replica's database_id. |
| \[GCP Cloud SQL PostgreSQL OTel\] Transaction ID wraparound risk | Alerts when transaction ID utilization of a PostgreSQL instance reaches 70% (about 1.5 billion XIDs since the last freeze), the threshold Google suggests for this metric; Google's recommender flags instances at 80%. Near 100%, PostgreSQL forces a read-only shutdown to prevent wraparound. Uses the window peak over 30 minutes; PostgreSQL-only metric, so no engine marker is needed. Some replicas do not report this metric and are not covered. Grouped by database_id. |

</details>

