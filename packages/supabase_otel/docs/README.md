# Supabase OpenTelemetry Assets

Supabase is an open-source Firebase alternative built on top of PostgreSQL, offering authentication, real-time subscriptions, RESTful APIs, and connection pooling as managed services.

This content package provides dashboards for Supabase metrics and service logs collected via the **[Supabase](https://www.elastic.co/docs/reference/integrations/supabase)** integration package. The assets cover node infrastructure, PostgreSQL database internals, application services (GoTrue, PostgREST, Realtime), and service log streams.


## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Setup

### Prerequisites

1. A Supabase project with the Observability endpoint enabled. The endpoint exposes Prometheus-format metrics for infrastructure, PostgreSQL, and application services.

2. Install the **Supabase** integration package and configure it with your Supabase project credentials. This content package provides dashboards that visualize data collected by that integration, including service logs forwarded via [Supabase Log Drains](https://supabase.com/docs/guides/monitoring-and-debugging/log-drains).

### Configuration

Configure the Supabase Integration Package to scrape your Supabase Prometheus endpoint and export to Elasticsearch.

| Placeholder | Description | Example |
|-------------|-------------|---------|
| `<SUPABASE_METRICS_ENDPOINT>` | Supabase project Observability metrics endpoint | `https://<project-ref>.supabase.co/customer/v1/privileged/metrics` |
| `<SUPABASE_SERVICE_KEY>` | Supabase service role API key for authentication | `eyJhbGciOiJIUzI1NiIs...` |


## Dashboards

| Dashboard | Description |
|-----------|-------------|
| **[Supabase OTel] Node & Infrastructure** | Node-level infrastructure metrics including CPU, memory, disk I/O, filesystem, and network. |
| **[Supabase OTel] Databases & PostgreSQL** | PostgreSQL internals, PgBouncer connection pooling, Go SQL connection pool, replication, and WAL. |
| **[Supabase OTel] Services & API** | Application service metrics for Auth (GoTrue), PostgREST, Realtime, and Go runtime. |


## Alerting Rule Templates
Alert rule templates provide pre-defined configurations for creating alert rules in Kibana.

For more information, refer to the [Elastic documentation](https://www.elastic.co/docs/reference/fleet/alerting-rule-templates).

Alert rule templates require Elastic Stack version 9.2.0 or later.

**The following alert rule templates are available:**

<details>
<summary>View the alert rule templates</summary>

| Name | Description |
|---|---|
| [Supabase OTel] Auth API server errors | Fires when a meaningful share of Auth (GoTrue) API requests return 5xx. Client errors are excluded: 4xx is routine for authentication flows (bad passwords, expired tokens) and is carried as context only. |
| [Supabase OTel] Auth service is down | Fires when the GoTrue (Auth) liveness gauge reports 0 for a Supabase project. With Auth down, no user can sign in or refresh a token even though the database and REST API may look healthy. |
| [Supabase OTel] Disk IO saturation | Fires when a disk device on the project node is busy for nearly all of the evaluation window. Disk IO is the most commonly exhausted resource on smaller Supabase compute tiers, and its exhaustion cascades into slower queries, connections held longer, and pool exhaustion. |
| [Supabase OTel] Filesystem nearly full | Fires when a filesystem on the project node is running out of space. The data volume filling up stops database writes; the root volume filling up breaks the platform. WAL accumulation and pinned replication slots are the usual non-obvious causes. |
| [Supabase OTel] Filesystem is read-only | Fires when a filesystem on the project node has been remounted read-only. PostgreSQL cannot write, so this is terminal for the project until the volume is recovered. |
| [Supabase OTel] Host CPU saturation | Fires when CPU utilisation on the project node stays near 100% across the evaluation window. Compute tiers fix the core count, and on the small core counts typical of lower tiers queries start queueing for CPU well before anything else looks wrong. |
| [Supabase OTel] Host memory pressure | Fires when available memory on the project node falls to a small fraction of total memory. Low available memory squeezes the PostgreSQL buffer cache, which amplifies disk IO, and is the precursor to an OOM kill. |
| [Supabase OTel] Host OOM kill detected | Fires when the kernel OOM killer terminates a process on the project node. A single occurrence means a component was killed rather than degraded, and is never expected in normal operation. |
| [Supabase OTel] Long-running transaction | Fires when the oldest open transaction exceeds a duration threshold. Long-lived transactions hold locks, block vacuum and pin WAL, so this is simultaneously a latency signal, a saturation signal and a disk-space risk. |
| [Supabase OTel] Metrics collection is failing | Fires when the exporters that produce this data report a scrape failure. This is a monitoring-health rule: while it is active, the absence of every other alert in this package stops being evidence that the project is healthy. |
| [Supabase OTel] PgBouncer clients queueing for connections | Fires when clients spend a sustained amount of time waiting for a server connection in a PgBouncer pool. A pool can be fully checked out and perfectly healthy provided nothing is queueing behind it, so wait time rather than pool occupancy is the definitive pressure signal. |
| [Supabase OTel] PgBouncer is down | Fires when the PgBouncer availability gauge reports 0 for a Supabase project. With the dedicated pooler down, clients fall back to connecting directly to PostgreSQL and can exhaust the connection budget within minutes. |
| [Supabase OTel] PostgreSQL connection budget nearly exhausted | Fires when the backends PostgreSQL reports approach the max_connections ceiling set by the compute tier. Connection exhaustion is the single most common way a Supabase project fails: once the ceiling is reached, new clients are refused outright. Utilisation is measured from pg_stat_database_num_backends rather than the pooler-reported counts, because that is the number PostgreSQL enforces the ceiling against and it is the only one that also includes direct clients, the exporter and platform utilities. |
| [Supabase OTel] PostgreSQL deadlocks detected | Fires when PostgreSQL records any deadlock. Deadlocks are application or schema bugs rather than capacity problems, so the remediation owner differs from every other rule in this package and the threshold is any occurrence. |
| [Supabase OTel] PostgreSQL is down | Fires when the PostgreSQL availability gauge reports 0 for a Supabase project, meaning the exporter could not reach the database. Every other service in the project is a client of this database, so this is the highest-priority signal. |
| [Supabase OTel] PostgreSQL restarted | Fires when the PostgreSQL restart counter increases, meaning the database bounced. A point-in-time availability check can miss a restart entirely, so this rule catches the bounce even when pg_up never appeared as 0. |
| [Supabase OTel] PostgREST database pool timeouts | Fires when PostgREST records database pool timeouts. Every increment is an API request that gave up waiting for a database connection, so this is a user-visible failure and the highest-signal PostgREST error metric. |
| [Supabase OTel] Replication lag is high | Fires when physical replication lag exceeds a freshness target, meaning a read replica is serving materially stale data. Guards the -1 sentinel that these gauges report when no replica is attached, so projects without replication never breach. |
| [Supabase OTel] Replication slot retaining WAL | Fires when a replication slot is retaining a large volume of WAL. An inactive slot pins WAL indefinitely and will eventually fill the data volume, which makes slot lag a disk-space risk rather than only a replication concern. |
| [Supabase OTel] Supavisor pool exhausted | Fires when at least 95% of a Supavisor pool's open connections are checked out, leaving almost nothing for the next client. Covers projects on the shared pooler, which emit no PgBouncer series at all. |

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
| [Supabase OTel] Database availability 99.5% rolling 30 days | Tracks availability of the project's PostgreSQL instance, which every other Supabase surface (REST, Auth, Realtime, direct SQL and the poolers) depends on. pg_up is a gauge reporting 1 when the database accepts a connection and answers a query, and 0 when it does not. A 5-minute timeslice is good only when every scrape in that window reported the database up, so a single failed scrape marks the whole timeslice bad; the SLO requires 99.5% of timeslices to be good over a rolling 30 days. Scrape gaps produce no data rather than a breach, so a paused project does not consume budget. This SLO owns the rolling availability budget; the acute 'database is down right now' condition is owned by an alert rule. |
| [Supabase OTel] Mean database query latency 99.5% rolling 30 days | Tracks mean query execution time for the project's database, derived from the two cumulative pg_stat_statements counters: total execution time in seconds over total queries executed. Because everything a Supabase project serves is a client of this one database, mean query time is the closest project-wide latency signal available and is the usual root cause behind 'the API is slow'. A 5-minute timeslice is good when mean execution time stayed at or below the 50 millisecond threshold, and the SLO requires 99.5% of timeslices to be good over a rolling 30 days. Both counters are cumulative, so each becomes a per-timeslice delta via max() - min(), and the equation scales the seconds-valued time delta by 1000 so the threshold reads directly in milliseconds. A timeslice in which no queries ran at all divides by zero, which Kibana records as no data rather than as a success, so quiet periods neither consume nor credit error budget. Two caveats when reading this SLO. It is a call-weighted mean across every statement, so frequent cheap queries dominate and a few important queries degrading badly will move it only slightly; there is no request-duration histogram in this data, so no percentile is available as an alternative. And a pg_stat_reset() inside a timeslice inflates both deltas toward their lifetime totals, so that slice reports the lifetime mean rather than the window mean. The 50 ms bar is a conservative starting point and should be recalibrated to the application's own query mix. |
| [Supabase OTel] REST API requests free of connection pool timeouts 99.5% rolling 30 days | Tracks whether the PostgREST data API is able to serve requests without exhausting its database connection pool. Every increment of pgrst_db_pool_timeouts_total is an API request that waited longer than db-pool-acquisition-timeout for a connection and was aborted with HTTP 504, so it is a directly user-visible failure. A 5-minute timeslice is good when no new pool timeout occurred; the SLO requires 99.5% of timeslices to be good over a rolling 30 days. The counter is a cumulative Sum, so the per-timeslice increment is taken as max()-min(). Timeslices in which PostgREST reports no data at all are treated as no data rather than as breaches, so projects that do not expose the REST API do not consume budget. Known limitation: a PostgREST restart resets the counter to zero, so max()-min() inside the restart timeslice returns the whole pre-restart total and marks that one timeslice bad even though no request timed out. The available SLO indicator types cannot express a reset-aware delta, so this cannot be filtered out. The cost is bounded and small — a 30-day rolling window holds 8640 five-minute timeslices and 99.5% allows 43 bad ones, so each restart spends about 2.3% of the error budget and roughly 43 restarts in one window would exhaust it on deploys alone. Projects that deploy more often than that should either lengthen the timeslice window or track this rule-side instead, where the ES|QL INCREASE() function handles resets correctly. |
| [Supabase OTel] Database transaction commit ratio 99.5% rolling 30 days | Tracks the share of database transactions that roll back rather than commit, using the cumulative pg_stat_database counters for committed and rolled back transactions. The equation computes the rollback share of all transactions in the window, so a 5-minute timeslice is good while that share stays at or below the 0.05 threshold, meaning at least 95% of transactions committed. The SLO requires 99.5% of timeslices to be good over a rolling 30 days. Both counters are cumulative, so each becomes a per-timeslice delta via max() - min(). A timeslice in which no transactions ran at all divides by zero, which Kibana records as no data rather than as a success, so quiet periods neither consume nor credit error budget. Calibrate before deploying. A rollback is not necessarily an error on this platform — PostgREST wraps every API request in a transaction, so RLS denials, constraint violations and requests that legitimately return 4xx all roll back, and ORMs roll back read-only transactions. Every application therefore has its own baseline rollback rate, part of it deliberate. The 5% bar is a conservative 'clearly wrong' line rather than a target, and should be tightened to sit just above the project's observed baseline once that is known. |

</details>


