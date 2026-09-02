# Supabase OpenTelemetry Integration

Collect metrics from [Supabase](https://supabase.com) using the OpenTelemetry Prometheus receiver.

## Overview

This integration scrapes metrics from the Supabase Metrics API (Prometheus-compatible) using the OTel Collector's Prometheus receiver. All metrics are collected into a single data stream

- **Metrics** (`supabase.metrics.otel`) — Infrastructure (CPU, memory, load, disk I/O, filesystem, network), PostgreSQL (size, connections, transactions, cache, WAL, replication, bgwriter, statements), Supavisor, PostgREST, Auth, Realtime, and Storage

Metrics are stored with native OTel schema — no field renaming or custom mapping is applied. Raw Prometheus metric names are preserved under the `metrics.*` namespace.

Once data starts flowing, the **[Supabase OpenTelemetry Assets](https://www.elastic.co/docs/reference/integrations/supabase_otel)** package provides assets for infrastructure, PostgreSQL, and application services.

## Compatibility

This integration requires a Supabase **Pro**, **Team**, or **Enterprise** plan. The Metrics API is not available on the Free tier.

## Prerequisites

| Requirement | Details |
|---|---|
| **Supabase plan** | Pro, Team, or Enterprise |
| **Elastic Stack** | 9.4.0+ |
| **Input package** | `prometheus_input_otel` (installed automatically as a dependency) |
| **Content package** | `supabase_otel` (installed automatically as a dependency) |

## Setup

1. **Get your Supabase credentials**:
   - Go to your Supabase dashboard → **Settings** → **API**
   - Copy the **Project URL** (e.g., `abcdefghijkl.supabase.co`)
   - Copy the **service_role** key (under "Project API keys")

2. **Add the integration in Kibana**:
   - Go to **Management** → **Integrations** → search for "Supabase"
   - Click **Add Supabase**
   - Fill in:
     - **Targets**: `<your-project-ref>.supabase.co:443`
     - **Username**: `service_role`
     - **Service Role Key**: paste your service_role JWT

3. **Verify data**:
   - Go to **Discover** and filter on `data_stream.dataset: "supabase.metrics.otel"`

## Metrics Reference

Metrics are scraped from the Supabase Metrics API endpoint:

```
GET https://<project-ref>.supabase.co/customer/v1/privileged/metrics
```

Authentication uses HTTP Basic Auth with `service_role` as the username and the service_role JWT as the password.

See the [Supabase Metrics documentation](https://supabase.com/docs/guides/telemetry/metrics) for full details on available metrics.

### Metric Categories

| Category | Prefix | Examples |
|---|---|---|
| Node / Infrastructure | `node_*` | `node_cpu_seconds_total`, `node_memory_MemAvailable_bytes`, `node_load5`, `node_disk_read_bytes_total` |
| PostgreSQL | `pg_*` | `pg_stat_database_xact_commit_total`, `pg_database_size_mb`, `pg_stat_bgwriter_buffers_alloc_total` |
| Supavisor | `supavisor_*` | `supavisor_connections_active`, `supavisor_pool_connections_idle`, `supavisor_client_queries_count_total` |
| PostgREST | `pgrst_*` | `pgrst_db_pool_available`, `pgrst_db_pool_timeouts_total`, `pgrst_schema_cache_query_time_seconds` |
| Auth (GoTrue) | `gotrue_*` | `gotrue_running`, `gotrue_compare_hash_and_password_completed_total` |
| Realtime | `realtime_*` | `realtime_postgres_changes_client_subscriptions` |
| Go Runtime | `go_*`, `process_*` | `go_goroutines`, `process_cpu_seconds_total`, `process_resident_memory_bytes` |
| HTTP | `http_*` | `http_server_request_duration_seconds_total`, `http_status_codes_total` |

All metrics are stored under the `metrics.*` field namespace with their original Prometheus names (e.g., `metrics.node_load5`, `metrics.pg_stat_database_xact_commit_total`).
