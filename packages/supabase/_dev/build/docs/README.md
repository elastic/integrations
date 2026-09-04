# Supabase OpenTelemetry Integration

[Supabase](https://supabase.com) is an open-source Firebase alternative built on PostgreSQL. It bundles a managed Postgres database with authentication, auto-generated REST APIs, realtime subscriptions, file storage, and connection pooling.

## Overview

This integration scrapes metrics from the Supabase Metrics API (Prometheus-compatible) using the OTel Collector's Prometheus receiver. Logs are forwarded through Supabase Log Drains into an Elastic Cloud [managed endpoint](https://www.elastic.co/docs/reference/opentelemetry/managed-inputs). Elastic operates the endpoint for logs, so you do not need to install or run an OpenTelemetry Collector.

- **Metrics** (`supabase.metrics.otel`) — Infrastructure (CPU, memory, load, disk I/O, filesystem, network), PostgreSQL (size, connections, transactions, cache, WAL, replication, bgwriter, statements), Supavisor, PostgREST, Auth, Realtime, and Storage
- **Logs** (`supabase.otel`) — API Gateway, PostgreSQL, PostgREST, Edge Functions, Storage, Realtime, and connection pooling

Metrics are stored with native OTel schema — no field renaming or custom mapping is applied. Raw Prometheus metric names are preserved under the `metrics.*` namespace.

Once data starts flowing, the **[Supabase OpenTelemetry Assets](https://www.elastic.co/docs/reference/integrations/supabase_otel)** package provides dashboards for infrastructure, PostgreSQL, application services, and service logs.

## Compatibility

This integration requires a Supabase **Pro**, **Team**, or **Enterprise** plan. The Metrics API and Log Drains are not available on the Free tier.

The log drain path has been tested with Supabase Log Drains delivering OTLP logs to `/inputs/supabase/_default_/v1/logs` on the Elastic Cloud managed endpoint.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

> **Note**: The managed endpoint used for logs is available on Elastic Cloud Serverless and Elastic Cloud Hosted. It is not available for self-managed, ECE, or ECK clusters. Refer to [Managed inputs](https://www.elastic.co/docs/reference/opentelemetry/managed-inputs).

## Prerequisites

| Requirement | Details |
|---|---|
| **Supabase plan** | Pro, Team, or Enterprise |
| **Elastic Stack** | 9.4.0+ |
| **Input package** | `prometheus_input_otel` (installed automatically as a dependency) |
| **Content package** | `supabase_otel` (installed automatically as a dependency) |

## Setup

### Metrics

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

### Logs

Supabase logs reach Elasticsearch through a [Supabase log drain](https://supabase.com/docs/guides/monitoring-and-debugging/log-drains) that posts OTLP to an Elastic Cloud [managed endpoint](https://www.elastic.co/docs/reference/opentelemetry/managed-inputs).

Setup has three parts, done in order:

1. Enable Supabase Log Drains.
2. Gather a **managed endpoint URL** and an **API key** from Elastic.
3. Create the log drain in Supabase.

#### Step 1: Enable Supabase Log Drains

**Logs** are available through [Supabase Log Drains](https://supabase.com/docs/guides/monitoring-and-debugging/log-drains). Log drains require a Pro, Team, or Enterprise plan.

#### Step 2: Gather the managed endpoint URL and API key from Elastic

In Kibana, go to **Add data** → **More** → **Supabase** and copy the **Supabase logs endpoint**. The URL follows this pattern:

```text
https://<managed-endpoint>/inputs/supabase/_default_/v1/logs
```

For example:

```text
https://abc123.ingest.us-east-1.aws.elastic.cloud/inputs/supabase/_default_/v1/logs
```

Create an API key in the same view, or follow the [Send data to Elastic Cloud](https://www.elastic.co/docs/solutions/observability/get-started/quickstart-elastic-cloud-otel-endpoint) quickstart. Supabase sends it as `Authorization: ApiKey <your-api-key>`.

#### Step 3: Create the log drain in Supabase

1. Open **Project Settings** → **Log Drains** and create a drain.
2. Choose **OpenTelemetry (OTLP)** as the destination.
3. Set **Endpoint** to the Supabase logs endpoint URL, for example `https://abc123.ingest.us-east-1.aws.elastic.cloud/inputs/supabase/_default_/v1/logs`.
4. Set **Protocol** to `http/protobuf` and enable **Gzip**.
5. Add header `Authorization: ApiKey <your-api-key>`.
6. Save the drain.

> **Note**: The managed endpoint URL for logs from Supabase is always your Elastic Cloud public endpoint plus `/inputs/supabase/_default_/v1/logs`. Do not point the drain at a self-hosted collector; the supported path is the Elastic Cloud managed endpoint.

### Verify data

In **Discover**:
- Metrics: `data_stream.dataset: "supabase.metrics.otel"`
- Logs: `data_stream.dataset: "supabase.otel"`

## Reference

Supabase metrics are scraped by this integration. Log drain payloads are decoded by the Elastic Cloud managed endpoint and written to the data streams below. For log drain configuration on the Supabase side, see [Log Drains](https://supabase.com/docs/guides/monitoring-and-debugging/log-drains). For managed endpoint behavior, see [Managed inputs](https://www.elastic.co/docs/reference/opentelemetry/managed-inputs).

### Metrics

| Signal | Data stream | Fields |
|--------|-------------|--------|
| Metrics | `metrics-supabase.metrics.otel-*` | [Supabase Metrics documentation](https://supabase.com/docs/guides/telemetry/metrics) |

Metrics are scraped from the Supabase Metrics API endpoint:

```
GET https://<project-ref>.supabase.co/customer/v1/privileged/metrics
```

Authentication uses HTTP Basic Auth with `service_role` as the username and the service_role JWT as the password.

See the [Supabase Metrics documentation](https://supabase.com/docs/guides/telemetry/metrics) for full details on available metrics.

#### Metric Categories

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

### Logs

| Signal | Data stream | Fields |
|--------|-------------|--------|
| Logs | `logs-supabase.otel-*` | [Supabase Log Drains](https://supabase.com/docs/guides/monitoring-and-debugging/log-drains) |

The Logs data stream holds every service forwarded by the drain. Use the **Service** filter on the Service logs overview dashboard to focus on a single service.
