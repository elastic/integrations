# Supabase OpenTelemetry Assets

Supabase is an open-source Firebase alternative built on top of PostgreSQL, offering authentication, real-time subscriptions, RESTful APIs, and connection pooling as managed services.

This content package provides dashboards for Supabase projects monitored via the OpenTelemetry Prometheus receiver. The assets cover three observability tiers: node infrastructure, PostgreSQL database internals, and application services (GoTrue, PostgREST, Realtime).


## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Setup

### Prerequisites

1. A Supabase project with the Observability endpoint enabled. The endpoint exposes Prometheus-format metrics for infrastructure, PostgreSQL, and application services.

2. Install the **Supabase** integration package and configure it with your Supabase project credentials. This content package provides dashboards that visualize data collected by that integration.

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
