# Supabase OpenTelemetry Assets

Supabase is an open-source Firebase alternative built on top of PostgreSQL, offering authentication, real-time subscriptions, RESTful APIs, and connection pooling as managed services.

This content package provides dashboards for Supabase metrics and service logs. Metrics are collected via the **Supabase** integration package. Logs are forwarded through [Supabase Log Drains](https://supabase.com/docs/guides/monitoring-and-debugging/log-drains) into an Elastic Cloud [managed endpoint](https://www.elastic.co/docs/reference/opentelemetry/managed-inputs). The assets cover node infrastructure, PostgreSQL database internals, application services (GoTrue, PostgREST, Realtime), and service log streams.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

> **Note**: The managed endpoint used for logs is available on Elastic Cloud Serverless and Elastic Cloud Hosted. It is not available for self-managed, ECE, or ECK clusters. Refer to [Managed inputs](https://www.elastic.co/docs/reference/opentelemetry/managed-inputs).

## Setup

### Metrics

1. A Supabase project with the Observability endpoint enabled.
2. Install the **Supabase** integration package and configure it with your Supabase project credentials.

| Placeholder | Description | Example |
|-------------|-------------|---------|
| `<SUPABASE_METRICS_ENDPOINT>` | Supabase project Observability metrics endpoint | `https://<project-ref>.supabase.co/customer/v1/privileged/metrics` |
| `<SUPABASE_SERVICE_KEY>` | Supabase service role API key for authentication | `eyJhbGciOiJIUzI1NiIs...` |

### Logs

Supabase logs reach Elasticsearch through a [Supabase log drain](https://supabase.com/docs/guides/monitoring-and-debugging/log-drains) that posts OTLP to an Elastic Cloud [managed endpoint](https://www.elastic.co/docs/reference/opentelemetry/managed-inputs). Elastic operates the endpoint, so you do not need to install or run an OpenTelemetry Collector.

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

Logs are written to `logs-supabase.otel-*`.

## Dashboards

| Dashboard | Description |
|-----------|-------------|
| **[Supabase OTel] Node & Infrastructure** | Node-level infrastructure metrics including CPU, memory, disk I/O, filesystem, and network. |
| **[Supabase OTel] Databases & PostgreSQL** | PostgreSQL internals, PgBouncer connection pooling, Go SQL connection pool, replication, and WAL. |
| **[Supabase OTel] Services & API** | Application service metrics for Auth (GoTrue), PostgREST, Realtime, and Go runtime. |
| **[Supabase OTel] Service logs overview** | Deep log stream monitoring for Supabase services — API Gateway, Edge Functions, PostgreSQL, connection pooling, PostgREST, Storage, and Realtime via OpenTelemetry. |

## Alerting Rule Templates
{{alertRuleTemplates}}

## SLO Templates
{{sloTemplates}}
