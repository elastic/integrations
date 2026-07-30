# Vercel OpenTelemetry Assets

Vercel is a cloud platform for deploying and hosting frontend applications on a globally distributed edge network.

The Vercel OpenTelemetry assets provide dashboards for runtime logs, audit logs, web analytics, and Speed Insights ingested through Vercel Log Drains into an Elastic Cloud [managed input](https://www.elastic.co/docs/reference/opentelemetry/managed-inputs), covering server-side health, user experience, traffic and engagement, and team governance.

## Compatibility

The Vercel OpenTelemetry assets have been tested with Vercel Log Drains / Observability drains posting to the Elastic Cloud [Managed OTLP Endpoint](https://www.elastic.co/docs/reference/opentelemetry/managed-inputs/managed-otlp-endpoint) Vercel path (`/vercel`).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage
the Elastic Stack on your own hardware.

> **Note**: Managed inputs, including the Managed OTLP Endpoint used by this content pack, are available on Elastic Cloud Serverless and Elastic Cloud Hosted. They are not available for self-managed, ECE, or ECK clusters. Refer to [Managed inputs](https://www.elastic.co/docs/reference/opentelemetry/managed-inputs).

## Setup

### Prerequisites

Configure the observability features you want to forward on the Vercel side before creating the drain:

- **Logs** and **Audit Logs**: Available through [Vercel Drains](https://vercel.com/docs/drains/using-drains). Log drains require a Pro or Enterprise plan. Audit Log drains require an Enterprise plan.
- **Web Analytics**: Install and enable the [@vercel/analytics](https://vercel.com/docs/analytics) SDK in your application so page views and custom events are emitted.
- **Speed Insights**: Install and enable the [@vercel/speed-insights](https://vercel.com/docs/speed-insights) SDK in your application so Web Vitals are collected in the browser.

You also need an Elastic Cloud Serverless project or Elastic Cloud Hosted deployment, plus an API key that can authenticate to the Managed OTLP Endpoint. Refer to [Authentication](https://www.elastic.co/docs/reference/opentelemetry/managed-inputs/managed-otlp-endpoint#authentication) for the required `event:write` privilege on the `apm` application.

### Configuration

Vercel data is ingested through an Elastic Cloud [managed input](https://www.elastic.co/docs/reference/opentelemetry/managed-inputs): the [Managed OTLP Endpoint](https://www.elastic.co/docs/reference/opentelemetry/managed-inputs/managed-otlp-endpoint). Elastic operates the ingest endpoint, so you do not need to install or run an OpenTelemetry Collector yourself.

To send Vercel drains to Elastic, point a custom Vercel drain at the Managed OTLP Endpoint **Vercel path** (`/vercel`), authenticated with an API key from Kibana / Elastic Cloud.

#### 1. Find your Managed OTLP Endpoint

Follow the steps for your environment in [Find your Elastic Cloud Managed OTLP Endpoint](https://www.elastic.co/docs/reference/opentelemetry/managed-inputs/managed-otlp-endpoint#find-your-elastic-cloud-managed-otlp-endpoint), or:

1. Log in to the [Elastic Cloud Console](https://cloud.elastic.co/).
2. Open your project or hosted deployment and select **Manage**.
3. In **Application endpoints, cluster and component IDs**, select **OpenTelemetry** (Serverless) or **Managed OTLP** (Hosted).
4. Copy the **Public endpoint** value.

Alternatively, from within your project, go to **Add data** → **Applications** → **OpenTelemetry** and copy the endpoint. That wizard can also generate a pre-configured API key.

#### 2. Create an API key

Create an API key with the Managed OTLP Endpoint privileges described in the [quickstart](https://www.elastic.co/docs/solutions/observability/get-started/quickstart-elastic-cloud-otel-endpoint) (minimum: `event:write` for the `apm` application). Copy the encoded API key value for use in Vercel.

#### 3. Build the Vercel custom endpoint URL

Append `/vercel` to your Managed OTLP public endpoint:

```text
https://<motlp-endpoint>/vercel
```

**Example** (replace with your own public endpoint):

```text
https://abc123.ingest.us-east-1.aws.elastic.cloud/vercel
```

Each deployment has its own host. Always use the public endpoint from your Elastic Cloud project or deployment, then append `/vercel`.

#### 4. Configure the drain in Vercel

1. In Vercel, open your team **Drains** settings and create a custom Log Drain / Observability drain.
2. Set the drain endpoint URL to the full custom endpoint from step 3 (`…/vercel`).
3. Authenticate using the API key from step 2. The Managed OTLP Endpoint expects `Authorization: ApiKey <your-api-key>` (see [Authentication](https://www.elastic.co/docs/reference/opentelemetry/managed-inputs/managed-otlp-endpoint#authentication)).
4. Select the data types to forward: Logs, Audit Logs, Web Analytics, and/or Speed Insights.

> **Note**: The custom endpoint to configure in Vercel is always `<Managed OTLP public endpoint>/vercel`. Do not point the drain at a self-hosted collector for this content pack; the supported path is the Elastic Cloud managed input.

## Reference

Vercel drain payloads are decoded by the Elastic Cloud Managed OTLP Endpoint and written to the data streams below. For drain configuration and payload types on the Vercel side, see [Using drains](https://vercel.com/docs/drains/using-drains). For Managed OTLP Endpoint behavior, see [Managed inputs](https://www.elastic.co/docs/reference/opentelemetry/managed-inputs).

### Metrics

Speed Insights Web Vitals (LCP, INP, CLS, TTFB, and related attributes) are stored in the `metrics-vercel.speedinsights.v1.otel-*` data stream.

### Logs

| Signal | Data stream |
|--------|-------------|
| Runtime logs | `logs-vercel.logs.otel-*` |
| Audit logs | `logs-vercel.auditlog.v1.otel-*` |
| Web Analytics | `logs-vercel.analytics.v2.otel-*` |

## Dashboards

| Dashboard | Description |
|-----------|-------------|
| **[Vercel OTel] Logs** | Server-side health overview covering request volume, error rates, HTTP status distribution, log sources, regions, and top routes. |
| **[Vercel OTel] Audit Logs** | Governance and security overview of audit event volume, actors, top event types, user activity, and sensitive operations. |
| **[Vercel OTel] Web Analytics** | Traffic and engagement overview covering page views, geography, devices, top pages, and custom events. |
| **[Vercel OTel] Speed Insights** | Web Vitals performance overview tracking LCP, INP, CLS, and TTFB at the p75 benchmark over time and per page. |
