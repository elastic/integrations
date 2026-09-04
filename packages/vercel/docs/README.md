# Vercel OpenTelemetry Integration

Vercel is a cloud platform for deploying and hosting frontend applications on a globally distributed edge network.

This integration explains how to send Vercel logs, audit logs, Web Analytics, Speed Insights, and traces to Elastic using [Vercel Drains](https://vercel.com/docs/drains) and the Elastic Cloud [managed endpoint](https://www.elastic.co/docs/reference/opentelemetry/managed-inputs). Elastic operates the endpoint, so there is nothing to deploy on your side: no Elastic Agent, no OpenTelemetry Collector, and no agent policy to configure. Follow the setup steps below in your Elastic Cloud project or deployment and in Vercel.

Once data starts flowing, the **[Vercel OpenTelemetry Assets](https://www.elastic.co/docs/reference/integrations/vercel_otel)** package provides assets for logs, audit logs, Web Analytics, and Speed Insights. Traces appear in `traces-generic.otel-*` and can be explored in Discover and in the [Services](https://www.elastic.co/docs/solutions/observability/apm/services) inventory.

## Compatibility

This integration has been tested with Vercel Drains delivering Logs, Audit Log, Web Analytics, and Speed Insights to the Vercel path (`/inputs/vercel/_default_`) of the Elastic Cloud managed endpoint, and with [Trace Drains](https://vercel.com/docs/drains/reference/traces) delivering OpenTelemetry traces to the Managed OTLP traces path (`/v1/traces`).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

> **Note**: The managed endpoint used by this integration is available on Elastic Cloud Serverless and Elastic Cloud Hosted. It is not available for self-managed, ECE, or ECK clusters. Refer to [Managed inputs](https://www.elastic.co/docs/reference/opentelemetry/managed-inputs).

## Setup

Vercel data reaches Elasticsearch through a [Vercel drain](https://vercel.com/docs/drains/using-drains) that posts to an Elastic Cloud [managed endpoint](https://www.elastic.co/docs/reference/opentelemetry/managed-inputs).

Do the following steps in order:

1. Enable the Vercel features you want to collect.
2. Gather the **managed endpoint URL** (and the traces URL, if you collect traces) and an **API key** from Elastic.
3. Create the drains in Vercel using those values.
4. Validate that data is arriving in Elastic.

### Step 1: Enable the Vercel features you want to collect

- **Logs** and **Audit Log**: available through [Vercel Drains](https://vercel.com/docs/drains/using-drains). Log drains require a Pro or Enterprise plan. Audit Log drains require an Enterprise plan.
- **Web Analytics**: install and enable the [@vercel/analytics](https://vercel.com/docs/analytics) SDK in your application so page views and custom events are emitted.
- **Speed Insights**: install and enable the [@vercel/speed-insights](https://vercel.com/docs/speed-insights) SDK in your application so Web Vitals are collected in the browser.
- **Traces**: available through [Trace Drains](https://vercel.com/docs/drains/reference/traces). Trace drains require a Pro or Enterprise plan. Vercel [automatically instruments](https://vercel.com/docs/tracing#automatic-instrumentation) infrastructure spans and outbound HTTP (fetch) spans when a Trace Drain is configured. For framework spans and custom spans, install the [`@vercel/otel`](https://vercel.com/docs/tracing/instrumentation) package.

### Step 2: Gather the managed endpoint URL and API key from Elastic

You need an Elastic Cloud Serverless project or an Elastic Cloud Hosted deployment.

#### Managed endpoint URL for Vercel

In Kibana, go to **Add data** → **More** → **Vercel** and copy the **Vercel endpoint**. The URL follows this pattern:

```text
https://<managed-endpoint>/inputs/vercel/_default_
```

For example:

```text
https://abc123.ingest.us-east-1.aws.elastic.cloud/inputs/vercel/_default_
```

#### Managed endpoint URL for traces

Traces use a different path from the other Vercel drains. They are ingested via the Elastic Cloud [Managed OTLP Endpoint](https://www.elastic.co/docs/reference/opentelemetry/managed-inputs/managed-otlp-endpoint).

Find the Managed OTLP public endpoint:

1. Log in to the [Elastic Cloud Console](https://cloud.elastic.co/).
2. Open your project or deployment and select **Manage**.
3. In **Application endpoints, cluster and component IDs**, select **OpenTelemetry** (Serverless) or **Managed OTLP** (Elastic Cloud Hosted), then copy the public endpoint value.

The traces destination is that public endpoint plus `/v1/traces`:

```text
https://<managed-endpoint>/v1/traces
```

For example, if your Managed OTLP public endpoint is `https://abc123.ingest.us-east-1.aws.elastic.cloud`, then the traces URL is:

```text
https://abc123.ingest.us-east-1.aws.elastic.cloud/v1/traces
```
#### API key

Create an API key in the same view, or follow the [Send data to Elastic Cloud](https://www.elastic.co/docs/solutions/observability/get-started/quickstart-elastic-cloud-otel-endpoint) quickstart, then copy the encoded value. Vercel sends it in an `Authorization` header that must use the `ApiKey` scheme, as described in [Authentication](https://www.elastic.co/docs/reference/opentelemetry/managed-inputs/managed-otlp-endpoint#authentication).

Alternatively, in your Elastic Cloud Serverless project, go to **Add data** → **Applications** → **OpenTelemetry**. That wizard shows the endpoint and generates a pre-configured API key for you.

### Step 3: Create the drains in Vercel

A Vercel drain carries a single data type, so create a separate drain for each of Logs, Audit Log, Web Analytics, Speed Insights, and Traces that you want in Elastic. All drains use the same API key. Logs, Audit Log, Web Analytics, and Speed Insights share the Vercel managed endpoint URL. Traces use the Managed OTLP traces URL instead.

#### Logs, Audit Log, Web Analytics, and Speed Insights

For each of these data types, in Vercel:

1. Open your team **Drains** settings and create a drain for that data type.
2. Choose **Custom Endpoint** as the destination.
3. Set the **Endpoint URL** to the managed endpoint URL for Vercel, for example `https://abc123.ingest.us-east-1.aws.elastic.cloud/inputs/vercel/_default_`.
4. Under **Custom Headers**, add a header named `Authorization` with the value `ApiKey <your-api-key>`, for example `Authorization: ApiKey abc123`.
5. Save the drain.

For Logs drains, you can also narrow which sources, environments, and sampling rates are forwarded under **Additional configuration for logs**. Refer to [Log Drains reference](https://vercel.com/docs/drains/reference/logs).

> **Note**: The managed endpoint URL for Vercel is always your Elastic Cloud public endpoint plus `/inputs/vercel/_default_`. Do not point the drain at a self-hosted collector; the supported path is the Elastic Cloud managed endpoint.

#### Traces

For traces, in Vercel:

1. Open your team **Drains** settings and create a drain of type **Traces**.
2. Choose **Custom Endpoint** as the destination.
3. Set the **Endpoint URL** to the Managed OTLP traces URL, for example `https://abc123.ingest.us-east-1.aws.elastic.cloud/v1/traces`.
4. Choose **Protobuf** or **JSON** as the delivery format. Both are sent over OTLP/HTTP.
5. Under **Custom Headers**, add a header named `Authorization` with the value `ApiKey <your-api-key>`, for example `Authorization: ApiKey abc123`.
6. Save the drain.

### Step 4: Validate that data is arriving

In Kibana, open **Discover** and query the data streams listed in [Reference](#reference), for example `logs-vercel.logs.otel-*` or `traces-generic.otel-*`. Vercel delivers drain payloads in batches, so allow a few minutes after saving a drain and generating traffic before the first documents appear.

To see the full request flow for traces, open **Applications** → **Service inventory** in Kibana. Services appear after they send spans in the selected time range. From a service you can open traces, related logs, and service maps. Refer to [Services](https://www.elastic.co/docs/solutions/observability/apm/services).

## Reference

Vercel drain payloads are decoded by the Elastic Cloud managed endpoint and written to the data streams below. Each data type has its own payload schema, documented by Vercel, and those fields are what you query in Elastic. For drain configuration on the Vercel side, see [Using drains](https://vercel.com/docs/drains/using-drains). For managed endpoint behavior, see [Managed inputs](https://www.elastic.co/docs/reference/opentelemetry/managed-inputs).

### Metrics

| Signal | Data stream | Fields |
|--------|-------------|--------|
| Speed Insights | `metrics-vercel.speedinsights.v1.otel-*` | [Speed Insights Drains reference](https://vercel.com/docs/drains/reference/speed-insights) |

Speed Insights carries Web Vitals (LCP, INP, CLS, TTFB) and their related attributes, such as route, device, and country.

### Logs

| Signal | Data stream | Fields |
|--------|-------------|--------|
| Logs | `logs-vercel.logs.otel-*` | [Log Drains reference](https://vercel.com/docs/drains/reference/logs) |
| Audit logs | `logs-vercel.auditlog.v1.otel-*` | [Audit Log Drains reference](https://vercel.com/docs/drains/reference/audit-logs) |
| Web Analytics | `logs-vercel.analytics.v2.otel-*` | [Analytics Drains reference](https://vercel.com/docs/drains/reference/analytics) |

The Logs data stream holds every source selected on the drain, so it covers build output and static asset requests alongside function output from the `lambda` and `edge` runtimes.

### Traces

| Signal | Data stream | Fields |
|--------|-------------|--------|
| Traces | `traces-generic.otel-*` | [Trace Drains reference](https://vercel.com/docs/drains/reference/traces) |


Traces land in the generic OpenTelemetry traces data stream. Use **Discover** on `traces-generic.otel-*` to inspect individual spans, and use **Applications** → **Service inventory** for the complete service-level view of those traces.

To see how a payload field is indexed, open the data stream in **Discover** and inspect a document, or check the data stream mappings in **Stack Management** → **Index Management**.

