# Vercel OpenTelemetry Assets

Vercel is a cloud platform for deploying and hosting frontend applications on a globally distributed edge network.

The Vercel OpenTelemetry assets provide dashboards for Vercel logs, audit logs, Web Analytics, and Speed Insights forwarded through [Vercel Drains](https://vercel.com/docs/drains) into an Elastic Cloud [managed endpoint](https://www.elastic.co/docs/reference/opentelemetry/managed-inputs), covering server-side health, user experience, traffic and engagement, and team governance.

## Compatibility

The Vercel OpenTelemetry assets have been tested with Vercel Drains delivering to the Vercel path (`/vercel`) of the Elastic Cloud managed endpoint.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage
the Elastic Stack on your own hardware.

> **Note**: The managed endpoint used by these assets is available on Elastic Cloud Serverless and Elastic Cloud Hosted. It is not available for self-managed, ECE, or ECK clusters. Refer to [Managed inputs](https://www.elastic.co/docs/reference/opentelemetry/managed-inputs).

## Setup

Vercel data reaches Elasticsearch through a [Vercel drain](https://vercel.com/docs/drains/using-drains) that posts to an Elastic Cloud [managed endpoint](https://www.elastic.co/docs/reference/opentelemetry/managed-inputs). Elastic operates the endpoint, so you do not need to install or run an OpenTelemetry Collector.

Setup has three parts, done in order:

1. Enable the Vercel features you want to collect.
2. Gather two values from Elastic: a **drain URL** and an **API key**.
3. Create the drains in Vercel using those two values.

### Step 1: Enable the Vercel features you want to collect

- **Logs** and **Audit Log**: available through [Vercel Drains](https://vercel.com/docs/drains/using-drains). Log drains require a Pro or Enterprise plan. Audit Log drains require an Enterprise plan.
- **Web Analytics**: install and enable the [@vercel/analytics](https://vercel.com/docs/analytics) SDK in your application so page views and custom events are emitted.
- **Speed Insights**: install and enable the [@vercel/speed-insights](https://vercel.com/docs/speed-insights) SDK in your application so Web Vitals are collected in the browser.

### Step 2: Gather the drain URL and API key from Elastic

You need an Elastic Cloud Serverless project or an Elastic Cloud Hosted deployment.

#### Drain URL

Find your Elastic Cloud public endpoint:

1. Log in to the [Elastic Cloud Console](https://cloud.elastic.co/).
2. Open your project or deployment and select **Manage**.
3. In **Application endpoints, cluster and component IDs**, select **OpenTelemetry** (Serverless projects) or **Managed OTLP** (Hosted deployments), then copy the public endpoint value.

The drain URL is that public endpoint plus `/vercel`, which is the path that accepts Vercel drain payloads:

```text
https://<managed-endpoint>/vercel
```

For example, if your public endpoint is `https://abc123.ingest.us-east-1.aws.elastic.cloud`, then the drain URL is:

```text
https://abc123.ingest.us-east-1.aws.elastic.cloud/vercel
```

Every project and deployment has its own host, so always build the drain URL from the endpoint shown in your own Elastic Cloud project or deployment. Refer to [Find your endpoint](https://www.elastic.co/docs/reference/opentelemetry/managed-inputs/managed-otlp-endpoint#find-your-elastic-cloud-managed-otlp-endpoint) for more detail.

#### API key

Create an API key by following the [Send data to Elastic Cloud](https://www.elastic.co/docs/solutions/observability/get-started/quickstart-elastic-cloud-otel-endpoint) quickstart, then copy the encoded value. Vercel sends it in an `Authorization` header that must use the `ApiKey` scheme, as described in [Authentication](https://www.elastic.co/docs/reference/opentelemetry/managed-inputs/managed-otlp-endpoint#authentication).

Alternatively, in your Elastic Cloud Serverless project, go to **Add data** → **Applications** → **OpenTelemetry**. That wizard shows the endpoint and generates a pre-configured API key for you.

### Step 3: Create the drains in Vercel

A Vercel drain carries a single data type, so create a separate drain for each of Logs, Audit Log, Web Analytics, and Speed Insights that you want in Elastic. All of them use the same drain URL and API key.

For each data type, in Vercel:

1. Open your team **Drains** settings and create a drain for that data type.
2. Choose **Custom Endpoint** as the destination.
3. Set the **Endpoint URL** to the drain URL, for example `https://abc123.ingest.us-east-1.aws.elastic.cloud/vercel`.
4. Under **Custom Headers**, add a header named `Authorization` with the value `ApiKey <your-api-key>`, for example `Authorization: ApiKey abc123`.
5. Save the drain.

For Logs drains, you can also narrow which sources, environments, and sampling rates are forwarded under **Additional configuration for logs**. Refer to [Log Drains reference](https://vercel.com/docs/drains/reference/logs).

> **Note**: The drain URL is always your Elastic Cloud public endpoint plus `/vercel`. Do not point the drain at a self-hosted collector for these assets; the supported path is the Elastic Cloud managed endpoint.

## Reference

Vercel drain payloads are decoded by the Elastic Cloud managed endpoint and written to the data streams below. For drain configuration and payload types on the Vercel side, see [Using drains](https://vercel.com/docs/drains/using-drains). For managed endpoint behavior, see [Managed inputs](https://www.elastic.co/docs/reference/opentelemetry/managed-inputs).

### Metrics

Speed Insights Web Vitals (LCP, INP, CLS, TTFB, and related attributes) are stored in the `metrics-vercel.speedinsights.v1.otel-*` data stream.

### Logs

| Signal | Data stream |
|--------|-------------|
| Logs | `logs-vercel.logs.otel-*` |
| Audit logs | `logs-vercel.auditlog.v1.otel-*` |
| Web Analytics | `logs-vercel.analytics.v2.otel-*` |

The Logs data stream holds every source selected on the drain, so it covers build output and static asset requests alongside function output from the `lambda` and `edge` runtimes. Use the **Log Source** filter on the Logs dashboard to focus on a single source.

## Dashboards

| Dashboard | Description |
|-----------|-------------|
| **[Vercel OTel] Logs** | Server-side health overview covering request volume, error rates, HTTP status distribution, log sources, regions, and top routes. |
| **[Vercel OTel] Audit Logs** | Governance and security overview of audit event volume, actors, top event types, user activity, and sensitive operations. |
| **[Vercel OTel] Web Analytics** | Traffic and engagement overview covering page views, geography, devices, top pages, and custom events. |
| **[Vercel OTel] Speed Insights** | Web Vitals performance overview tracking LCP, INP, CLS, and TTFB at the p75 benchmark over time and per page. |
