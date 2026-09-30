{{- generatedHeader }}
# OpenRouter

## Overview

The OpenRouter integration collects API usage, cost, and performance metrics from the
[OpenRouter Analytics API](https://openrouter.ai/docs/api/api-reference/analytics/query-analytics-data),
providing cross-provider observability into LLM request volume, token consumption, spend,
latency, throughput, and cache efficiency.

OpenRouter is a unified LLM gateway that routes requests across 300+ models from providers
such as OpenAI, Anthropic, Google, Meta, Nvidia, and others.

### Supported use cases

- **Usage & cost monitoring**: Track daily spend and token consumption by model and API key
- **Performance observability**: Monitor latency percentiles and throughput per model and API key
- **Cache efficiency**: Measure cache hit rates to optimize prompt caching and reduce cost
- **Budget alerting**: Surface spend anomalies before they accumulate
- **SLO tracking**: Alert on provider-level latency regressions

## What do I need to use this integration?

- An OpenRouter **Management API key**. Create one at
  [openrouter.ai/settings/management-keys](https://openrouter.ai/settings/management-keys).
- Elastic and Kibana ≥ 9.4.0 (basic subscription)

## How do I deploy this integration?

### Elastic Managed deployment

Elastic Managed integrations allow you to collect data without managing Elastic Agent yourself.
For more information, refer to [Elastic Managed integrations](https://www.elastic.co/docs/manage-data/ingest/agentless/agentless-integrations).

Elastic Managed deployments are only supported in Elastic Serverless and Elastic Cloud environments.
This functionality is in beta and is subject to change.

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent
[installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

### Onboard / configure

1. Create a Management API key at [openrouter.ai/settings/management-keys](https://openrouter.ai/settings/management-keys).
2. In Kibana, navigate to **Management > Integrations** and search for **OpenRouter**.
3. Click **Add OpenRouter** and enter the Management API key.
4. Configure the data streams using the settings below, then deploy.

<details>
<summary>Usage data stream settings (daily)</summary>

| Setting | Default | Description |
|---------|---------|-------------|
| Collection interval | `6h` | How often the Analytics API is polled for new daily data. |
| Initial lookback | `168h` (7 days) | How far back to collect data on the first run. |
| Dimensions | `model`, `api_key_id` | Up to 2 dimensions to group data by. |

</details>

<details>
<summary>Performance data stream settings (hourly)</summary>

| Setting | Default | Description |
|---------|---------|-------------|
| Collection interval | `1h` | How often the Analytics API is polled for new hourly data. |
| Initial lookback | `168h` (7 days) | How far back to collect data on the first run. |
| Dimensions | `model`, `api_key_id` | Up to 2 dimensions to group data by. |

</details>

### Validation

After deploying, verify data is flowing in **Discover**:
- `metrics-openrouter.usage-*`
- `metrics-openrouter.performance-*`

## API limits

| Constraint | Value |
|---|---|
| Rate limit | 64 requests per minute |
| Maximum rows per query | 10,000 |
| Maximum dimensions per query | 2 |
| Maximum query time span (latency/rate metrics or `provider` dimension) | 31 days |
| Maximum query time span (volume/cost metrics, long-window dimensions only) | 365 days |

The integration issues windowed requests (30 days for `usage`, 24 hours for `performance`)
to stay safely within the 31-day span limit regardless of dimension selection.

## Troubleshooting

- **HTTP 401 errors**: Verify the Management API key is correct and has not been revoked.
  Standard API keys (not Management keys) will be rejected.
- **No data / empty results**: The account may have no recent traffic. The `openrouter.usage.request_count`
  field will be `0` or absent. Data appears only for time windows where requests were made.
- **`limit: Too big`**: The integration uses `limit: 10000` (the API maximum). If this error
  appears, it is a bug — please report it.
- **`time_range exceeds maximum of 31 days`**: The integration's windowing ensures queries
  never span more than 30 days (`usage`) or 24 hours (`performance`). If this error appears,
  it is a bug — please report it.

## Reference

### Usage

The `usage` data stream collects daily snapshot metrics (request count, token consumption, cost)
from the OpenRouter Analytics API. Each document represents the total for a given day and
dimension combination. Metrics can be summed across dimensions (e.g. total spend across all models)
but should not be summed across time — use `MAX` when aggregating across multiple documents
for the same period.

#### Usage fields

{{ fields "usage" }}

### Performance

The `performance` data stream collects hourly non-additive rate metrics (latency, throughput,
cache hit rate) from the OpenRouter Analytics API.

**Important:** Performance metrics are ratios or percentiles. Never use `SUM` aggregations —
always use `AVG` or `MAX` in ES|QL queries.

#### Performance fields

{{ fields "performance" }}

## Alerting Rule Templates
{{alertRuleTemplates}}
