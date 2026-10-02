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
- **BYOK visibility**: Separate spend on your own provider keys (and OpenRouter's BYOK fees) from spend on OpenRouter credits
- **Budget alerting**: Surface spend anomalies before they accumulate
- **SLO tracking**: Alert on model-level latency regressions

## What do I need to use this integration?

- An OpenRouter **Management API key**. Create one at
  [openrouter.ai/settings/management-keys](https://openrouter.ai/settings/management-keys).
- Elastic and Kibana ≥ 9.6.0 (basic subscription)

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
2. In Kibana, navigate to **Management → Integrations** and search for **OpenRouter**.
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
If the API reports a truncated result (`metadata.truncated`), the window is halved and
retried (down to 1 day for `usage`, 1 hour for `performance`). If a result is still
truncated at the minimum window, the returned rows are ingested and the remainder is lost;
reduce the number of distinct dimension values or use fewer dimensions.

Supported dimensions are `model`, `variant`, `api_key_id`, `workspace`, `app`, `user`, and `provider`.

## Troubleshooting

- **HTTP 401 errors**: Verify the Management API key is correct and has not been revoked.
  Standard API keys (not Management keys) will be rejected.
- **No data / empty results**: The account may have no recent traffic. The `openrouter.usage.request_count`
  field will be `0` or absent. Data appears only for time windows where requests were made.
- **`limit: Too big`**: The integration uses `limit: 10000` (the API maximum). If this error
  appears, it is a bug. Report it.
- **`time_range exceeds maximum of 31 days`**: The integration's windowing ensures queries
  never span more than 30 days (`usage`) or 24 hours (`performance`). If this error appears,
  it is a bug. Report it.

## Reference

### Usage

The `usage` data stream collects daily snapshot metrics (request count, token consumption, cost)
from the OpenRouter Analytics API. Each document represents the total for a given day and
dimension combination. Metrics can be summed across dimensions (for example, total spend across all models).

The current day is polled again on every collection interval, so the same daily bucket can appear
in several documents with growing totals. When aggregating, first take `MAX` per `@timestamp` and
per dimension combination (include all dimension fields, because only the configured ones are set),
then `SUM`. `blended_cost_per_million_tokens` is a rate: do not sum it, derive it from
`total_usage / tokens_total` instead.

#### Usage fields

{{ fields "usage" }}

### Performance

The `performance` data stream collects hourly non-additive metrics from the OpenRouter Analytics
API: latency, time to first token, generation time, inter-token latency, router overhead and
throughput (averages and percentiles), plus cache, response-cache and guardrail rates. It also
collects `request_count`, which is the only additive field.

**Important:** Latency, throughput and rate metrics are averages, percentiles or ratios computed by
the API for each row (hour and dimension combination). Never use `SUM` on them. To combine rows,
use a request-weighted average, `SUM(metric * request_count) / SUM(request_count)`, for the
`avg_*` fields and the rates. For percentiles (`p50_*`, `p90_*`, `p95_*`, `p99_*`) use `MAX`,
for example the worst `p99_latency`, or look at single rows: neither a plain nor a weighted
average of percentiles is a true percentile of all traffic.

#### Performance fields

{{ fields "performance" }}

## Dashboards

- **[Metrics OpenRouter] Usage & Cost Overview**: requests, cost (regular keys, BYOK, BYOK fees), tokens,
  cache, and breakdowns by model and API key.
- **[Metrics OpenRouter] Performance Overview**: latency, TTFT, generation, inter-token and router latency,
  throughput, cache and guardrail rates, and a per-model comparison.

Both dashboards use pinned controls with ES|QL-backed values, which require Kibana 9.6 or later.

## Alerting Rule Templates
{{alertRuleTemplates}}
