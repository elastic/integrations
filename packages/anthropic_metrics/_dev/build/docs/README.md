{{- generatedHeader }}
# Anthropic Metrics

## Overview

The Anthropic Metrics integration collects API usage, cost, and rate limit data from [Anthropic](https://www.anthropic.com) organizations via the Admin APIs. It enables observability and monitoring teams to track token consumption, monitor spend, and surface rate limit configurations for capacity planning.

### Compatibility

This integration uses the **Anthropic Platform Admin API** (`platform.claude.com`) to collect workspace- and API-key-level cost, usage, and rate limit data. It requires an Anthropic organization on a **Team** or **Enterprise** plan with access to the [Admin API](https://platform.claude.com/docs/en/manage-claude/admin-api). Individual accounts (Free, Pro, Max) cannot create the required Admin API keys and are not supported.

Enterprise plan customers can use this integration for workspace- and API-key-level data. 
For per-user or per-product breakdowns (Chat, Claude Code, Cowork, etc.), the separate Enterprise Analytics API (`claude.ai/analytics/api-keys`) is required — that API is currently not covered by this integration.


### How it works

Elastic Agent polls three Anthropic Admin API endpoints on a configurable schedule using the CEL input:

- **Usage API** (`/v1/organizations/usage_report/messages`): Token consumption by model, workspace, and service tier
- **Cost API** (`/v1/organizations/cost_report`): Daily cost breakdown by workspace and model
- **Rate Limits API** (`/v1/organizations/rate_limits`): Per-model rate limit configurations (RPM, ITPM, OTPM)

## What data does this integration collect?

### Usage

Token usage metrics aggregated in configurable time buckets (1 minute, 1 hour, or 1 day):
- Uncached input tokens, cached input tokens, cache creation tokens, and output tokens
- Breakdowns by model, workspace, service tier, context window, and inference geography

### Cost

Daily cost data (amounts reported by the API in lowest units (eg cents)):
- Token usage costs, web search costs, and code execution costs
- Breakdowns by workspace and description (includes model and inference geography)

### Rate Limit

Rate limit configuration snapshots:
- Requests per minute (RPM), input tokens per minute (ITPM), output tokens per minute (OTPM)
- Model group membership and batch request limits

### Supported use cases

- **Token usage monitoring**: Track consumption trends across models and workspaces
- **Cost management**: Monitor daily spend and allocate costs by workspace
- **Capacity planning**: Compare rate limits against actual consumption to prevent throttling
- **Finance reporting**: Export usage and cost data for billing reconciliation

## What do I need to use this integration?

- An **Anthropic organization** (Team or Enterprise) with Platform Admin API access
- An **Admin API key** (starts with `sk-ant-admin...`) provisioned by an organization admin via [Claude Console > Settings > Admin keys](https://console.anthropic.com/settings/admin-keys).
- **Elastic Agent** installed on a host with outbound HTTPS access to `api.anthropic.com`

## How do I deploy this integration?

### Agentless deployment

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/docs/manage-data/ingest/agentless/agentless-integrations) and the [Agentless integrations FAQ](https://www.elastic.co/docs/troubleshoot/security/agentless-integrations).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Elastic Agent polls the Anthropic Admin APIs and ships collected events to Elasticsearch, where they are processed by the integration's ingest pipelines.

### Onboard / configure

1. Create an Admin API key in the [Claude Console](https://console.anthropic.com/settings/admin-keys) with organization admin permissions.
2. In Kibana, navigate to **Management > Integrations** and search for **Anthropic Metrics**.
3. Click **Add Anthropic Metrics** and enter the Admin API key.
4. Configure each data stream using the settings below, then deploy the policy to your Elastic Agent.

<details>
<summary>Usage data stream settings</summary>

| Setting | Default | Description |
|---------|---------|-------------|
| Interval | `5m` | How often the Usage API is polled. |
| Initial Interval | `24h` | Lookback window on the first collection run. Must fit within Anthropic's [granularity limits](https://platform.claude.com/docs/en/manage-claude/usage-cost-api). |
| Bucket Width | `1h` | Time granularity for usage buckets. One of `1m`, `1h`, or `1d`. Use `1m` for real-time alerting, `1h` for operational monitoring, or `1d` for finance reporting. |
| Group By | `model`, `workspace_id`, `service_tier`, `inference_geo` | Dimensions to break down usage data. Additional options: `api_key_id`, `context_window`, `speed`. |

</details>

<details>
<summary>Cost data stream settings</summary>

| Setting | Default | Description |
|---------|---------|-------------|
| Interval | `1h` | How often the Cost API is polled. The API only returns daily buckets, so polling more frequently than `1h` adds no value. |
| Initial Interval | `168h` (7 days) | Lookback window on the first collection run. |
| Group By | `workspace_id`, `description` | Dimensions to break down cost data. When `description` is included, the API returns structured fields for model, service tier, cost type, token type, context window, and inference geography. |

</details>

<details>
<summary>Rate Limit data stream settings</summary>

| Setting | Default | Description |
|---------|---------|-------------|
| Interval | `15m` | How often the Rate Limits API is polled. This is a snapshot API, so each poll returns the full current configuration. |

</details>

### Validation

After deploying, verify data is flowing by checking the following data streams in **Discover**:
- `metrics-anthropic_metrics.usage-*`
- `metrics-anthropic_metrics.cost-*`
- `metrics-anthropic_metrics.rate_limit-*`

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

- **HTTP 401 errors**: Verify the Admin API key is valid and starts with `sk-ant-admin...`. Standard API keys do not work with Admin endpoints.
- **HTTP 403 errors**: Confirm the key has organization admin permissions and the organization has Admin API access enabled.
- **No data for usage/cost streams**: Check that the time window parameters (`initial_interval`, `bucket_width`) are configured correctly and that the organization has recent API activity.

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Usage

The `usage` data stream collects token usage metrics from the Anthropic Usage API.

#### Usage fields

{{ fields "usage" }}

### Cost

The `cost` data stream collects daily cost data from the Anthropic Cost API.

#### Cost fields

{{ fields "cost" }}

### Rate Limit

The `rate_limit` data stream collects rate limit configuration from the Anthropic Rate Limits API.

#### Rate Limit fields

{{ fields "rate_limit" }}


## Alerting Rule Template
{{alertRuleTemplates}}