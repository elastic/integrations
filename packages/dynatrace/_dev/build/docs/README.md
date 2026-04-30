# Dynatrace

The [Dynatrace](https://www.dynatrace.com/) integration collects observability and audit-related data from **Dynatrace SaaS** and **Dynatrace Managed** into Elasticsearch using the Elastic Agent [CEL input](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-cel.html). Use it to centralize problems (alerts), audit actions, cluster inventory, license usage, and related signals alongside the rest of your Elastic data.

This package is **community-supported** and ships as a **technical preview**: each data stream sets `release: experimental`, which surfaces as the technical preview badge in the Elastic Integrations UI. It is not authored or endorsed by Dynatrace as an official Elastic integration. The icon uses Dynatrace brand artwork for recognition.

## Overview

Two Fleet policy templates are available:

- **Dynatrace SaaS** — single-tenant Environment API access (`problems`, `audit_logs`, `cluster_version`).
- **Dynatrace Managed** — Cluster API v2 for fleet and licensing data, plus per-tenant Problems API via `/e/<environmentId>/...` (`activegates`, `license_usage`, `environments`, `tenant_problems`).

### How it works

On each interval the CEL program issues HTTPS GET requests to Dynatrace REST endpoints with `Authorization: Api-Token <token>`. Paginated endpoints use Dynatrace `nextPageKey` cursors; state is persisted per data stream so later runs advance from the last watermark. For **tenant problems**, the collector refreshes the environments list, caps optional batching with **Max tenants per cycle**, and maintains separate cursors per tenant.

### Compatibility

- **Dynatrace SaaS** — Environment API v1/v2 as used by the implemented paths (problems v2, audit logs v2, cluster version v1).
- **Dynatrace Managed** — Cluster API v2 (`/api/cluster/v2/...`) and per-tenant Environment API v2 under `/e/<environmentId>/api/v2/...`.

API references:

- [Problems v2](https://docs.dynatrace.com/docs/dynatrace-api/environment-api/problems-v2)
- [Audit logs](https://docs.dynatrace.com/managed/dynatrace-api/environment-api/audit-logs/get-log)
- [Cluster version](https://docs.dynatrace.com/docs/dynatrace-api/environment-api/cluster-information)
- [ActiveGates](https://docs.dynatrace.com/managed/dynatrace-api/cluster-api/cluster-api-v2/activegate/get-activegates)
- [Cluster license usage](https://docs.dynatrace.com/managed/dynatrace-api/cluster-api/cluster-api-v2/cluster-license/get-cluster-license-usage)
- [List managed environments](https://docs.dynatrace.com/managed/dynatrace-api/cluster-api/cluster-api-v2/environments/list-managed-environments)

## Data streams

**Dynatrace SaaS**

| Dataset | Description |
| --------| ----------- |
| `problems` | Problems from the Problems v2 API (`/api/v2/problems`). |
| `audit_logs` | Audit log entries from `/api/v2/auditlogs`. |
| `cluster_version` | Cluster version snapshot from `/api/v1/config/clusterversion`. |

**Dynatrace Managed**

| Dataset | Description |
| --------| ----------- |
| `activegates` | ActiveGate rows from `/api/cluster/v2/activeGates`. |
| `license_usage` | Cluster license and usage from `/api/cluster/v2/clusterLicense` (**metrics** data stream). |
| `environments` | Tenant list from `/api/cluster/v2/environments` using `pageSize`, optional `filter`, `includeConsumptionInfo` / `includeStorageInfo` (when not paginating with `nextPageKey`), and `nextPageKey` pagination. |
| `tenant_problems` | Problems per tenant from `/e/<environmentId>/api/v2/problems`. |

## Requirements

- Elastic Agent enrolled in Fleet (or agentless where supported). See the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).
- Network path from the agent (or agentless runner) to your Dynatrace SaaS URL or Managed cluster URL.
- **SaaS API token** — scopes such as `problems.read`, `auditLogs.read`, and `DataExport` as documented in the integration UI.
- **Managed cluster API token** — Cluster API access with **Service Provider API** (`ServiceProviderAPI`) for cluster endpoints.
- **Managed tenant problems (optional)** — A separate tenant token with `problems.read` and `DataExport` may be used; otherwise the cluster token is reused and must allow tenant problem reads.

## Agentless-enabled integration

Agentless integrations collect data without managing Elastic Agent on your hosts where the platform supports it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. Beta or preview limitations may apply; see Elastic documentation for current support.

## Setup

### Dynatrace

1. Sign in to Dynatrace SaaS or the Managed cluster as an administrator.
2. Create an API token with the scopes or permissions required for the policy template you use (see **Requirements**).
3. Copy the **environment base URL** (SaaS) or **cluster base URL** (Managed) with no trailing API path.

### Enable the integration in Elastic

1. In Kibana open **Management → Integrations**.
2. Search for **Dynatrace** and choose **Add Dynatrace**.
3. Select **Dynatrace SaaS** or **Dynatrace Managed** and attach the integration to an agent policy.
4. Enter **Environment URL** + **API Token** (SaaS), or **Cluster URL**, **Cluster API Token**, and optional **Tenant API Token** (Managed).
5. Enable individual data streams and tune **Interval**, **Initial lookback**, **Page size**, and (Managed tenant problems) **Max tenants per cycle** as needed.
6. Save the policy and confirm data appears in Discover (`event.module: dynatrace`).

### Validation

Use `data_stream.dataset` filters, for example:

- `dynatrace.problems`, `dynatrace.audit_logs`, `dynatrace.cluster_version`
- `dynatrace.activegates`, `dynatrace.license_usage`, `dynatrace.environments`, `dynatrace.tenant_problems`

License usage indexes follow the metrics naming pattern `metrics-dynatrace.license_usage-*`; other datasets use `logs-dynatrace.*-*`.

## Troubleshooting

For Fleet and agent issues see [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

- **401 / 403** — Token missing required scopes (`problems.read`, `auditLogs.read`, `DataExport`, or `ServiceProviderAPI` for cluster calls).
- **No tenant problems** — Verify cluster URL, cluster token permissions, and that environments list requests succeed (`dynatrace.environments`).
- **429 Too Many Requests** — Reduce page sizes or increase the collection interval; the CEL programs stop advancing for that interval on HTTP 429 and retry later.
- **Resetting cursors** — Removing and re-adding the integration (or policy) resets persisted CEL state; use when you intentionally need a full replay.

## Performance and scaling

See [Ingest architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) for Elastic-side guidance.

- Pagination is drained up to **Maximum pages per interval** per data stream where configured.
- Larger **Page size** improves throughput until Dynatrace rate limits apply.
- **Tenant problems** uses an internal work list; **Max tenants per cycle** spreads large tenant counts across intervals.

## Logs and metrics reference

### problems

This is the `problems` dataset (SaaS).

#### Example

{{event "problems"}}

{{fields "problems"}}

### audit_logs

This is the `audit_logs` dataset (SaaS).

#### Example

{{event "audit_logs"}}

{{fields "audit_logs"}}

### cluster_version

This is the `cluster_version` dataset (SaaS).

#### Example

{{event "cluster_version"}}

{{fields "cluster_version"}}

### activegates

This is the `activegates` dataset (Managed).

#### Example

{{event "activegates"}}

{{fields "activegates"}}

### license_usage

This is the `license_usage` dataset (Managed, **metrics**).

#### Example

{{event "license_usage"}}

{{fields "license_usage"}}

### environments

This is the `environments` dataset (Managed).

#### Example

{{event "environments"}}

{{fields "environments"}}

### tenant_problems

This is the `tenant_problems` dataset (Managed).

#### Example

{{event "tenant_problems"}}

{{fields "tenant_problems"}}

## Reference

- [ECS field reference](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html)
- [Filebeat CEL input](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-cel.html)
