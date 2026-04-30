# Dynatrace integration for Elastic

> **Note**: This AI-assisted guide was validated by our engineers. You may need to adjust the steps to match your environment.

This package is **community-supported** and ships as a **technical preview**: each data stream sets `release: experimental`, which surfaces as the technical preview badge in the Elastic Integrations UI. It is **not** authored or endorsed by Dynatrace as an official Elastic integration.

The icon (`img/dynatrace-logo.svg`) uses Dynatrace **brand artwork** (wordmark and logo mark) for recognition alongside Dynatrace APIs and environments.

## Overview

The Dynatrace integration collects observability and audit data from Dynatrace into the Elastic Stack using the [Common Expression Language (CEL)](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-cel.html) input. Two deployment variants are supported:

- **Dynatrace SaaS** — collect data from a single Dynatrace SaaS tenant.
- **Dynatrace Managed** — collect cluster-level data and per-tenant problems from a self-hosted Dynatrace Managed cluster.

### Compatibility

This integration is compatible with:

- **Dynatrace SaaS** environments using the Environment API v1/v2.
- **Dynatrace Managed** clusters with the Cluster API v2 and per-tenant Environment API v2.

API references:

- Problems v2: <https://docs.dynatrace.com/docs/dynatrace-api/environment-api/problems-v2>
- Audit logs: <https://docs.dynatrace.com/managed/dynatrace-api/environment-api/audit-logs/get-log>
- Cluster info: <https://docs.dynatrace.com/docs/dynatrace-api/environment-api/cluster-information>
- Cluster ActiveGates: <https://docs.dynatrace.com/managed/dynatrace-api/cluster-api/cluster-api-v2/activegate/get-activegates>
- Cluster license usage: <https://docs.dynatrace.com/managed/dynatrace-api/cluster-api/cluster-api-v2/cluster-license/get-cluster-license-usage>
- List environments (tenants): <https://docs.dynatrace.com/managed/dynatrace-api/cluster-api/cluster-api-v2/environments/list-managed-environments>

### How it works

Elastic Agent runs the **CEL** input on the configured interval. Each data stream calls a Dynatrace REST API endpoint, paginates through results using Dynatrace's `nextPageKey` cursor, and stores cursor state per data stream so subsequent runs collect only new events. Authentication uses the `Authorization: Api-Token <token>` header.

The **Dynatrace Managed** variant fans out the **Tenant Problems** data stream over every environment returned by `/api/cluster/v2/environments`. The list of environments is refreshed each interval; problems for each tenant are collected with their own per-tenant cursor (`from` timestamp + `nextPageKey`), so adding or removing environments at the cluster level is picked up automatically without changing the policy.

## What data does this integration collect?

The integration produces the following data streams:

**Dynatrace SaaS:**

- `dynatrace.problems` — Open and recently closed problems detected by Davis AI from the [Problems v2 API](https://docs.dynatrace.com/docs/dynatrace-api/environment-api/problems-v2).
- `dynatrace.audit_logs` — Audit log entries (logins, configuration changes, token operations) from the [audit logs API](https://docs.dynatrace.com/managed/dynatrace-api/environment-api/audit-logs/get-log).
- `dynatrace.cluster_version` — Periodic snapshot of the Dynatrace cluster version returned by `/api/v1/config/clusterversion`.

**Dynatrace Managed:**

- `dynatrace.activegates` — One document per ActiveGate from `/api/cluster/v2/activeGates`, including modules, OS info, autoupdate status, and connected hosts.
- `dynatrace.license_usage` — Cluster-wide license and billing usage from `/api/cluster/v2/clusterLicense` (host units, DDU, DEM, sessions, overage).
- `dynatrace.environments` — Tenants registered on the cluster from `/api/cluster/v2/environments`, optionally including consumption and storage.
- `dynatrace.tenant_problems` — Problems collected **per tenant** by iterating the environments list and calling `/e/<environmentId>/api/v2/problems` for each.

### Supported use cases

- Centralize Dynatrace alerts (problems) with other observability and security signals in Elastic.
- Audit who changed what, in which environment, with full diff (`patch`) preserved.
- Track ActiveGate fleet health, module configuration, and update status.
- Monitor license consumption and overage across a Managed cluster.
- Inventory tenants in a Managed cluster and watch for problems on each tenant from one place.

## What do I need to use this integration?

### Dynatrace prerequisites

- A Dynatrace SaaS tenant **or** a Dynatrace Managed cluster reachable from the Elastic Agent host.
- An access token with the right scopes:
  - **SaaS**: a tenant access token with `problems.read`, `auditLogs.read`, and `DataExport` scopes.
  - **Managed cluster**: a Cluster API token with the **Service Provider API** (`ServiceProviderAPI`) permission.
  - **Managed tenant problems** (optional separate token): a tenant access token with `problems.read` and `DataExport` scopes. If omitted, the cluster API token is reused.

### Elastic prerequisites

- Elastic Agent installed and enrolled in Fleet (or run as agentless). See the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).
- Network connectivity from the Elastic Agent (or agentless runner) to the Dynatrace SaaS endpoint or Managed cluster.

## How do I deploy this integration?

### Agent-based deployment

Install Elastic Agent and enroll it in a Fleet policy. Add the Dynatrace integration and choose the variant that matches your Dynatrace deployment (`Dynatrace SaaS` or `Dynatrace Managed`). Agentless deployment is also supported.

### Set up steps in Dynatrace

1. Sign in to your Dynatrace SaaS tenant or Managed cluster as an administrator.
2. Generate an access token with the scopes / permissions listed above.
3. Note the **Environment URL** (SaaS) or **Cluster URL** (Managed).

### Set up steps in Kibana

1. Open **Management → Integrations**.
2. Search for **Dynatrace** and click **Add Dynatrace**.
3. Pick the variant: **Dynatrace SaaS** or **Dynatrace Managed**.
4. Configure the required fields:
   - **SaaS**: `Environment URL`, `API Token`.
   - **Managed**: `Cluster URL`, `Cluster API Token`, optional `Tenant API Token`.
5. Adjust per-data-stream **Initial Interval**, **Page Size**, and (for `tenant_problems`) **Max Tenants Per Cycle** if needed.
6. Save and verify documents land in `logs-dynatrace.*-*` (or `metrics-dynatrace.license_usage-*`).

### Validation

In Kibana **Discover**, filter by `event.module: "dynatrace"` and confirm at least one data stream is producing events. Useful per-stream KQL filters:

- `data_stream.dataset: "dynatrace.problems"`
- `data_stream.dataset: "dynatrace.audit_logs"`
- `data_stream.dataset: "dynatrace.activegates"`
- `data_stream.dataset: "dynatrace.tenant_problems"`

## Troubleshooting

For common Fleet / agent issues see [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

- **`401 Unauthorized` / `403 Forbidden`**: the token lacks the required scope (for example `problems.read` or `ServiceProviderAPI`). Regenerate the token with the right scopes.
- **No tenants enumerated for Managed**: confirm the cluster URL is correct (no trailing path) and the cluster token has `ServiceProviderAPI`. The `dynatrace.environments` data stream must produce documents before `dynatrace.tenant_problems` does.
- **`429 Too Many Requests`**: lower the **Page Size** or increase the **Interval**. Dynatrace enforces per-token rate limits; the CEL program backs off on `429` and retries on the next interval.
- **Stale data after backfill**: cursors are persisted per data stream. Reinstall the integration (or remove the policy and re-add) to reset cursors.
- **Empty `patch` field on audit logs**: only operations with a delta carry a patch — logins, logouts, and revocations have no patch.

## Performance and scaling

For ingest reference architectures see [Ingest architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures).

- **Pagination**: all paginated endpoints use Dynatrace's cursor (`nextPageKey`). The CEL program drains all available pages within a single interval, up to **Max Pages Per Interval**, and stores the latest watermark for the next run.
- **Page size**: choose values close to the documented maximum (problems: 500, audit logs: 5000, environments: 1000) for higher throughput, but reduce if you observe `429` responses.
- **Time windows**: on first run the integration honours **Initial Interval** (default `now-1d`). Subsequent runs query from the last received timestamp + 1 ms to avoid duplicates.
- **Per-tenant fan-out (Managed)**: a single CEL run lists tenants and walks each tenant's problems sequentially using a work-list. Use **Max Tenants Per Cycle** to spread very large clusters across multiple intervals (the work-list resumes between runs).
- **Agent placement**: deploy the agent close (network-wise) to the Dynatrace cluster to minimise latency on per-tenant requests.

## Reference

ECS field reference: <https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html>.

Filebeat CEL input documentation: <https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-cel.html>.
