{{- generatedHeader }}
# Anthropic Integration for Elastic

## Overview

The Anthropic integration for Elastic enables collection of audit and compliance telemetry from Anthropic's [Admin and Compliance APIs](https://platform.claude.com/docs/en/api). It surfaces sign-in events, organization administration, API key lifecycle, Claude.ai and Claude Code content events, billing changes, and many other activity types into Elasticsearch so they can be analyzed in Kibana and the Elastic Security solution.

### Compatibility

This integration is compatible with the public Anthropic Admin API (`https://api.anthropic.com/v1/organizations/...`) and the Anthropic Compliance API (`https://api.anthropic.com/v1/compliance/...`). Both surfaces are served from a single global endpoint and use the `anthropic-version: 2023-06-01` API version.

### How it works

The integration polls Anthropic's REST APIs over HTTPS on a configurable interval using the Elastic Agent's [CEL](https://www.elastic.co/docs/reference/integrations/filebeat/filebeat-input-cel) input. Each data stream paginates through new events since the previous poll and persists a cursor so successive runs do not re-fetch already-collected data.

## What data does this integration collect?

The Anthropic integration collects log messages of the following types:

* Compliance activity events — one event per audit-relevant action across authentication, organization administration, RBAC, API keys, Claude.ai and Claude Code content, MCP servers, billing, and the Compliance API itself.

### Supported use cases

* Security operations: monitor sign-ins, API key creation, RBAC changes, SSO/SCIM provisioning, and admin actions on the Anthropic organization.
* Audit and compliance: retain a queryable, ECS-aligned record of all org-level changes for regulatory and internal-review use.
* Operational visibility: track Compliance API usage itself via `compliance_api_accessed` events.

## What do I need to use this integration?

Before installing the integration:

1. You must be an admin or primary owner on a Claude **Enterprise**, **Team**, or **Claude Platform** organization. Individual and consumer accounts cannot create the required API keys.
2. Compliance API access must be enabled on the parent organization. On Claude Enterprise this is a self-serve toggle at **claude.ai → Organization Settings → Data and privacy → Enable Compliance API**. On Claude Platform, request enablement through Anthropic Sales / Onboarding.
3. Mint an API key:
   * **Recommended:** create a single **Admin API Key** at **Claude Console → Settings → Admin Keys** (prefix `sk-ant-admin01-...`). With Compliance API enabled on the org, this key can call the Compliance Activities endpoint.
   * **Alternative:** create a **Compliance Access Key** at **claude.ai → Organization Settings → Data and privacy** (prefix `sk-ant-api01-...`) with at least the `read:compliance_activities` scope.
4. Copy the key — Anthropic shows it only once.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Elastic Agent is required to call the Anthropic API and ship the collected events to Elasticsearch, where they are processed by the integration's ingest pipeline.

### Onboard / configure

1. In Kibana, navigate to **Management → Integrations** and search for **Anthropic**.
2. Click **Add Anthropic** and provide the policy name, API URL (default `https://api.anthropic.com`), and the API key obtained above.
3. Choose which data streams to enable. The `audit` data stream collects compliance activities.
4. (Optional) Restrict the audit feed using the `activity_types`, `actor_ids`, or `organization_ids` filters to scope collection to specific event types, users, or child organizations.
5. Save the integration policy and assign it to the Elastic Agent policy that should collect Anthropic data.

### Validation

After saving the integration policy:

1. Wait one polling interval (default `5m` for the `audit` data stream).
2. In Kibana, open **Discover** and query `data_stream.dataset:"anthropic.audit"`. You should see compliance activity documents flowing in.
3. Generate an Anthropic admin action (for example, create or revoke an API key, or sign in to the console) and confirm a corresponding event appears within roughly one minute plus the polling interval.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

Common Anthropic-specific issues:

* **HTTP 401 `authentication_error`** — the API key is invalid or has been revoked. Mint a new key and update the policy.
* **HTTP 403 `permission_error`** — the key does not have the `read:compliance_activities` scope, or Compliance API access is not enabled on the org. Re-enable Compliance API and re-create the key, then update the policy.
* **HTTP 429 `rate_limit_error`** — the parent organization has exceeded the `/v1/compliance/*` 600 requests/minute limit (shared across all keys). Increase the polling interval or reduce the number of concurrent integration policies pointing at the same parent org.
* **No new events** — check the Elastic Agent logs for CEL request errors and verify the integration policy's API URL and key are correct.

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

The `/v1/compliance/*` rate limit of **600 requests per minute** is enforced per Anthropic parent organization and is shared across every key (Compliance Access Keys and Admin API Keys). Multiple Elastic deployments pulling from the same parent organization compete for this budget. For multi-tenant collection, configure one integration policy per Anthropic parent organization.

## Reference

### audit

The `audit` data stream collects compliance activities from the Anthropic Compliance API (`GET /v1/compliance/activities`). It produces one document per activity, covering 300+ `activity_type` values across authentication, organization administration, RBAC, API key lifecycle, Claude.ai and Claude Code content, MCP servers, billing, and the Compliance API itself.

#### audit fields

{{ fields "audit" }}

{{ event "audit" }}

{{ ilm }}

{{ transform }}

### Inputs used

{{ inputDocs }}

### API usage

These APIs are used with this integration:

* [List Compliance Activities](https://platform.claude.com/docs/en/api/compliance/activities/list) — backs the `audit` data stream.
* [Compliance API overview](https://platform.claude.com/docs/en/manage-claude/compliance-api) — enablement, scopes, and integration patterns.
* [Compliance API errors](https://platform.claude.com/docs/en/manage-claude/compliance-errors) — `error.type` enum, 429 and 5xx behavior.
