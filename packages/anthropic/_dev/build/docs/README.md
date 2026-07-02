{{- generatedHeader }}
# Anthropic

## Overview

The Anthropic integration collects compliance activity logs from [Claude's Compliance API](https://platform.claude.com/docs/en/manage-claude/compliance-api). Claude Enterprise, Team, and Claude Platform organizations generate audit events for security-relevant activities such as user authentication, organization administration, role and permission changes, API key lifecycle, Claude.ai and Claude Code usage, MCP server configuration, billing updates, and Compliance API access. This integration enables security and compliance teams to monitor administrative activity, detect unauthorized changes, and maintain an audit trail of organization operations in Elasticsearch and Kibana.

### Compatibility

This integration requires a **Claude Enterprise**, **Team**, or **Claude Platform** organization with the [Compliance API](https://platform.claude.com/docs/en/manage-claude/compliance-api) enabled. Individual and consumer accounts cannot create the required API keys.

The integration polls the Anthropic [Activity Feed](https://platform.claude.com/docs/en/manage-claude/compliance-activity-feed) at `https://api.anthropic.com/v1/compliance/activities` on a configurable schedule. Authentication requires the `read:compliance_activities` scope, which can be carried by either a **Compliance Access Key** (`sk-ant-api01-...`) or an **Admin API Key** (`sk-ant-admin01-...`).

## What data does this integration collect?

The Anthropic integration collects compliance activity events covering 300+ activity types across these categories:

* **Authentication events:** Sign-ins, sign-outs, magic links, social login, and mobile login attempts.
* **Organization administration:** Organization settings, domains, invites, member management, data exports, IP restrictions, HIPAA settings, and parent/child organization relationships.
* **Access control and RBAC:** Role assignments, group membership, SSO and SCIM provisioning, directory sync, and workspace permissions.
* **API key management:** Admin API keys, platform API keys, and user API keys — creation, updates, and deletion.
* **Claude.ai content:** Chat lifecycle, artifacts, projects, file uploads, and sharing settings.
* **Claude Code and security:** Code review configuration, security scans, webhooks, and repository settings.
* **MCP and integrations:** MCP server configuration, connector requests, and desktop extension activity.
* **Billing and subscription:** Payment methods, billing emails, usage limits, and subscription changes.
* **Compliance API usage:** Access to the Compliance API itself via `compliance_api_accessed` events.

### Supported use cases

* **Security monitoring:** Track sign-ins, API key creation, RBAC changes, SSO/SCIM provisioning, and privileged admin actions on the Anthropic organization.
* **Compliance auditing:** Retain a queryable, ECS-aligned record of organization-level changes for regulatory and internal-review requirements.
* **Operational visibility:** Monitor Claude.ai and Claude Code usage patterns, MCP server changes, and billing configuration updates.
* **Incident investigation:** Correlate audit events with actor identity, organization context, and timestamps to investigate security incidents.

## What do I need to use this integration?

* A **Claude Enterprise**, **Team**, or **Claude Platform** organization with the Compliance API enabled.
* An **Admin API Key** or **Compliance Access Key** with the `read:compliance_activities` scope.
* **Elastic Agent** installed on a host with outbound HTTPS access to `api.anthropic.com`.

For the full Anthropic-side setup, see [Get access to the Compliance API](https://platform.claude.com/docs/en/manage-claude/compliance-api-access).

### Request Compliance API access

Compliance API access is enabled on request by Anthropic. Contact your Anthropic representative to request enablement for your parent organization. After enablement:

* **claude.ai organizations (Claude Enterprise):** a **Compliance access keys** section appears at **claude.ai → Organization settings → Data and privacy**.
* **Claude Console organizations:** Admin API keys created after enablement automatically carry the `read:compliance_activities` scope. Admin API keys created before enablement cannot call the Activity Feed and must be recreated.

### Create an API key

This integration reads the Activity Feed only, so either key type in the following table works as long as it carries `read:compliance_activities`. Choose the key type that matches your organization:

| Key type | Created by | Where to create | Key prefix |
| --- | --- | --- | --- |
| **Compliance Access Key** | Primary owner | **claude.ai → Organization settings → Data and privacy** | `sk-ant-api01-...` |
| **Admin API Key** | Organization admin | **Claude Console → Settings → Admin keys** | `sk-ant-admin01-...` |

> **Note:** Claude Enterprise parent organizations do not appear in Claude Console. If your organization uses claude.ai, create a Compliance Access Key there rather than an Admin API Key in Claude Console.

#### Option A: Compliance Access Key (claude.ai)

1. Sign in to [claude.ai](https://claude.ai) as the **primary owner** of the parent organization.
2. Go to **Organization settings → Data and privacy** and find the **Compliance access keys** section.
3. Click **Create key**, name the key, and select the `read:compliance_activities` scope. This is the minimum scope required for this integration.
4. Click **Create** and copy the secret key immediately. Anthropic displays the full secret only once.

#### Option B: Admin API Key (Claude Console)

1. Sign in to [Claude Console](https://platform.claude.com) as an **organization admin**.
2. Go to **Settings → Admin keys**.
3. Click **Create key**, name the key, and click **Create**.
4. Copy the secret key immediately. Anthropic displays the full secret only once.

Admin API keys receive `read:compliance_activities` only when the Compliance API was enabled for the organization **before** the key was created. If you receive HTTP 403 errors, create a new Admin API Key after confirming Compliance API access is enabled.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Elastic Agent polls the Anthropic Compliance API and ships collected events to Elasticsearch, where they are processed by the integration's ingest pipeline.

### Agentless deployment

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Refer to [Agentless integrations](https://www.elastic.co/docs/reference/fleet/agentless-integrations) for more information.

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the underlying agent infrastructure.

To use an agentless deployment, select **Anthropic** in **Management → Integrations**, click **Add Anthropic**, and choose the agentless option when configuring the integration. Provide the Compliance Access Key or Admin API Key as described in [Onboard / configure](#onboard--configure); Elastic manages the underlying collection infrastructure for you.

### Onboard / configure

Complete the Anthropic-side setup before deploying — request Compliance API access and create an API key with the `read:compliance_activities` scope. See [Get access to the Compliance API](https://platform.claude.com/docs/en/manage-claude/compliance-api-access) for key types, scope details, and rotation guidance.

1. In Kibana, navigate to **Management → Integrations** and search for **Anthropic**.
2. Click **Add Anthropic** and enter the Compliance Access Key or Admin API Key you created.
3. Configure the polling interval (default: 5 minutes). The default initial lookback is 24 hours.
4. Optionally filter collection by activity type, actor ID, or organization ID to scope events to specific users, event types, or child organizations.
5. Save the integration policy and assign it to the Elastic Agent policy that should collect Anthropic data.

### Validation

After deploying the integration:

1. Wait one polling interval (default 5 minutes).
2. In Kibana, open **Discover** and filter for `data_stream.dataset: "anthropic.audit"`.
3. Verify that events are being ingested with populated `@timestamp`, `event.action`, and actor fields.
4. Generate an Anthropic admin action (for example, sign in to the console or create an API key) and confirm a corresponding event appears within roughly one polling interval.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

**HTTP 401 (`authentication_error`):** The API key is invalid or has been revoked. Create a new key and update the integration policy.

**HTTP 403 (`permission_error`):** The key does not have the `read:compliance_activities` scope, or Compliance API access is not enabled on the organization. Re-enable Compliance API, recreate the key, and update the policy.

**HTTP 429 (`rate_limit_error`):** The parent organization has exceeded the Compliance API limit of 600 requests per minute (shared across all keys). Increase the polling interval or reduce the number of integration policies pointing at the same parent organization.

**No new events:** Check Elastic Agent logs for request errors and verify the API key and integration policy settings are correct.

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

The Compliance API rate limit of **600 requests per minute** is enforced per Anthropic parent organization and shared across every key. Multiple Elastic deployments pulling from the same parent organization compete for this budget. For multi-tenant collection, configure one integration policy per Anthropic parent organization.

## Reference

### Audit

The `audit` data stream collects compliance activity events from the Anthropic Compliance API. It produces one document per activity, covering authentication, organization administration, RBAC, API key lifecycle, Claude.ai and Claude Code content, MCP servers, billing, and Compliance API access.

#### Audit fields

{{ fields "audit" }}

#### Sample event

{{ event "audit" }}

{{ ilm }}

{{ transform }}

### Inputs used

{{ inputDocs }}

### API usage

These APIs are used with this integration:

* [Query the Activity Feed](https://platform.claude.com/docs/en/manage-claude/compliance-activity-feed) — Activity Feed behavior, filtering, pagination, and activity object schema.
* [List Compliance Activities](https://platform.claude.com/docs/en/api/compliance/activities/list) — API reference for `GET /v1/compliance/activities`.
* [Get access to the Compliance API](https://platform.claude.com/docs/en/manage-claude/compliance-api-access) — request access, create keys, and choose between Compliance Access Keys and Admin API Keys.
* [Compliance API errors](https://platform.claude.com/docs/en/manage-claude/compliance-errors) — error types, rate limits, and retry behavior.
