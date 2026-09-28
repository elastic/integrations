{{- generatedHeader }}
# Atlassian Cloud Integration for Elastic

## Overview
The Atlassian Cloud integration for Elastic enables collection of organization-wide audit log events from [Atlassian Cloud](https://www.atlassian.com/) products including Jira, Confluence, Bitbucket, Trello, and other Atlassian Cloud applications.

This integration polls the [Atlassian Organizations REST API](https://developer.atlassian.com/cloud/admin/organization/rest/) to collect administrative and security-relevant events such as user management, authentication, product access changes, organization policy updates, app/marketplace activity, and API token lifecycle events. The audit log captures activity across all Atlassian Cloud products in an organization in a unified format.

### When should I use this integration?

Elastic provides several Atlassian integrations. Choose the one that best fits your needs:

* **Atlassian Cloud** (this integration) — Collects **organization-level** audit events from the Atlassian Organizations API. Events span all Atlassian Cloud products (Jira, Confluence, Bitbucket, Trello, and others) in a single stream. Use this integration when you need unified visibility into organization-wide administrative activity such as SSO policy changes, cross-product user provisioning, marketplace app management, and domain verification. This integration is only available for Atlassian Cloud and does not support self-hosted deployments.

* **Atlassian Jira** (`atlassian_jira`) — Collects **Jira-specific** audit events from the Jira audit API. Use this integration when you need detailed Jira administrative activity such as permission scheme changes, project configuration updates, custom field modifications, and Jira-specific user and group management. This integration supports both Atlassian Cloud and self-hosted Jira Data Center deployments.

* **Atlassian Confluence** (`atlassian_confluence`) — Collects Confluence-specific audit events. Use this for detailed Confluence administrative activity.

* **Atlassian Bitbucket** (`atlassian_bitbucket`) — Collects Bitbucket-specific audit events. Use this for detailed Bitbucket administrative activity.

These integrations are **complementary** and can be used together. For example, you might use this integration for broad organization-level security monitoring while also using the Jira integration for deeper Jira-specific audit detail. Events from each integration are stored in separate data streams, so there is no conflict when running them side by side.

### Compatibility
This integration is compatible with the Atlassian Cloud Organizations REST API v1, accessed via the `/admin/v1/orgs/{orgId}/events-stream` endpoint. Atlassian Cloud Organization admin access and an API key with the `read:events:admin` scope are required.

### How it works
The integration polls the Atlassian Organizations API on a configurable interval using cursor-based pagination. Each poll cycle retrieves new audit events since the last successful poll, parses them, and ships the documents to Elasticsearch where the ingest pipeline maps fields to ECS and enriches them with categorization, related entities, and geo information.

## What data does this integration collect?
The Atlassian Cloud integration collects organization-wide audit events of the following types:
* User management — invitations, deactivations, reactivations, removals.
* Authentication — logins, logouts, password changes, 2FA configuration.
* Product access — access grants, revocations, role changes.
* Organization policies — security policy updates, SSO configuration, domain verification.
* App / marketplace activity — app installations, uninstallations, access changes.
* API tokens — token creation and revocation.
* Group management — membership changes.
* Data security — data residency, classification policies.

### Supported use cases
This integration supports security monitoring, compliance reporting, and incident investigation across the full Atlassian Cloud organization. Common use cases include detecting suspicious authentication activity, tracking administrative changes, auditing user lifecycle events, monitoring third-party app installations, and correlating Atlassian admin activity with other security telemetry.

## What do I need to use this integration?
* An Atlassian Cloud Organization with admin access.
* An API key with the `read:events:admin` scope. See the [Atlassian API key management documentation](https://support.atlassian.com/organization-administration/docs/manage-an-organization-with-the-admin-apis/) for creation steps.
* The Organization ID (UUID) of the Atlassian Cloud organization.
* Access to a Guard Premium or Cloud Enterprise plan might be required for full visibility into user-created activities.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Elastic Agent is required to poll the Atlassian Organizations REST API and ship the events to Elastic, where they will be processed via the integration's ingest pipelines.

### Onboard / configure
1. In [admin.atlassian.com](https://admin.atlassian.com), select your organization.
2. Navigate to **Organization settings** → **API keys**.
3. Choose **API keys with scopes** → **Create API key**.
4. Name the key (for example, `Elastic Integration`).
5. Set an expiration (maximum of 1 year). Plan for rotation before the key expires.
6. Select the `read:events:admin` scope, then create the key.
7. Copy and save the API key value — it is shown only once.
8. Note the **Organization ID** (UUID format) from the admin URL or organization settings.
9. In Kibana, add the Atlassian Cloud integration and configure it with the API URL (`https://api.atlassian.com`), Organization ID, and API key.

### Validation
After configuration, verify that documents appear in the `logs-atlassian_cloud.audit-*` data stream within one or two polling intervals. The default polling interval is 5 minutes. Confirm that recent administrative actions (for example, a new API key creation) appear in the indexed events.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

Common issues:
* **401 Unauthorized**: verify the API key is current, has the `read:events:admin` scope, and was not revoked. API keys expire after at most 1 year.
* **403 Forbidden**: verify the user that created the API key has Organization admin rights and that the Organization ID is correct.
* **429 Too Many Requests**: the `/events-stream` endpoint enforces 50 requests/minute per API path and 60 requests/minute per user. Reduce polling frequency or batch size if rate limits are hit.
* **Missing events**: Atlassian Cloud audit log visibility depends on the organization's Atlassian plan. Guard Premium or Cloud Enterprise may be required for some user-created activities.

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference
### audit

The `audit` data stream provides organization-wide audit events from Atlassian Cloud. Events cover user management, authentication, product access, organization policies, marketplace app activity, API token lifecycle, group membership changes, and data-security policy updates.

#### audit fields

{{ fields "audit" }}

#### audit sample event

{{ event "audit" }}

{{ ilm }}

{{ transform }}

### Inputs used
{{ inputDocs }}

### API usage
These APIs are used with this integration:
* [Atlassian Organizations REST API — Poll audit log events (`/admin/v1/orgs/{orgId}/events-stream`)](https://developer.atlassian.com/cloud/admin/organization/rest/api-group-events/#api-v1-orgs-orgid-events-stream-get)
