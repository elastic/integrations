{{- generatedHeader }}
# HackerOne Integration for Elastic

## Overview

The HackerOne integration for Elastic enables collection of bug bounty reports from the [HackerOne Customer API](https://api.hackerone.com/) so that vulnerability disclosure activity can be analyzed alongside the rest of your security telemetry in Elastic.

The integration polls `GET /v1/reports` on a configurable interval, follows the JSON:API `links.next` cursor to walk all pages within a polling cycle, and persists the maximum `last_activity_at` watermark between cycles so that only new and updated reports are collected on subsequent polls.

### Compatibility

This integration is compatible with the HackerOne Customer API `v1` (`https://api.hackerone.com/v1/`). API tokens generated under **Organization Settings → API Tokens** for Professional, Community, or Enterprise programs (and the free Sandbox program) are supported.

### How it works

The integration uses the Elastic Agent CEL input to:

1. Authenticate against the HackerOne API using HTTP Basic auth (token identifier as username, token value as password).
2. Issue a `GET /v1/reports` request scoped by one or more `program_handles` and/or `inbox_ids`, sorted by `reports.last_activity_at` ascending, filtered by `filter[last_activity_at__gt]=<cursor + 1ms>`, and parameterized with the configured `page[size]`. Adding 1 ms to the persisted cursor avoids re-collecting the boundary record and works around HackerOne API parsing edge cases on `__gt` comparisons.
3. Walk paginated results by following the `links.next` URL returned in each response body. The first request includes only `page[size]` (no explicit page number); subsequent requests follow the absolute URL HackerOne returns in `links.next`.
4. Persist the maximum `last_activity_at` value seen across the cycle as the cursor for the next poll.

## What data does this integration collect?

The HackerOne integration collects bug bounty report records, including:

* Lifecycle state and timestamps (creation, triage, closure, disclosure, last activity).
* Vulnerability metadata (title, description, severity rating + CVSS metrics, CWE/CAPEC weakness, CVE IDs).
* Actors (reporter, assignee, program handle, collaborators).
* Structured scope (asset under attack), bounty and swag awards, attachments, summaries, custom fields, inbox routing, and remediation guidance.
* Activity timeline (one document per report; activity timeline is preserved on the report document).

### Supported use cases

* Centralized monitoring of vulnerability disclosure programs across Elastic Security workflows.
* SLA dashboards using the `hackerone.report.attributes.timer_*` fields delivered by the upstream API.
* Bounty spend reporting using `hackerone.report.relationships.bounties.data.attributes.*` and bounty currency aggregations.
* Correlation between HackerOne report URLs (`vulnerability.reference`) and other vulnerability scanner findings.

## What do I need to use this integration?

You will need the following from your HackerOne organization before installing this integration:

1. **API access entitlement.** API tokens are available to Professional, Community, and Enterprise programs. The free [Sandbox program](https://hackerone.com/teams/new/sandbox) is suitable for testing.
2. **An organization API token** with the `report_management` permission. Generate it as an Organization Administrator under **Organization Settings → API Tokens**. Capture both the **identifier** and the **value** (the value is shown only once at creation).
3. **One or more program handles** (the slug under `https://hackerone.com/<handle>`) **or** **inbox IDs** to scope collection.
4. **(Optional) IP allowlist entry** for the Elastic Agent's egress IP if your organization has IP allowlisting enabled on API tokens.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

### Onboard / configure

1. In Kibana, go to **Integrations** and search for **HackerOne**.
2. Click **Add HackerOne**.
3. Configure the following required variables:
   * **URL** — Base URL of the HackerOne API (default `https://api.hackerone.com`).
   * **API token identifier** — The identifier portion of the HackerOne API token (used as Basic auth username).
   * **API token value** — The secret value of the HackerOne API token (used as Basic auth password).
   * **Program handles** and/or **Inbox IDs** — At least one of these must be set.
   * **Interval** — How often to poll the API (default `5m`).
   * **Initial lookback** — How far back to look on the first poll (default `24h`).
   * **Page size** — Reports per page (default `100`, API maximum).
4. Optionally restrict the collection scope using **State filter** and **Severity filter**.
5. Save the integration policy and assign it to an Elastic Agent policy.

### Validation

After the integration is enabled, navigate to **Discover** in Kibana and filter on `event.dataset: "hackerone.report"`. New documents should appear within one polling interval (default `5m`) of being created or updated in HackerOne.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

* **`401 Unauthorized`** — The API token identifier or value is incorrect, or the identifier was used as an email address instead of as the username. Use the token **identifier** as the Basic auth username.
* **`403 Forbidden`** — The token is valid but the requesting IP address is not on the organization's IP allowlist, or the token does not have access to the requested program. Add the Elastic Agent's egress IP to the allowlist or grant the token's group `report_management` permission on the target program.
* **`429 Too Many Requests`** — HackerOne rate-limits report list reads at 300 requests per minute. Increase the polling interval or reduce the number of programs collected by a single agent if you hit this limit.
* **No documents indexed** — Verify at least one of `program_handles` or `inbox_ids` is set. The HackerOne API requires at least one scope filter and rejects calls without it.

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

A single agent comfortably handles dozens of programs at the default `5m` interval, since steady-state polling consumes one request per program per cycle. Backfill of large historical windows (`initial_interval: 30d` or more) may issue several requests per cycle until the cursor catches up.

## Reference

### report

The `report` data stream collects HackerOne bug bounty reports via the `GET /v1/reports` Customer API endpoint. One document is emitted per report; updates to a report appear as new documents.

#### report fields

{{ fields "report" }}

{{ event "report" }}

{{ ilm }}

{{ transform }}

### Inputs used

{{ inputDocs }}

### API usage

The following HackerOne Customer API endpoints are used by this integration:

* [`GET /v1/reports`](https://api.hackerone.com/customer-resources/#reports-get-all-reports) — list and incrementally collect bug bounty reports.
