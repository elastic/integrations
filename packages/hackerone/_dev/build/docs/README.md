{{- generatedHeader }}
# HackerOne Integration for Elastic

## Overview

The HackerOne integration brings your bug bounty and vulnerability disclosure reports into Elastic Security. Use it to monitor submissions from security researchers, track report status, and analyze vulnerability data alongside your other security tools.

The integration checks HackerOne on a schedule you choose and pulls in new or updated reports. After the first run, it only collects reports that changed since the last check, so you stay up to date without duplicate data.

### Compatibility

This integration works with the [HackerOne Customer API](https://api.hackerone.com/). You need an organization API token from a Professional, Community, or Enterprise program. You can also use the free [Sandbox program](https://hackerone.com/teams/new/sandbox) to test the integration.

### How it works

On each scheduled run, the integration:

1. Connects to HackerOne using your API token.
2. Fetches reports for the programs or inboxes you specify.
3. Sends each report to Elasticsearch for search, dashboards, and alerting.

When a report is updated in HackerOne (for example, triaged or resolved), the integration picks up the change on the next run.

## What data does this integration collect?

Each report includes details such as:

* **Status and timeline** — when the report was created, triaged, closed, disclosed, and last updated.
* **Vulnerability details** — title, description, severity rating, CVSS score, weakness type, and CVE IDs when available.
* **People involved** — the researcher who submitted the report, assignee, program, and collaborators.
* **Scope and rewards** — the affected asset, bounty and swag awards, attachments, and remediation guidance.

### Supported use cases

* Monitor vulnerability disclosure programs from a single place in Elastic Security.
* Build SLA dashboards using response-time and resolution-time metrics.
* Track bounty spending across programs.

## What do I need to use this integration?

Before you install the integration, gather the following from your HackerOne organization:

1. **API access.** API tokens are available on Professional, Community, and Enterprise programs. Use the free [Sandbox program](https://hackerone.com/teams/new/sandbox) for testing.
2. **An organization API token** with **Report management** permission. As an Organization Administrator, go to **Organization Settings → API Tokens** to create one. Save both the **identifier** and the **value** when the token is created — the value is shown only once.
3. **At least one program handle or inbox ID** to tell the integration which reports to collect.
   * **Program handle** — the name in your program URL: `https://hackerone.com/<handle>` (for example, `acme`).
   * **Inbox ID** — the numeric ID from your inbox settings page URL.
4. **(Optional) IP allowlist entry** — if your organization restricts API access by IP, add the outbound IP address of the Elastic Agent host.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

### Onboard / configure

1. In Kibana, go to **Integrations** and search for **HackerOne**.
2. Click **Add HackerOne**.
3. Fill in the required settings:
   * **URL** — HackerOne API address (default: `https://api.hackerone.com`).
   * **API token identifier** — the identifier from your API token.
   * **API token value** — the secret value from your API token.
   * **Program handles** and/or **Inbox IDs** — at least one is required.
   * **Interval** — how often to check for new reports (default: every 5 minutes).
   * **Initial lookback** — how far back to fetch reports on the first run (default: 24 hours).
   * **Page size** — number of reports retrieved per request (default: 100).
4. Optionally narrow what is collected with **State filter** and **Severity filter**.
5. Save the integration policy and assign it to an Elastic Agent policy.

### Validation

After the integration is running, open **Discover** in Kibana and search for `event.dataset: "hackerone.report"`. You should see reports within one polling interval (default: 5 minutes) after they are created or updated in HackerOne.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

* **401 Unauthorized** — The API token identifier or value is wrong. Make sure you entered the token **identifier** (not your email address) in the identifier field.
* **403 Forbidden** — The token is valid, but access was denied. Check that the Elastic Agent's IP address is on your organization's allowlist, and that the token has access to the programs you configured.
* **429 Too Many Requests** — HackerOne limits how many requests you can make per minute. Try increasing the polling interval or collecting fewer programs with a single agent.
* **No documents indexed** — Confirm that at least one **Program handle** or **Inbox ID** is set. The integration needs at least one to know which reports to collect.

## Scaling

For guidance on scaling data ingestion, see [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures).

A single agent can handle many programs at the default 5-minute interval. If you set a long initial lookback (for example, 30 days or more), the first run may take longer while historical reports are collected.

## Reference

### report

The `report` data stream collects bug bounty reports from HackerOne. Each report is stored as one document. When a report is updated, a new document is indexed with the latest information.

#### report fields

{{ fields "report" }}

{{ event "report" }}

{{ ilm }}

{{ transform }}

### Inputs used

{{ inputDocs }}

### API usage

This integration uses the following HackerOne API endpoint:

* [List reports](https://api.hackerone.com/customer-resources/#reports-get-all-reports) — retrieves bug bounty reports for the programs or inboxes you configure.
