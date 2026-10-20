{{- generatedHeader }}
# SOCRadar Integration

## Overview

The SOCRadar integration collects security alarms from the [SOCRadar](https://socradar.io) platform via its REST API and ingests them into Elasticsearch. Each alarm is stored as a log event in the `logs-socradar_alert.incidents-*` data stream.

Alarms are indexed as ECS `event.kind: alert` documents that can be explored in Kibana Discover and the included dashboard.

### Compatibility

This integration is compatible with **SOCRadar API v4**.

### How it works

The integration uses the **CEL input** to poll the SOCRadar REST API at a configurable interval. On first run, it fetches alarms from a configurable lookback period. On subsequent runs, it fetches only alarms created since the last successful poll. Alarm data is normalized via an ingest pipeline and stored in the `incidents` data stream.

## What data does this integration collect?

The SOCRadar integration collects security alarm events from the following endpoint:

- `GET /api/company/{company_id}/incidents/v4`

Each event represents a single SOCRadar alarm and includes details such as risk level, alarm type, status, affected assets, and related entities.

### Supported use cases

- **Centralized alarm visibility** — View all SOCRadar alarms in Kibana Discover and the included dashboard.
- **Risk-based triage** — Alarm risk levels are mapped to ECS `event.severity` so alarms can be filtered and prioritized by severity.

## What do I need to use this integration?

- A valid **SOCRadar API Key**
- Your **SOCRadar Company ID**
- Elastic Agent installed on a host with network access to `https://platform.socradar.com`

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

### Onboard / configure

1. In Kibana, go to **Fleet → Integrations** and search for **SOCRadar**.
2. Click **Add SOCRadar**.
3. Fill in the required fields:
   - **API Key** — Your SOCRadar API key.
   - **Company ID** — Your SOCRadar company ID (e.g., `330`).
   - **API URL** — SOCRadar API base URL (default: `https://platform.socradar.com`).
   - **Initial Lookback Period** — How far back to fetch alarms on first run (e.g., `72h`, `720h` for 30 days).
   - **Polling Interval** — How often to poll for new alarms (default: `5m`).
4. Click **Save and continue**.

### Validation

After installation, open **Kibana → Discover** and filter by index `logs-socradar_alert.incidents-*`. Alarms should appear within one polling interval.

You can also open the **SOCRadar dashboard** from **Kibana → Dashboards** to verify data is flowing correctly.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### No data in Discover after installation

- Confirm the Elastic Agent is running and has network access to `https://platform.socradar.com`.
- Check the agent logs in **Fleet → Agents**.
- Verify your API Key and Company ID are correct.

## Performance and scaling

The integration polls the SOCRadar alarms endpoint once per **Polling Interval** (default `5m`) and pages through the results using **Records per page** (default `100`) until it reaches the last page.

- The first collection replays the whole **Initial Lookback Period** (default `72h`, configurable up to `8760h`). A large lookback issues many paged requests in a single cycle, so start with a smaller window if you are close to your SOCRadar API quota.
- Each alarm is indexed under a document ID derived from its alarm ID, so an alarm that is re-fetched (for example when a mid-pagination retry replays an earlier page) is rejected as a duplicate rather than indexed twice.
- Lower the polling interval only if your alarm volume justifies it; every collection cycle costs at least one API request.

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Incidents

The `incidents` data stream collects alarm events from the SOCRadar API.

{{event "incidents"}}

#### Incidents fields

{{ fields "incidents" }}

### Inputs used

{{ inputDocs }}

### API usage

These APIs are used with this integration:

- `GET /api/company/{company_id}/incidents/v4` — Fetches paginated alarm events. Supports `start_date`, `page`, `limit`, and `include_alarm_details` query parameters.
