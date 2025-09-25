# Bitsight Integration

## Overview

The Bitsight integration ingests Vulnerability evidence from the Bitsight Threats API and enriches each event with the originating threat and company metadata. Use it to:
- Track newly reported exposures affecting your organizations
- Correlate Bitsight findings with Elastic Security investigations
- Monitor remediation progress over time

## Compatibility

- Transport: HTTP(S) to Bitsight Threats API

## Requirements

- A Bitsight API token with access to the Threats endpoints
- Elastic Agent with network egress to Bitsight

## Setup

1) In Kibana navigate to Integrations → Add integration → search for “Bitsight”.
2) Select the Vulnerability data stream and fill in:
   - Base URL (e.g., `https://api.bitsighttech.com`)
   - API token (Basic auth: username = token, password left blank)
   - Poll interval and batch size
   - Initial lookback window (how far back to fetch on first run)

## Data streams

### Vulnerability

The data stream walks the Threats API depth‑first and emits one document per evidence row:
- Threat list: `GET /ratings/v2/threats?category_slug=vulnerability&first_seen_date_gte=...&limit=...&sort=first_seen_date`
- Companies per threat: `GET /ratings/v2/threats/{threat_guid}/companies?limit=...`
- Evidence per company: `GET /ratings/v2/threats/{threat_guid}/companies/{company_guid}/evidence?limit=...`

Behavior
- Pagination: Follows `links.next` when present
- Cursor: Persists `cursor.last_first_seen_date` to resume between runs
- Backoff: Pauses on HTTP 429 or 5xx to avoid hammering the API (queue is preserved)
- Output: Each event is a JSON string with `threat`, `company`, and `evidence`

Mappings & ECS
- `event.kind=event`, `event.category=[vulnerability]`, `event.type=[info]`
- `vulnerability.id` derives from `bitsight.threat.name` (e.g., `CVE-…`)
- `host.ip` extracted from `bitsight.evidence.identifier` when it looks like `ip:port`

## Request tracing (support)

When enabled, the Agent writes HTTP traces to `logs/cel/http-request-trace-*.ndjson` on the host. These files may contain sensitive payloads—disable the tracer after capturing evidence.

## Troubleshooting

- 401/403: Verify the token is valid; Basic auth uses the token as the username and a blank password
- 429/5xx: The integration backs off and preserves the queue; check later or reduce polling rate
- No events: Confirm time window (initial lookback) and that Threats API returns results for the period
- Ingest mismatches: Use “Preserve original event” and compare `event.original` against decoded fields

## Reference

{{event "vulnerability"}}

{{fields "vulnerability"}}
