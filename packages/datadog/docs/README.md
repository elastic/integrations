# Datadog Audit Logs

Collects the Datadog audit trail from an S3 bucket written by
[Datadog Log Archives](https://docs.datadoghq.com/logs/log_configuration/archives/),
using SQS object-created notifications for near-real-time delivery.

## Data flow

1. In Datadog, configure a Logs Archive with the query `source:audit`, targeting
   an S3 bucket. Datadog writes gzipped NDJSON objects to a date-partitioned
   prefix (`dt=YYYYMMDD/hour=HH/archive_*.json.gz`), one audit event per line.
2. Configure an S3 event notification on that bucket for `s3:ObjectCreated:*`,
   delivering to an SQS queue.
3. Point this integration at the bucket ARN and the SQS queue URL.

If no queue URL is supplied, the integration falls back to polling the bucket on
the configured interval. SQS is strongly preferred — polling re-lists the bucket
on every interval and does not scale with archive volume.

## Required AWS permissions

- `s3:GetObject` on the archive prefix
- `s3:ListBucket` on the bucket (polling mode only)
- `sqs:ReceiveMessage`, `sqs:DeleteMessage`, `sqs:GetQueueAttributes` on the queue

Prefer `role_arn` over static access keys.

## Data stream

`datadog.audit` — all audit surfaces (API requests, workflows, agent
configuration changes, dashboards, organization management, MCP server calls,
audit-trail queries) in one stream.

## Notable fields

| Field | Description |
|---|---|
| `datadog.event.name` | Datadog product surface (`Request`, `Workflows`, `Dashboard`, …) |
| `datadog.action` | Raw Datadog verb (`accessed`, `modified`, `created`, …) |
| `event.action` | Composite `<surface>_<verb>`, e.g. `dashboard_modified` |
| `datadog.route.path` | Templated API route — aggregate on this, not `url.path`, which contains IDs |
| `datadog.actor.type` | `USER`, `SYSTEM`, or `SERVICE_ACCOUNT` |
| `datadog.auth_method` | `SESSION`, `SYSTEM`, `API_AND_APP_KEY`, `OAUTH_TOKEN` |
| `datadog.threat_intel.*` | Datadog's Spur-sourced IP enrichment, including VPN/proxy tunnel detail |
| `datadog.asset.new_value` / `.prev_value` | `flattened` before/after blobs for configuration changes |
| `datadog.metadata` | `flattened` catch-all for surface-specific metadata |
| `related.user` | Every actor identifier in the event, including API key and OAuth client IDs |

`datadog.asset.new_value`, `datadog.asset.prev_value`, `datadog.metadata`, and `datadog.threat_intel` are
`flattened`. They are queryable in KQL and DSL by subkey, but **not** in ES|QL,
which hard-errors on `flattened`. Stable dimensions are lifted into typed
sibling fields for that reason.

## Dashboard

![Datadog Audit Logs Dashboard](../img/Datadog_dashboard.png)
