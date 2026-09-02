# Datadog Audit Logs

## Overview

The Datadog Audit Logs integration collects Datadog audit trail events from an
Amazon S3 bucket written by [Datadog Log Archives](https://docs.datadoghq.com/logs/log_configuration/archives/).
It maps audit activity to ECS and provides a dashboard for investigating changes
to Datadog resources and accounts.

### Compatibility

This integration supports Elastic Stack 8.19.0 or later and 9.1.0 or later.
It requires Datadog Log Archives configured with an Amazon S3 destination.

### How it works

Datadog writes gzipped NDJSON audit events to a date-partitioned S3 prefix
(`dt=YYYYMMDD/hour=HH/archive_*.json.gz`). Elastic Agent reads the objects using
the AWS S3 input and sends one audit event per line to the `datadog.audit` data
stream.

S3 object-created notifications can be delivered to Amazon SQS for near-real-time
collection. In Polling mode, the integration polls the bucket at the configured
interval.

## What data does this integration collect?

The integration collects all Datadog audit surfaces, including API requests,
workflow activity, Agent configuration changes, dashboards, organization
management, MCP server calls, and audit-trail queries. Configure a Datadog Logs
Archive with the query `source:audit` to limit the archive to audit events.

## What do I need to use this integration?

- An Elastic deployment with Fleet and Elastic Agent.
- A Datadog account with [Datadog Log Archives](https://docs.datadoghq.com/logs/log_configuration/archives/)
  configured to write audit logs to an S3 bucket.
- An AWS identity that can read the archive objects.

The identity needs these permissions:

- `s3:GetObject` on the archive prefix.
- `s3:ListBucket` on the bucket when polling is enabled.
- `sqs:ReceiveMessage`, `sqs:DeleteMessage`, and `sqs:GetQueueAttributes` on the
  queue when SQS notifications are enabled.

Use an IAM role (`role_arn`) instead of static access keys when possible.

## How do I deploy this integration?

For general instructions on installing integrations and deploying Elastic Agent,
refer to the {{ url "getting-started-observability" "Getting started" }} guide.
This integration supports Fleet-managed Elastic Agent. Agentless deployment is
not supported.

### Configure Datadog Log Archives

1. In Datadog, create a Logs Archive with the query `source:audit` and an Amazon
   S3 destination. Datadog writes gzipped NDJSON objects to the archive.
2. Configure an S3 event notification for `s3:ObjectCreated:*` that delivers to
   an SQS queue when using SQS mode.
3. In Fleet, add the Datadog Audit Logs integration and configure the S3 bucket
   ARN, archive prefix, AWS region, and credentials.
4. Select SQS mode and provide the queue URL for near-real-time collection. For
   polling mode, leave the queue URL empty and set the polling interval.

### Validate the integration

Generate a Datadog audit event and confirm that it appears in the
`logs-datadog.audit-*` data stream. In Kibana Discover, filter for
`data_stream.dataset: datadog.audit` and verify that `event.action` and
`datadog.event.name` are populated.

## Troubleshooting

### No events arrive

- Confirm that the Datadog archive query is `source:audit` and that objects are
  being written to the configured bucket and prefix.
- Verify `s3:GetObject` and, for polling mode, `s3:ListBucket` permissions.
- For SQS mode, verify the S3 notification, queue URL, and SQS permissions.
- Check the Elastic Agent logs for AWS authentication or object-processing errors.

### Events are delayed

Use SQS mode for near-real-time delivery. Polling re-lists the bucket on every
interval and may become slower as the archive volume increases.

## Performance and scaling

SQS mode is recommended for production and supports scaling across multiple
Elastic Agents. Scope the S3 prefix to the Datadog archive and use the
`number_of_workers` setting to increase object-processing concurrency when the
archive produces a high volume of events. Start with the default settings and
measure agent CPU, memory, S3 request rate, and event ingestion latency before
increasing concurrency.

## Reference

### Notable fields

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

`datadog.asset.new_value`, `datadog.asset.prev_value`, `datadog.metadata`, and
`datadog.threat_intel` are `flattened`. They are queryable in KQL and DSL by
subkey, but not in ES|QL, which returns an error for `flattened` fields. Stable
dimensions are lifted into typed sibling fields for that reason.

### ECS field reference

{{ fields "audit" }}

### Dashboard

![Datadog Audit Logs Dashboard](../img/Datadog_dashboard.png)
