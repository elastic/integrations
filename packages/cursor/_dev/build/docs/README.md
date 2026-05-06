{{- generatedHeader }}
# Cursor

## Overview

The Cursor integration collects audit logs from [Cursor](https://cursor.com), an AI-native code editor built on Visual Studio Code. Cursor Enterprise teams generate audit events for security-relevant activities such as user authentication, role changes, team configuration updates, API key management, and directory group operations. This integration enables security and compliance teams to monitor administrative activity, detect unauthorized changes, and maintain an audit trail of team operations.

### Compatibility

This integration requires a **Cursor Enterprise** plan. The Admin API and S3 streaming delivery are available only to Enterprise-tier teams.

- **Admin API (CEL input):** Cursor Admin API at `https://api.cursor.com`. No versioning — the API uses a single, stable version.
- **S3 Streaming (AWS S3 input):** Requires S3 streaming delivery configured by Cursor (contact `hi@cursor.com`). Files are delivered as gzip-compressed NDJSON (`.jsonl.gz`) in date-partitioned paths (`YYYY/MM/DD/`).

### How it works

This integration supports two methods for collecting audit logs:

1. **REST API polling (CEL input):** The Elastic Agent polls the `GET /teams/audit-logs` endpoint on a configurable schedule (default: every 5 minutes). The CEL program handles pagination, time-based filtering, and automatic chunking of lookback windows longer than 30 days (API hard limit). Events are deduplicated using a fingerprint of the `event_id` field.

2. **S3 streaming (AWS S3 input):** Cursor pushes audit log files to a customer-owned S3 bucket in near-real-time. The Elastic Agent reads from the S3 bucket directly or via SQS notifications. This method provides richer event metadata (auth context, ghost mode, privacy mode, request correlation ID) and is not subject to API rate limits.

Both input methods feed the same `audit` data stream and share a common ingest pipeline that normalizes events from either format into a unified schema.

## What data does this integration collect?

The Cursor integration collects audit log events covering 30+ event types across these categories:

* **Authentication events:** User logins (`login`) and logouts (`logout`), including login type and success/failure status (S3 format).
* **User lifecycle events:** Adding (`add_user`), removing (`remove_user`), and changing roles (`update_user_role`) of team members.
* **Team configuration events:** Settings changes (`team_settings`), privacy mode toggles (`privacy_mode`), spend limit adjustments (`user_spend_limit`), team rules (`team_rule`), repository settings (`team_repo`), webhooks (`team_hook`), and custom commands (`team_command`).
* **API key management:** Team (`team_api_key`), user (`user_api_key`), and organization (`organization_api_key`) API key creation and revocation.
* **Directory group management:** Creating, updating, deleting directory groups, modifying permissions, and managing group membership.
* **Bugbot operations:** Installation, settings, repository configuration, team rules, team settings, and bulk repository updates for the Bugbot CI assistant.
* **Security events:** Protected git scope management (`protected_git_scope`), access checks (`protected_git_scope_access_check`), service accounts (`service_account`), cloud agent secrets (`cloud_agent_secret`), and invite links (`invite_link`).

### Supported use cases

- **Security monitoring:** Track authentication patterns, detect unauthorized access attempts (S3 format captures login failures), and monitor privileged operations such as API key management and role changes.
- **Compliance auditing:** Maintain a complete audit trail of administrative actions for regulatory compliance. All events include actor identity, source IP, and timestamp.
- **Operational visibility:** Monitor team configuration changes, directory group management, and Bugbot operations to understand who changed what and when.
- **Incident investigation:** Correlate audit events with GeoIP-enriched source IPs and related user identities to investigate security incidents.

## What do I need to use this integration?

- A **Cursor Enterprise** plan.
- An **Admin API key** (for the CEL input) or an **S3 streaming configuration** (for the AWS S3 input).
- **Elastic Agent** installed on a host with outbound HTTPS access to `api.cursor.com` (CEL input) or access to the S3 bucket / SQS queue (S3 input).

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data and ship it to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Onboard / configure

#### Option A: Admin API (CEL input)

1. Log in to [cursor.com/dashboard](https://cursor.com/dashboard) with a team administrator account.
2. Navigate to **Settings → Advanced → Admin API Keys**.
3. Click **Create New API Key**, provide a descriptive name, and copy the generated key immediately (it cannot be retrieved later). The key format is `key_` followed by hexadecimal characters.
4. In Kibana, add the **Cursor** integration and select the **Collect Cursor audit logs via the Admin API** input.
5. Enter the API key and configure the polling interval (default: 5 minutes). The default initial lookback is 24 hours.
6. Optionally filter by event types using a comma-separated list (e.g., `login,add_user,team_settings`).

#### Option B: S3 Streaming (AWS S3 input)

1. Contact Cursor (`hi@cursor.com`) to arrange S3 streaming delivery of audit logs to your AWS S3 bucket.
2. Cursor will write `.jsonl.gz` files to a date-partitioned path structure in your bucket.
3. Optionally configure S3 event notifications to an SQS queue for near-real-time processing (recommended over bucket polling).
4. Ensure IAM permissions are configured: `s3:GetObject`, `s3:ListBucket` for bucket polling; add `sqs:ReceiveMessage`, `sqs:DeleteMessage`, `sqs:GetQueueAttributes` if using SQS.
5. In Kibana, add the **Cursor** integration and select the **Collect Cursor audit logs via AWS S3 or AWS SQS** input.
6. Configure either the S3 bucket ARN (for direct polling) or the SQS queue URL (for notification-based processing) along with AWS credentials.

### Validation

After deploying the integration:

1. Navigate to **Discover** in Kibana and filter for `data_stream.dataset: "cursor.audit"`.
2. Verify that events are being ingested with correct `event.action` values (e.g., `login`, `add_user`, `team_settings`).
3. Check that `@timestamp`, `source.ip`, `user.email`, and ECS categorization fields (`event.category`, `event.type`) are populated.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

**Rate limits (CEL input):** The Cursor Admin API enforces a limit of 20 requests per minute per team. The default polling interval of 5 minutes and built-in rate limiting in the CEL program keep usage well within this limit. If you see `429` errors, increase the polling interval.

**30-day window limit (CEL input):** The Admin API restricts each request to a maximum 30-day time range. The CEL program automatically chunks longer lookback windows into 30-day segments during initial backfill.

**`"unknown"` values (S3 input):** System-initiated events (e.g., auto-enrolled users, automated removals) may have `ip_address` and `user_email` set to `"unknown"`. The pipeline handles this gracefully and does not attempt IP conversion on sentinel values.

**Multiple agents:** Run a single Elastic Agent instance per Cursor team to avoid rate limit contention. Multiple agents polling the same team will share the 20 req/min budget.

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

For high-volume teams, the S3 streaming input is recommended as it is not subject to API rate limits and provides near-real-time delivery.

## Reference

### Audit

The `audit` data stream collects audit log events from Cursor covering authentication, user management, team configuration, API key lifecycle, directory group operations, Bugbot management, and security events. It supports two input methods: REST API polling via CEL and S3 streaming via AWS S3/SQS.

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

* [Cursor Admin API — Get Audit Logs](https://cursor.com/docs/account/teams/admin-api#get-audit-logs): `GET /teams/audit-logs` — retrieves paginated audit log events with time-based filtering. Supports filtering by event type via the `eventTypes` query parameter. Authentication uses HTTP Basic with the Admin API key as the username and an empty password.
* [Cursor S3 Streaming](https://cursor.com/docs/enterprise/compliance-and-monitoring): Enterprise customers can configure streaming delivery of audit logs to an S3 bucket. Files are gzip-compressed NDJSON (`.jsonl.gz`) organized in `YYYY/MM/DD/` date-partitioned paths.
