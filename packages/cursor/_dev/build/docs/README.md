{{- generatedHeader }}
# Cursor

## Overview

The Cursor integration collects audit logs from [Cursor](https://cursor.com), an AI-native code editor built as a fork of Visual Studio Code. Cursor Enterprise teams generate audit events for security-relevant activities such as user authentication, role changes, team configuration updates, API key management, directory group operations, and security controls. This integration enables security and compliance teams to monitor administrative activity, detect unauthorized changes, and maintain an audit trail of team operations.

### Compatibility

This integration requires a **Cursor Enterprise** plan. The Admin API and S3 streaming delivery are available only to Enterprise-tier teams.

This integration supports two methods for collecting Cursor audit logs:

- **Admin API (CEL input):** the Elastic Agent polls the Cursor Admin API at `https://api.cursor.com` on a configurable schedule. The Cursor Admin API only retains audit events for the last 30 days.
- **S3 Streaming (AWS S3 input):** Cursor delivers audit logs to a customer-owned S3 bucket as gzip-compressed NDJSON files (`.jsonl.gz`) in date-partitioned paths (`YYYY/MM/DD/`). S3 streaming must be enabled on the Cursor side; contact `hi@cursor.com` to request it.

Both input methods feed the same `audit` data stream and share a common ingest pipeline that normalizes events from either source into a unified schema.

## What data does this integration collect?

The Cursor integration collects audit log events covering 30+ event types across these categories:

* **Authentication events:** User logins (`login`) and logouts (`logout`), including login type and success/failure status (S3 format only).
* **User lifecycle events:** Adding (`add_user`), removing (`remove_user`), and changing roles (`update_user_role`) of team members.
* **Team configuration events:** Settings changes (`team_settings`), privacy mode toggles (`privacy_mode`), spend limit adjustments (`user_spend_limit`), team rules (`team_rule`), repository settings (`team_repo`), webhooks (`team_hook`), custom commands (`team_command`), and cloud agent user settings (`cloud_agent_user_settings`).
* **API key management:** Team (`team_api_key`), user (`user_api_key`), and organization (`organization_api_key`) API key creation and revocation.
* **Directory group management:** Creating, updating, deleting directory groups, modifying permissions, and managing group membership.
* **Bugbot operations:** Installation, settings, repository configuration, team rules, team settings, and bulk repository updates for the Bugbot CI assistant.
* **Security and access control events:** Protected git scope management (`protected_git_scope`), access checks (`protected_git_scope_access_check`), service accounts (`service_account`), cloud agent secrets (`cloud_agent_secret`), invite links (`invite_link`), and invite emails (`invite_email_sent`).

### Supported use cases

- **Security monitoring:** Track authentication patterns, detect unauthorized access attempts (the S3 format captures login failures), and monitor privileged operations such as API key management and role changes.
- **Compliance auditing:** Maintain a complete audit trail of administrative actions for regulatory compliance (SOC 2 Type II). All events include actor identity, source IP, and timestamp.
- **Operational visibility:** Monitor team configuration changes, directory group management, and Bugbot operations to understand who changed what and when.
- **Incident investigation:** Correlate audit events with GeoIP-enriched source IPs and related user identities to investigate security incidents.

## What do I need to use this integration?

- A **Cursor Enterprise** plan (the Admin API and S3 streaming are not available on lower tiers).
- An **Admin API key** (for the CEL input) or an **S3 streaming configuration** (for the AWS S3 input).
- **Elastic Agent** installed on a host with outbound HTTPS access to `api.cursor.com` (CEL input) or access to the S3 bucket and SQS queue (S3 input).

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data and ship it to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Onboard / configure

#### Option A: Admin API (CEL input)

1. Log in to [cursor.com/dashboard](https://cursor.com/dashboard) with a team administrator (owner) account.
2. Navigate to **Settings → Advanced → Admin API Keys**.
3. Click **Create New API Key**, provide a descriptive name, and copy the generated key immediately (it cannot be retrieved later). The key format is `key_` followed by hexadecimal characters.
4. In Kibana, add the **Cursor** integration and select the **Collect Cursor audit logs via the Admin API** input.
5. Enter the API key and configure the polling interval (default: 5 minutes). The default initial lookback is 24 hours.
6. Optionally filter by event types using a comma-separated list (for example, `login,add_user,team_settings`).

#### Option B: S3 Streaming (AWS S3 input)

1. Contact Cursor (`hi@cursor.com`) to arrange S3 streaming delivery of audit logs to your AWS S3 bucket.
2. Cursor writes gzip-compressed NDJSON files (`.jsonl.gz`) to a date-partitioned path structure (`YYYY/MM/DD/`) in your bucket.
3. Optionally configure S3 event notifications to an SQS queue for near-real-time processing (recommended over bucket polling).
4. Ensure IAM permissions are configured: `s3:GetObject` and `s3:ListBucket` for bucket polling; add `sqs:ReceiveMessage`, `sqs:DeleteMessage`, and `sqs:GetQueueAttributes` if using SQS.
5. In Kibana, add the **Cursor** integration and select the **Collect Cursor audit logs via AWS S3 or AWS SQS** input.
6. Configure either the S3 bucket name (for direct polling) or the SQS queue URL (for notification-based processing) along with AWS credentials.

### Validation

After deploying the integration:

1. Navigate to **Discover** in Kibana and filter for `data_stream.dataset: "cursor.audit"`.
2. Verify that events are being ingested with correct `event.action` values (for example, `login`, `add_user`, `team_settings`).
3. Check that `@timestamp`, `source.ip`, `user.email`, and ECS categorization fields (`event.category`, `event.type`) are populated.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

**Rate limits (CEL input):** The Cursor Admin API enforces a limit of 20 requests per minute per team. The default polling interval of 5 minutes keeps usage well within this limit. If you encounter `429` errors, increase the polling interval.

**30-day retention (CEL input):** The Cursor Admin API only serves audit events from the last 30 days. The integration automatically clamps the initial lookback to a maximum of 30 days, so configuring a larger `Initial Lookback Interval` will still produce a valid backfill — it simply collects the previous 30 days.

**`"unknown"` values (S3 input):** System-initiated events (for example, auto-enrolled users or automated removals) can have `ip_address` and `user_email` set to `"unknown"`. The pipeline handles this gracefully and does not attempt IP conversion on these sentinel values.

**Multiple agents:** Run a single Elastic Agent instance per Cursor team to avoid rate limit contention. Multiple agents polling the same team share the 20 requests-per-minute budget.

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

For high-volume teams, the S3 streaming input is recommended as it is not subject to API rate limits and provides near-real-time delivery.

## Reference

### Audit

The `audit` data stream collects audit log events from Cursor covering authentication, user management, team configuration, API key lifecycle, directory group operations, Bugbot management, and security controls. It supports two input methods: Admin API polling and S3 streaming via AWS S3/SQS.

#### Audit fields

{{ fields "audit" }}

#### Sample event

{{ event "audit" }}

{{ ilm }}

{{ transform }}

### Inputs used

{{ inputDocs }}

### API usage

These APIs and services are used with this integration:

* [Cursor Admin API — Get Audit Logs](https://cursor.com/docs/account/teams/admin-api#get-audit-logs): retrieves audit log events with time-based filtering. Optional filtering by event type is supported. Audit events are retained for 30 days.
* [Cursor S3 Streaming](https://cursor.com/docs/enterprise/compliance-and-monitoring): Enterprise customers can arrange streaming delivery of audit logs to an S3 bucket. Files are gzip-compressed NDJSON (`.jsonl.gz`) organized in `YYYY/MM/DD/` date-partitioned paths.
