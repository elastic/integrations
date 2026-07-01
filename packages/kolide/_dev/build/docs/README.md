{{- generatedHeader }}
# Kolide Integration for Elastic

## Overview

The Kolide integration for Elastic collects device-trust and endpoint-compliance logs from [Kolide](https://www.kolide.com/) (by 1Password). It ingests authentication sessions, posture issues, device inventory and trust-status changes, and administrative audit events, normalizes them to the Elastic Common Schema (ECS), and makes them available for search, visualization, and detection in Elastic.

### Compatibility

This integration works with the current Kolide Device Trust platform ("Kolide K2") and its public REST API (version `2026-04-07`) and webhooks. It does not cover the legacy open-source Kolide Fleet (osquery) product.

### How it works

The integration supports three collection methods that you can choose between (and combine) when configuring it:

- Webhooks (HTTP endpoint): Kolide pushes events in near real time to an HTTP endpoint exposed by the Elastic Agent. This is the recommended method for low-latency device-compliance data. Each delivery is signed with an HMAC-SHA256 signature for verification.
- REST API (polling): the Elastic Agent periodically polls the Kolide REST API and collects new records using cursor-based pagination and a timestamp filter. This is useful for backfill and for fuller resource records.
- AWS S3 (Kolide Log Pipeline): Kolide's Log Pipeline writes objects to a customer-owned S3 bucket under per-type key prefixes (defaults: `kolide/auth_logs/`, `kolide/audit_logs/`, `kolide/check_runs/`); the Elastic Agent reads each prefix with an `aws-s3` input (SQS notifications or direct bucket polling). The `auth` and `audit` data streams can read their respective prefixes, and the dedicated `device_check` data stream reads `kolide/check_runs/`. S3 is the most complete source for check-run history — it includes passing, inapplicable, and unknown check results in addition to failures. Raw osquery `results` objects are not ingested.

## What data does this integration collect?

The Kolide integration collects the following data streams:

* `webhook`: single webhook ingress that receives all Kolide webhook event types on one endpoint and routes each event to the correct data stream automatically.
* `auth`: SSO authentication sessions (`auth_logs.success`, `auth_logs.failure`; API `GET /auth_logs`).
* `issues`: device posture-check failures and resolutions (`issues.new`, `issues.resolved`; API `GET /issues`).
* `device`: device inventory and trust-status changes (`devices.created`, `devices.registered`, `devices.destroyed`, `device_trust.status_changed`; API `GET /devices`).
* `audit`: administrative audit log of console actions (`audit_log.recorded`; API `GET /audit_logs`; Log Pipeline S3 `kolide/audit_logs/`).
* `device_check`: device check-run results from the Log Pipeline (S3 `kolide/check_runs/`), covering every run — `passing`, `failing`, `inapplicable`, and `unknown`. This complements the failure-focused `issues` data stream.

The `auth` and `audit` data streams additionally support the Log Pipeline via an `aws-s3` input that reads the `kolide/auth_logs/` and `kolide/audit_logs/` prefixes.

> **Note on `event.outcome` for posture data:** For the `device_check` and `issues` data streams, `event.outcome` reflects the device posture result, not the success of event processing. A check run with status `passing` (or a resolved issue) maps to `event.outcome: success`, `failing` (or an open issue) maps to `event.outcome: failure`, and `inapplicable` or `unknown` check statuses map to `event.outcome: unknown`. The raw posture state is also preserved in `kolide.device_check.status` for `device_check`.

> **Note on host correlation for `device_check`:** Check-run results identify the device only by its numeric Kolide device ID, mapped to `host.id`. The payload carries no hostname, so `host.name` is not set on this data stream. Correlate check runs with the `device`, `auth`, and `issues` data streams using the shared `host.id`. If you need `host.name` directly on check-run documents, enrich them at ingest time with an Elasticsearch [enrich policy](https://www.elastic.co/docs/manage-data/ingest/transform-enrich/data-enrichment) that maps `host.id` to `host.name` from the `device` data stream. This requires the `device` data stream to be enabled and the enrich policy to be executed and periodically refreshed so new or renamed devices resolve.

### Supported use cases

Monitoring device-trust posture, investigating SSO authentication outcomes alongside device compliance state, tracking device enrollment and blocking transitions, and auditing administrative changes in Kolide — all correlated with the rest of your security data in Elastic via ECS.

## What do I need to use this integration?

- Elastic Agent installed on a host that can receive Kolide webhooks (a publicly reachable HTTPS endpoint), reach `https://api.kolide.com`, or read from your AWS S3 bucket or SQS queue.
- A Kolide tenant with Full Access administrator privileges to create API keys, webhook endpoints, or Log Pipeline destinations.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

### Set up steps in Kolide

As a Full Access administrator, sign in to Kolide and choose one or more collection methods:

For webhooks:
1. Go to Settings → Developers → Webhooks and add **one** new endpoint.
2. Provide a publicly reachable HTTPS URL pointing at the Elastic Agent's listening address, port, and path (for example, `https://<agent-host>:9550/kolide/webhook`).
3. Subscribe the endpoint to **all** event types — the integration routes each event to the correct data stream automatically.
4. Copy the endpoint signing secret (shown once) — you will provide it to the integration as the HMAC key.

For the REST API:
1. Go to Settings → Developers → API Keys and create a new key (read access is sufficient).
2. Copy the API key (shown once); it has the form `k2sk_v1_...`.

For the AWS S3 Log Pipeline:
1. In Kolide, go to Log Destinations and add a new Amazon S3 Bucket destination.
2. Choose STS (recommended): create an IAM role in your own AWS account whose trust policy allows Kolide's AWS account (`516897320088`) to assume it, gated by the External ID that Kolide displays. Grant the role `s3:GetBucketLocation`, `s3:GetObject`, and `s3:PutObject` on the bucket so Kolide can write logs.
3. Select the log types to deliver (authentication logs, audit logs, and check results) and, optionally, customize the object key template.
4. On the read side, the Elastic Agent uses your own AWS credentials (not Kolide's role). For SQS mode, configure an S3 event notification (`s3:ObjectCreated:*`) to an SQS queue and grant the reader `s3:GetObject` plus `sqs:ReceiveMessage`, `sqs:DeleteMessage`, and `sqs:GetQueueAttributes`. For direct polling, grant `s3:GetObject` and `s3:ListBucket`. Add `kms:Decrypt` if the bucket uses SSE-KMS.

Note: Kolide sends webhooks from dynamic AWS us-east-1 IP addresses, so IP allow-listing is not a reliable control — rely on the HMAC signature instead.

#### Vendor resources
- [Kolide Webhooks documentation](https://www.kolide.com/docs/developers/webhooks)
- [Kolide REST API reference](https://kolideapi.readme.io/reference)
- [Kolide Log Pipeline documentation](https://www.kolide.com/docs/admins/log-pipeline/overview)

### Set up steps in Kibana

1. In Kibana, go to Management → Integrations and search for Kolide.
2. Add the integration.
3. For webhooks: enable the `webhook` data stream (HTTP endpoint input). Set the listen address, port, and URL path, and provide the HMAC signing secret (and optionally the `X-Kolide-Webhook-Identifier` value). All Kolide event types are received on this single endpoint and routed automatically.
4. For the REST API: enable whichever data streams you want to poll (auth, issues, device, audit), select the CEL input, provide the API URL (`https://api.kolide.com`), the API key, and adjust the polling interval and initial lookback as needed.
5. For AWS S3 (Log Pipeline): provide your AWS credentials once on the integration, then enable the `aws-s3` input on the data streams you want — `auth`, `audit`, or `device_check`. Each defaults to its Kolide prefix (`kolide/auth_logs/`, `kolide/audit_logs/`, `kolide/check_runs/`). For each, set either an SQS queue URL (SQS mode) or a bucket ARN (polling mode). In SQS mode, use a separate queue per prefix (filter S3 notifications by prefix); in polling mode each stream lists only its own prefix. Adjust the bucket list prefix if your Kolide destination uses a custom key template.

### Validation

After setup, generate or wait for activity in Kolide (for example, sign in via SSO to produce an auth log). In Kibana, open Discover and confirm documents are arriving in the `logs-kolide.*` data streams.

## Troubleshooting

- No data via webhooks: Confirm the Kolide endpoint URL matches the Agent's listen address, port, and path, that the endpoint is publicly reachable over HTTPS, and that the HMAC signing secret matches.
- Webhook signature failures: Ensure the configured HMAC key equals the Kolide endpoint signing secret; Kolide signs the raw request body with HMAC-SHA256 and sends the lowercase hex digest in the `Authorization` header with no prefix.
- No data via the REST API: Verify the API key is valid (a 401 indicates a turned-off feature or bad token, and a 403 indicates the key lacks permission) and that the host can reach `https://api.kolide.com`.
- No data via AWS S3: Confirm the Elastic Agent credentials can `s3:ListBucket` and `s3:GetObject` on the bucket (and `sqs:ReceiveMessage` in SQS mode), that the bucket list prefix matches your Kolide object key template, and that SQS notifications are filtered to the correct prefix. Kolide writes to `kolide/auth_logs/`, `kolide/audit_logs/`, and `kolide/check_runs/` by default; osquery `results/` objects are not ingested.

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

### Choosing a transport per data stream

Kolide's Log Pipeline writes one log per S3 object rather than batching, so the AWS S3/SQS input makes a separate fetch for every document. For high-volume streams this is fine, but for small, sparse streams it adds many network round-trips and can make large backlogs slow to drain. To keep latency low and avoid contention on a shared S3 queue, consider matching the transport to the stream:

- **`audit` and `auth`**: prefer the REST API (CEL) or webhook inputs. These streams are typically small and sparse, and the API/webhook paths deliver them quickly without per-object S3 fetches.
- **`device_check` (check runs)**: use the AWS S3 input. This stream is large, so S3 is the better fit, and keeping it on S3 keeps the small, important streams off the same queue.

This split keeps the small streams responsive while still using S3 for the bulk data.

If you do consume large streams over S3/SQS, you can increase throughput by running multiple Elastic Agents (or scaling out workers) so SQS messages are processed concurrently. Note the one-object-per-log behavior is a Kolide-side limitation. The guidance above is a workaround until it is addressed upstream.

## Reference

### Inputs used
{{ inputDocs }}

### API usage

These Kolide REST API endpoints are used by this integration:
* `GET /auth_logs`
* `GET /issues`
* `GET /devices`
* `GET /audit_logs`

### Vendor documentation links
- [Kolide documentation](https://www.kolide.com/docs)
- [Kolide Webhooks](https://www.kolide.com/docs/developers/webhooks)
- [Kolide REST API reference](https://kolideapi.readme.io/reference)
- [Kolide Log Pipeline](https://www.kolide.com/docs/admins/log-pipeline/overview)

### Data streams

#### webhook

The `webhook` data stream is the single ingress point for all Kolide webhook events. It listens on one HTTP endpoint and uses the ingest `reroute` processor to redirect each event to the appropriate target data stream (`auth`, `issues`, `device`, or `audit`) based on the Kolide event type. No documents are stored in the `webhook` data stream itself.

##### webhook fields

{{ fields "webhook" }}

#### auth

The `auth` data stream provides Kolide SSO authentication sessions, including the device-trust posture at sign-in, the client IP and geolocation, and the sub-events of the session.

##### auth fields

{{ fields "auth" }}

##### auth sample event

{{ event "auth" }}

#### issues

The `issues` data stream provides Kolide posture-check failures and resolutions for devices.

##### issues fields

{{ fields "issues" }}

##### issues sample event

{{ event "issues" }}

#### device

The `device` data stream provides Kolide device inventory records and device-trust status changes.

##### device fields

{{ fields "device" }}

##### device sample event

{{ event "device" }}

#### audit

The `audit` data stream provides the Kolide administrative audit log of console actions.

##### audit fields

{{ fields "audit" }}

##### audit sample event

{{ event "audit" }}

#### device_check

The `device_check` data stream provides Kolide device check-run results delivered through the Log Pipeline (S3). Unlike the `issues` data stream, which tracks the failure lifecycle, this stream records every check run — `passing`, `failing`, `inapplicable`, and `unknown`.

##### device_check fields

{{ fields "device_check" }}

##### device_check sample event

{{ event "device_check" }}

{{ ilm }}

{{ transform }}
