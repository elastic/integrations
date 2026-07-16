{{- generatedHeader }}

# Kolide Integration for Elastic

## Overview

The Kolide integration for Elastic collects device-trust and endpoint-compliance logs from Kolide (by 1Password). It ingests authentication sessions, posture issues, approval-workflow requests, device inventory, trust-status changes, people identity records, and administrative audit events. The integration normalizes these logs to the Elastic Common Schema (ECS) so you can use them for search, visualization, and detection in Elastic.

### Compatibility

This integration works with the current Kolide Device Trust platform ("Kolide K2"), its public REST API (version `2026-04-07`), and webhooks. It doesn't support the legacy open-source Kolide Fleet (osquery) product.

This integration is compatible with Elastic Stack version 8.19.0 or later.

### How it works

The integration supports four collection methods that you can choose between and combine when you configure it:

- Webhooks (HTTP endpoint): Kolide pushes events in near real time to an HTTP endpoint that Elastic Agent exposes. This is the recommended method for low-latency device-compliance data. Each delivery is signed with an HMAC-SHA256 signature for verification.
- REST API (polling): Elastic Agent periodically polls the Kolide REST API and collects records using cursor-based pagination and timestamp filters where supported. This is useful for backfill and for fuller resource records.
- AWS S3 (Kolide Log Pipeline): Kolide's Log Pipeline writes objects to a customer-owned S3 bucket under per-type key prefixes (default values are `kolide/auth_logs/`, `kolide/audit_logs/`, `kolide/check_runs/`, `kolide/results/`, and `kolide/status/`). Elastic Agent reads each prefix using an `aws-s3` input through SQS notifications or direct bucket polling. The `auth` and `audit` data streams can read their respective prefixes. The dedicated `device_check` data stream reads `kolide/check_runs/`, and the dedicated `osquery_result` and `osquery_status` data streams read `kolide/results/` and `kolide/status/`, which are the raw osquery result and status logs. The Log Pipeline is the most complete source for check-run history because it includes passing, inapplicable, and unknown check results in addition to failures.
- Google Cloud Storage (Kolide Log Pipeline): The same Log Pipeline data is written to customer-owned GCS buckets under the same per-type key prefixes and read using a `gcs` input through bucket polling. The object payloads are identical to the S3 delivery, so the same `auth`, `audit`, `device_check`, `osquery_result`, and `osquery_status` data streams apply. You can choose S3 or GCS depending on which cloud your Kolide log destination targets.

## What data does this integration collect?

The Kolide integration collects the following data streams:

- `webhook`: A single webhook ingress that receives all Kolide webhook event types on one endpoint and routes each event to the correct data stream automatically.
- `auth`: SSO authentication sessions (`auth_logs.success` and `auth_logs.failure` using the API endpoint `GET /auth_logs`).
- `issues`: Device posture-check failures and resolutions (`issues.new` and `issues.resolved` using the API endpoint `GET /issues`).
- `request`: Approval-workflow requests (`requests.issue_exemption` and `requests.registration` using the API endpoints `GET /exemption_requests` and `GET /registration_requests`, as well as request webhooks).
- `device`: Device inventory and trust-status changes (`devices.created`, `devices.registered`, `devices.destroyed`, and `device_trust.status_changed` using the API endpoint `GET /devices`).
- `people`: Identity records for people known to Kolide using the API endpoint `GET /people`.
- `deprovisioned_person`: Identity records for people who have been offboarded or deprovisioned in Kolide using the API endpoint `GET /deprovisioned_people`. This is a separate resource from `people`.
- `audit`: Administrative audit logs of console actions (`audit_log.recorded` using the API endpoint `GET /audit_logs` or Log Pipeline S3/GCS paths under `kolide/audit_logs/`).
- `device_check`: Device check-run results from the Log Pipeline (S3/GCS paths under `kolide/check_runs/`), covering every run including `passing`, `failing`, `inapplicable`, and `unknown` statuses. This complements the failure-focused `issues` data stream.
- `osquery_result`: Raw osquery Result Logs from the Log Pipeline (S3/GCS paths under `kolide/results/`), covering both snapshot-query rows and differential (`added` and `removed`) rows. Per-query column data is stored as a flattened field rather than mapped per column, since it is arbitrary and depends on the target osquery table or custom SQL.
- `osquery_status`: Raw osquery Status Logs from the Log Pipeline (S3/GCS paths under `kolide/status/`), which contain GLOG-style telemetry about the osquery daemon itself rather than host inventory state.

The `auth` and `audit` data streams also support the Log Pipeline using the `aws-s3` and `gcs` inputs that read the `kolide/auth_logs/` and `kolide/audit_logs/` prefixes.

### Osquery result and status details

The `osquery_result` and `osquery_status` data streams ingest raw osquery agent logs, unlike the other Log Pipeline streams in this integration (`auth`, `audit`, and `device_check`), which are Kolide's own structured logs. The integration populates `host.id` and `host.name` from Kolide's `kolide_decorations` block. This block is only present when the device is enrolled with Kolide's own launcher. A bare open-source osquery deployment shipping logs through the Log Pipeline only carries osquery's own `hostIdentifier` (stored in `kolide.osquery_result.host_identifier` and `kolide.osquery_status.host_identifier`), and `host.id` and `host.name` do not populate. Per-query row data (`kolide.osquery_result.added`, `kolide.osquery_result.removed`, and `kolide.osquery_result.snapshot`) is a `flattened` field rather than a per-column mapping, since the columns are arbitrary and depend on the target osquery table or custom SQL. This keeps the mapping bounded, but means individual columns do not get native Kibana Lens numeric or date typing, or exact-match aggregations.

### Event outcome for posture data

For the `device_check` and `issues` data streams, `event.outcome` reflects the device posture result rather than the success of event processing. A check run with status `passing` (or a resolved issue) maps to `event.outcome: success`. A check run with status `failing` (or an open issue) maps to `event.outcome: failure`. An `inapplicable` or `unknown` check status maps to `event.outcome: unknown`. The integration preserves the raw posture state in `kolide.device_check.status` for `device_check`.

### Host correlation for device checks

Check-run results identify the device only by its numeric Kolide device ID, which maps to `host.id`. The payload carries no hostname, so the integration does not set `host.name` on this data stream. You can correlate check runs with the `device`, `auth`, and `issues` data streams using the shared `host.id`. If you need `host.name` directly on check-run documents, you must enrich them at ingest time with an Elasticsearch [enrich policy](https://www.elastic.co/docs/manage-data/ingest/transform-enrich/data-enrichment) that maps `host.id` to `host.name` from the `device` data stream. This setup requires you to enable the `device` data stream and periodically refresh the enrich policy so new or renamed devices resolve correctly.

### Document identity for requests

The Kolide REST API endpoints `GET /exemption_requests` and `GET /registration_requests` do not support a modified-since filter, so the integration re-fetches every request on every poll. To prevent duplicate indexing of unchanged requests, the integration deduplicates documents using the request identity (a combination of `kolide.request.id` and `kolide.request.type`), its current status, and decision notes. This means the `request` data stream reflects each request's latest known status. It provides one document per request that is updated as its status changes, rather than a full history of every transition. Kolide allows reopening a previously approved or denied request, meaning a request can cycle through the same status multiple times. If a request is re-decided with the exact same status and decision note text as a previous decision, the integration deduplicates it as a duplicate event. To view the full timeline of who approved, denied, or reopened a request, use the `audit` data stream (`audit_log.recorded`), and correlate the events using `user.target.email` and `rule.name`.

### Document identity for people

The endpoint `GET /people` returns a full-table snapshot with no modified-since filter, so the integration re-fetches every person on every poll. To prevent unnecessary indexing, the integration deduplicates documents using a fingerprint of the entire raw record, excluding `last_authenticated_at`. This exclusion prevents a new document from being created every time an active person authenticates. A change to any other field (such as name, email, registered-device status, or SCIM usernames) produces a new document, while unchanged records are deduplicated across polls.

### Supported use cases

Integrating Kolide with Elastic provides a powerful solution for enhancing security posture and operational visibility. You can use this integration for the following use cases:

- Monitor device-trust posture and investigate SSO authentication outcomes alongside device compliance state.
- Track approval workflows, device enrollment, and blocking transitions.
- Correlate device activity with identity records of people.
- Audit administrative changes in Kolide.
- Correlate your Kolide device trust data with the rest of your security data in Elastic using the Elastic Common Schema (ECS).

## What do I need to use this integration?

Before you set up the Kolide integration, you must have the following:
- A Kolide tenant with Full Access administrator privileges to create API keys, webhook endpoints, or Log Pipeline destinations.
- An Elastic Agent installed on a host. Depending on your chosen ingestion method, the host must meet the following network requirements:
  - Receive Kolide webhooks on a publicly reachable HTTPS endpoint.
  - Reach the Kolide REST API at `https://api.kolide.com`.
  - Access your AWS S3 bucket or Amazon Simple Queue Service (SQS) queue.
  - Access your Google Cloud Storage (GCS) bucket.

If you're collecting data using the REST API or the Log Pipeline, you must also configure the following resources:
- A Kolide API key with the form `k2sk_v1_` created in your Kolide console under Settings → Developers → API Keys.
- An AWS Identity and Access Management (IAM) role or credentials with permissions to read from your AWS S3 bucket or SQS queue, if you use AWS.
- A Google Cloud Platform (GCP) service account JSON key with the Storage Object Viewer role to read from your GCS bucket, if you use GCP.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

Elastic Agent is required to receive webhook requests, poll the REST API, or read from S3 or GCS buckets and ship the data to Elastic, where the events will then be processed using the integration's ingest pipelines.

### Agentless deployment

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. Agentless deployments provide a means to ingest data while avoiding the orchestration, management, and maintenance needs associated with standard ingest infrastructure. Using an agentless deployment makes manual agent deployment unnecessary, allowing you to focus on your data instead of the agent that collects it.

For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

### Set up steps in Kolide

To set up steps in Kolide, you must have full access administrator privileges. Sign in to Kolide and choose one or more of the collection methods below.

#### Webhooks setup

To configure Kolide webhooks, complete the following steps:
1. Log in to your Kolide account and navigate to Settings, then Developers, and then Webhooks.
2. Select Add Webhook and create one new endpoint.
3. Provide a publicly reachable HTTPS URL pointing at the Elastic Agent listen address, port, and path, such as `https://<your-agent-host>:9550/kolide/webhook` (replace `<your-agent-host>` with the actual address or hostname of your Elastic Agent).
4. Subscribe the endpoint to all event types. The integration automatically routes each event to the correct data stream.
5. Copy the signing secret displayed on screen. This secret is shown only once and is required to configure the HMAC key on the Elastic side.

#### REST API setup

To configure the REST API, complete the following steps:
1. Log in to your Kolide account and navigate to Settings, then Developers, and then API Keys.
2. Select Create API Key. Read access is sufficient to retrieve logs.
3. Copy the API key. It is displayed only once and has the form `k2sk_v1_` followed by your token.

#### AWS S3 log pipeline setup

To configure the AWS S3 log pipeline, complete the following steps:
1. In Kolide, navigate to Log Destinations and select Amazon S3 Bucket to add a new destination.
2. Select the STS authorization method, which is the recommended approach.
3. Create an IAM role in your AWS account. Update the trust policy to allow Kolide's AWS account ID `516897320088` to assume the role, and restrict access using the External ID displayed in the Kolide console.
4. Grant the IAM role permissions for `s3:GetBucketLocation`, `s3:GetObject`, and `s3:PutObject` on your S3 bucket so Kolide can write logs.
5. Select the log types you want to deliver. The supported log types include authentication logs, audit logs, check results, and osquery Result or Status logs.
6. Configure the read permissions. The Elastic Agent reads the logs from your AWS S3 bucket and does not use Kolide's IAM role. You must configure the Elastic Agent with AWS credentials that have read access.
7. For SQS notification mode, configure an S3 event notification for `s3:ObjectCreated:*` to deliver notifications to your SQS queue. Grant your Elastic Agent IAM reader credentials the permissions for `s3:GetObject` on the bucket and `sqs:ReceiveMessage`, `sqs:DeleteMessage`, and `sqs:GetQueueAttributes` on the SQS queue.
8. For direct polling mode, grant your Elastic Agent IAM reader credentials the permissions for `s3:GetObject` and `s3:ListBucket` on the bucket.
9. If your bucket is encrypted using SSE-KMS, ensure the Elastic Agent IAM reader credentials also have `kms:Decrypt` permissions on the KMS key.

#### Google Cloud Storage log pipeline setup

To configure the Google Cloud Storage log pipeline, complete the following steps:
1. Log in to your Google Cloud Console, select your project, and create a GCS bucket.
2. Create a service account that can enumerate, read, and write objects in the bucket by granting it the Storage Object Admin role on the bucket, then generate a JSON key for this service account.
3. Log in to Kolide, navigate to Log Destinations, select GCP Storage Bucket, and enter a display name and the bucket name.
4. Paste the complete service account JSON key file contents into the field provided.
5. Select the log types to deliver. This integration supports Administrator Audit Logs, User Authentication Logs, Device Check Run Logs, and osquery Result and Status Logs. Keep the default object path templates because they match the integration's default file selectors.
6. Create a separate service account with read-only access (the Storage Object Viewer role) and generate a JSON key for it. The Elastic Agent uses this key to poll the bucket. Alternatively, if the Elastic Agent runs on a GCE or GKE instance, you can leave the credentials blank to use Application Default Credentials.

#### Vendor resources

The following resources provide additional information about setting up Kolide integrations:
- [Kolide Webhooks documentation](https://www.kolide.com/docs/developers/webhooks)
- [Kolide REST API reference](https://kolideapi.readme.io/reference)
- [Kolide Log Pipeline documentation](https://www.kolide.com/docs/admins/log-pipeline/overview)
- [Configuring Google Cloud Storage for the Log Pipeline](https://www.kolide.com/docs/using-kolide/log-pipeline/configuring-google-cloud-storage)

### Set up steps in Kibana

To set up the Kolide integration in Kibana, complete the following steps:
1. In Kibana, navigate to Management, select Integrations, and search for Kolide.
2. Select the Kolide integration, and click Add Kolide.
3. Configure the settings based on your chosen collection methods. You can enable and configure webhooks, the REST API, or log pipeline inputs.

#### Webhooks configuration

Configure the following settings to receive webhook events:

| Setting                 | Description                                                                                   |
| ----------------------- | --------------------------------------------------------------------------------------------- |
| Listen Address          | Bind address for the HTTP listener. Use `0.0.0.0` to listen on all interfaces.                |
| Listen Port             | Bind port for the HTTP listener, such as `9550`.                                              |
| URL Path                | The URL path to accept Kolide webhook requests on, such as `/kolide/webhook`.                 |
| Webhook Signing Secret  | The signing secret copied from the Kolide webhook settings. Used to verify HMAC signatures.   |
| Webhook Identifier      | The webhook endpoint identifier value from the Kolide webhook settings.                       |
| Preserve Original Event | Check this option to preserve a raw copy of the original event in the `event.original` field. |

#### REST API configuration

Configure the following settings to pull logs from the Kolide REST API:

| Setting                 | Description                                                                                   |
| ----------------------- | --------------------------------------------------------------------------------------------- |
| URL                     | The base URL of the Kolide REST API. The default is `https://api.kolide.com`.                 |
| API Key                 | The Kolide API key used as a Bearer token. This key has the form `k2sk_v1_`.                  |
| Interval                | How often the Kolide REST API is polled, such as `5m` (5 minutes).                            |
| Initial Interval        | How far back to look the first time the integration runs, such as `24h` (24 hours).           |
| Preserve Original Event | Check this option to preserve a raw copy of the original event in the `event.original` field. |

#### AWS S3 log pipeline configuration

Configure the following settings to collect logs from AWS S3:

| Setting                 | Description                                                                                                 |
| ----------------------- | ----------------------------------------------------------------------------------------------------------- |
| Access Key ID           | The AWS access key ID the Elastic Agent uses to read from the bucket or queue.                              |
| Secret Access Key       | The AWS secret access key the Elastic Agent uses to read from the bucket or queue.                          |
| Session Token           | The AWS session token for temporary credentials, if using STS.                                              |
| SQS Queue URL           | URL of the SQS queue receiving S3 object-created notifications.                                             |
| S3 Bucket ARN           | ARN of the S3 bucket to poll directly if not using SQS notifications, such as `arn:aws:s3:::kolide-bucket`. |
| Bucket List Prefix      | Prefix used to list objects in the bucket, such as `kolide/audit_logs/`.                                    |
| Number of Workers       | Number of workers that process the S3 objects or SQS messages.                                              |
| Preserve Original Event | Check this option to preserve a raw copy of the original event in the `event.original` field.               |

#### Google Cloud Storage log pipeline configuration

Configure the following settings to collect logs from Google Cloud Storage:

| Setting                 | Description                                                                                   |
| ----------------------- | --------------------------------------------------------------------------------------------- |
| Project ID              | The GCP project ID that the GCS bucket belongs to.                                            |
| Service Account Key     | The GCP service account JSON key contents with Storage Object Viewer read access.             |
| GCS Buckets             | The list of GCS buckets to poll in YAML format, specifying the bucket name.                   |
| File Selectors          | A list of regular expression patterns to filter which object keys are processed.              |
| Number of Workers       | Number of workers that process the GCS objects.                                               |
| Preserve Original Event | Check this option to preserve a raw copy of the original event in the `event.original` field. |

### Validation

To validate that the integration is working properly and ingesting data into Elasticsearch, perform the following steps:
1. Generate activity in Kolide, such as logging in via Single Sign-On (SSO) to trigger an authentication event, or running a manual device check.
2. In Kibana, navigate to Discover.
3. In the data view dropdown, select logs-*.
4. Search for incoming documents using the search query:
   ```kql
   data_stream.dataset: "kolide.webhook" or data_stream.dataset: "kolide.audit" or data_stream.dataset: "kolide.auth"
   ```
5. Verify that documents appear with recent timestamps and contains expected event values.
6. Navigate to Dashboards and select the [Logs Kolide] Overview dashboard to confirm that the visualizations are successfully populated with data.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Common configuration issues

If you encounter issues with your Kolide integration, use the following solutions to resolve them:

- No data from webhooks: Confirm the Kolide endpoint URL matches the Agent's listen address, port, and path. Verify that the endpoint is publicly reachable over HTTPS and that the HMAC signing secret matches.
- Webhook signature failures: Ensure the configured HMAC key matches the Kolide endpoint signing secret. Kolide signs the raw request body with HMAC-SHA256 and sends the lowercase hex digest in the `Authorization` header with no prefix.
- No data using the REST API: Verify the API key is valid. A 401 error code indicates a disabled feature or bad token, and a 403 error code indicates the key lacks permission. Confirm that the host can reach `https://api.kolide.com`.
- No data from AWS S3: Confirm the Elastic Agent credentials have permissions to run `s3:ListBucket` and `s3:GetObject` on the bucket. If you're using SQS mode, ensure the credentials have permissions for `sqs:ReceiveMessage`. Check that the bucket list prefix matches your Kolide object key template, and verify that SQS notifications are filtered to the correct prefix. Kolide writes to `kolide/auth_logs/`, `kolide/audit_logs/`, `kolide/check_runs/`, `kolide/results/`, and `kolide/status/` by default.
- No data from Google Cloud Storage: Confirm the project ID and bucket name are correct. Ensure that the reader service account has the `Storage Object Viewer` role on the bucket. Verify that each stream's file selector regex matches your Kolide object key template. By default, the templates expect the `kolide/auth_logs/`, `kolide/audit_logs/`, `kolide/check_runs/`, `kolide/results/`, and `kolide/status/` prefixes.
- No host ID or host name on osquery result or osquery status documents: These fields are populated from Kolide's `kolide_decorations` block, which requires the device to be enrolled with Kolide's own launcher. A bare open-source osquery deployment shipping logs through the Log Pipeline only carries `kolide.osquery_result.host_identifier` or `kolide.osquery_status.host_identifier` (osquery's own `hostIdentifier`), not the Kolide-decorated host fields.

### Vendor resources

For more details on configuring Kolide, check the following resources:

- [Kolide Developer API Documentation](https://developer.kolide.com)
- [Kolide Log Pipeline Documentation](https://k2.kolide.com/x/features/log-pipeline)

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

### Choosing a transport per data stream

Kolide's Log Pipeline writes one log per object rather than batching, so the AWS S3/SQS and GCS inputs make a separate fetch for every document. For high-volume streams this is fine, but for small, sparse streams it adds many network round-trips and can make large backlogs slow to drain. To keep latency low and avoid contention on a shared S3 queue, you can match the transport to the stream.

To optimize your ingestion, configure the transports using these guidelines:
- For `audit` and `auth` data streams, prefer the REST API (CEL) or webhook inputs. These streams are typically small and sparse, and the API or webhook paths deliver them quickly without per-object fetches.
- For `device_check`, `osquery_result`, and `osquery_status` data streams, use the AWS S3 or GCS input because they're the only collection methods available. These streams are typically large or high-volume. The `osquery_result` stream is especially large because every scheduled query execution can produce a log line, making object storage the appropriate fit. Keeping them in object storage also keeps the small, important streams off the same queue.

This split keeps the small streams responsive while still using object storage for the bulk data.

If you consume large streams over S3/SQS or GCS, you can increase throughput by running multiple Elastic Agents or scaling out workers to process objects concurrently. The one-object-per-log behavior is a Kolide-side limitation. This guidance is a workaround until Kolide addresses the issue upstream.

## Reference

### Inputs used

{{ inputDocs }}

### API usage

The integration uses the following Kolide REST API endpoints to retrieve logs and telemetry:
- `GET /auth_logs`
- `GET /issues`
- `GET /exemption_requests`
- `GET /registration_requests`
- `GET /devices`
- `GET /people`
- `GET /deprovisioned_people`
- `GET /audit_logs`

### Vendor documentation links

You can refer to the following vendor documentation for more details about Kolide features and APIs:
- [Kolide documentation](https://www.kolide.com/docs)
- [Kolide Webhooks](https://www.kolide.com/docs/developers/webhooks)
- [Kolide REST API reference](https://kolideapi.readme.io/reference)
- [Kolide Log Pipeline](https://www.kolide.com/docs/admins/log-pipeline/overview)

### Data streams

This integration uses these data streams to organize collected logs and metrics:

#### webhook

The `webhook` data stream is the single ingress point for all Kolide webhook events. It listens on one HTTP endpoint and uses the ingest `reroute` processor to redirect each event to the appropriate target data stream, such as `auth`, `issues`, `device`, or `audit`, based on the Kolide event type. No documents are stored in the `webhook` data stream itself.

##### webhook fields

{{ fields "webhook" }}

#### auth

The `auth` data stream provides Kolide SSO authentication sessions. This includes the device-trust posture at sign-in, the client IP address and geolocation, and the sub-events of the session.

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

#### request

The `request` data stream collects approval-workflow requests from the Kolide REST API using the `GET /exemption_requests` and `GET /registration_requests` endpoints, as well as request webhooks. The logs from these endpoints are normalized into a single data stream with `kolide.request.type` set to either `exemption` or `registration`.

##### request fields

{{ fields "request" }}

##### request sample event

{{ event "request" }}

#### device

The `device` data stream provides Kolide device inventory records and device-trust status changes. Because the `GET /devices` endpoint does not expose a modified-since cursor, each interval retrieves the complete collection. The ingest pipeline assigns a content-based document `_id` so unchanged devices are deduplicated across polls, while any change is captured as a new document.

##### device fields

{{ fields "device" }}

##### device sample event

{{ event "device" }}

#### people

The `people` data stream provides Kolide identity records for active people using the `GET /people` endpoint. This includes Elastic Common Schema (ECS) user fields, SCIM-imported usernames, last-authentication time, and device-registration flags that Kolide exposes on this resource. Group, identity provider (IdP), SCIM, and deprovisioning details live on separate Kolide API resources like `person_groups` and `deprovisioned_people` that this data stream does not collect. Because the `GET /people` endpoint does not expose a modified-since cursor, each interval retrieves the complete collection. The ingest pipeline derives a content-fingerprint document `_id`, excluding `last_authenticated_at`, so byte-identical records are deduplicated across polls; records whose tracked fields change between polls are indexed as new documents rather than overwriting the prior one.

##### people fields

{{ fields "people" }}

##### people sample event

{{ event "people" }}

#### deprovisioned_person

The `deprovisioned_person` data stream provides Kolide identity records for people who have been offboarded or deprovisioned using the `GET /deprovisioned_people` endpoint. This is a separate API resource from `people` rather than a field on the person object. You can use this data stream to detect lingering access or devices owned by departed identities. Unlike the `people` data stream, this resource does not return SCIM usernames, but it includes an `api_url` field that links back to the corresponding `GET /people/{id}` resource.

Because the `GET /deprovisioned_people` endpoint does not expose a modified-since cursor, each interval collects the complete collection. This full collection retrieval is intentional because an incremental approach cannot detect when records disappear from the list, for example when a user is re-provisioned, when a Kolide-side correction is made, or when records are missed because of pagination drift. The ingest pipeline derives a content-fingerprint document `_id`, excluding `last_authenticated_at`, so duplicate records are deduplicated across polls. Records with tracked fields that change between polls are indexed as new documents.

##### deprovisioned_person fields

{{ fields "deprovisioned_person" }}

##### deprovisioned_person sample event

{{ event "deprovisioned_person" }}

#### audit

The `audit` data stream provides the Kolide administrative audit log of console actions using the `GET /audit_logs` endpoint.

##### audit fields

{{ fields "audit" }}

##### audit sample event

{{ event "audit" }}

#### device_check

The `device_check` data stream provides Kolide device check-run results delivered through the Kolide Log Pipeline using an Amazon S3 bucket. You can configure this using Amazon SQS notifications or direct bucket polling. Unlike the `issues` data stream, which tracks the failure lifecycle, this stream records every check run, including these check statuses:
- `passing`
- `failing`
- `inapplicable`
- `unknown`

##### device_check fields

{{ fields "device_check" }}

##### device_check sample event

{{ event "device_check" }}

#### osquery_result

The `osquery_result` data stream provides raw osquery Result Logs delivered through the Kolide Log Pipeline using Amazon S3 or Google Cloud Storage under the `kolide/results/` prefix. This includes both snapshot-query rows and differential (`added` and `removed`) rows. Per-query column data in `kolide.osquery_result.added`, `kolide.osquery_result.removed`, or `kolide.osquery_result.snapshot` is arbitrary and depends on the target osquery table or custom SQL, so it is stored as a flattened field rather than mapped per column.

##### osquery_result fields

{{ fields "osquery_result" }}

##### osquery_result sample event

{{ event "osquery_result" }}

#### osquery_status

The `osquery_status` data stream provides raw osquery Status Logs, which contain GLOG-style telemetry about the osquery daemon itself, delivered through the Kolide Log Pipeline using Amazon S3 or Google Cloud Storage under the `kolide/status/` prefix.

##### osquery_status fields

{{ fields "osquery_status" }}

##### osquery_status sample event

{{ event "osquery_status" }}

{{ ilm }}

{{ transform }}
