# aws_cloudtrail_otel

## Product Domain (AWS CloudTrail via OTel)

AWS CloudTrail is a governance, compliance, and security auditing service that records API activity and account events across an AWS organization. It captures who invoked an API, which service and operation were called, when and from where the request originated, whether it succeeded or failed, and which resources were affected. CloudTrail is the primary audit trail for IAM changes, resource provisioning, data-plane access in supported services, and cross-account activity—supporting security investigations, compliance reporting, and operational troubleshooting.

The Elastic **AWS CloudTrail Logs OpenTelemetry Assets** package is a content integration that ships Kibana dashboards for telemetry ingested via OpenTelemetry—not an Elastic Agent log shipper. Collection is typically configured with the EDOT Cloud Forwarder (ECF) for AWS or a standalone OpenTelemetry Collector using the `awss3receiver`, `awslogsencodingextension` (CloudTrail JSON format), and `elasticsearchexporter`. CloudTrail log files land in S3 (often under `AWSLogs/<account-id>/`) and are polled via SQS notifications; the OTel pipeline parses records into ECS-aligned documents indexed under the `aws.cloudtrail.otel` dataset.

This package complements the classic Elastic Agent **AWS** integration (`aws.cloudtrail` data stream) by targeting the OTel ingestion path. It provides a CloudTrail Logs Overview dashboard for monitoring API call volume, success vs. failure outcomes, top services and operations, access-key activity, client user agents, and error-code breakdowns across AWS accounts.

## Data Collected (brief)

Logs only (no metrics). The package expects data already ingested with `data_stream.dataset: aws.cloudtrail.otel` via OpenTelemetry; it does not define its own Elastic Agent data streams or ingest pipelines.

Each document represents one CloudTrail management or data event. Key fields surfaced in dashboards and typical OTel mappings include:

| Field area | Examples |
|---|---|
| **RPC / API context** | `rpc.system`, `rpc.service`, `rpc.method` (AWS service and operation) |
| **AWS identity & errors** | `aws.access_key.id`, `aws.error.code` |
| **Network & client** | `source.address`, `user_agent.original` |
| **Outcome** | Derived from presence of `aws.error.code` (success vs. failure) |

Standard CloudTrail attributes (event ID, event type and category, user identity ARN and type, session issuer, request/response parameters, resource ARNs, read-only flag, management vs. data event classification, etc.) may also be present depending on trail configuration and OTel encoding settings. Collection requires AWS CloudTrail enabled with S3 delivery, SQS queue notifications on the log bucket, and an OTel pipeline (ECF for AWS or collector with `awslogs_encoding/cloudtrail`).

## Expected Audit Log Entities

Evidence is from `packages/aws_cloudtrail_otel/docs/README.md`, the bundled **CloudTrail Logs Overview** dashboard (`packages/aws_cloudtrail_otel/kibana/dashboard/aws_cloudtrail_otel-9bfbe31c-e775-4ee4-9e34-a449e603d109.json`), and the OpenTelemetry `awslogsencodingextension` CloudTrail field mapping ([OTel Collector Contrib README](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/extension/encoding/awslogsencodingextension#cloudtrail-record-fields), tested at v0.138.0 per package README). This integration is **dashboards-only**—it expects data already ingested with `data_stream.dataset: aws.cloudtrail.otel` via ECF for AWS or a standalone OTel collector; there are no Elastic Agent data streams, ingest pipelines, or package test fixtures. Actor and target semantics follow native CloudTrail `userIdentity` and `resources` JSON, mapped to ECS-aligned OTel attributes at **collection time** (not post-ingest Elastic pipelines). Records are true **AWS API audit logs** (management and data events) plus separate **CloudTrail digest** integrity records. ECS `*.target.*` fields are **not populated** (`dev/target-fields-audit/out/target_enhancement_packages.csv` classifies `aws_cloudtrail_otel` as **none** for all target-entity fields; no row in `target_fields_audit.csv`). `destination.user.*` / `destination.host.*` are **not used** (absent from `destination_identity_hits.csv`). The classic Elastic Agent **`aws.cloudtrail`** data stream adds post-ingest entity enrichment (`user.entity.id`, `user.target.entity.id`, `service.target.entity.id`, `related.entity`, etc.) and sets **`event.action`** from `eventName`; the OTel path does **neither**. **`event.action` is absent** on the OTel path — CloudTrail `eventName` maps to **`rpc.method`** instead; the bundled dashboard groups operations by `rpc.method`, not `event.action`.

### Event action (semantic)

What operation or activity does each stream record?

| Action (normalized label) | Classification | Confidence | Evidence | Per-stream notes |
| --- | --- | --- | --- | --- |
| `AttachUserPolicy` | administration | high | Classic `aws.cloudtrail` fixture (`test-attach-user-policy-json.log-expected.json`); OTel README: `eventName` → `rpc.method` | **`aws.cloudtrail.otel`** — IAM policy attachment; representative mutating management API |
| `GetCallerIdentity` | authentication | high | Classic fixture (`test-get-caller-identity-json.log-expected.json`); dashboard "Top Services and Operations" ES\|QL groups by `rpc.method` | **`aws.cloudtrail.otel`** — STS identity lookup; read-only |
| `CreateDBInstance` | configuration_change | high | Classic fixture (`test-create-db-instance-json.log-expected.json`) | **`aws.cloudtrail.otel`** — RDS provisioning |
| `PutObject` / `GetObject` | data_access | high | Classic S3 fixtures in `packages/aws/data_stream/cloudtrail/_dev/test/pipeline/` | **`aws.cloudtrail.otel`** — S3 data-plane access when data events enabled |
| `UserAuthentication` | authentication | high | Classic fixture (`test-user-authentication.log`); `eventType: AwsServiceEvent` | **`aws.cloudtrail.otel`** — Identity Center / sign-in service event, not a direct API call |
| `ConsoleLogin` | authentication | high | Classic pipeline handles `event.action == 'ConsoleLogin'` (`default.yml` L1847–1851) | **`aws.cloudtrail.otel`** — AWS Management Console sign-in |
| `DeleteRule` | configuration_change | high | Classic fixture (`test-delete-rule-json.log`) | **`aws.cloudtrail.otel`** — EventBridge rule deletion |
| *(no per-event action)* | — | high | OTel README digest mapping — `aws.cloudtrail.digest.*` metadata only | **Digest records** — log-file integrity verification; no `userIdentity` or `eventName` |

CloudTrail **`eventName`** is the canonical per-event action (e.g. `AttachUserPolicy`, `GetCallerIdentity`, `PutObject`). On the OTel path it appears as **`rpc.method`**, not ECS **`event.action`**. Do not substitute **`rpc.system`** (`AwsApiCall`, `AwsServiceEvent`) or **`aws.event.category`** (`Management`, `Data`) for the operation verb — they classify record type and audit category, not the specific API call.

### Event action (ECS candidates)

| ECS / vendor field | Mapped to `event.action` today? | Mapping correct? | Recommended `event.action` value (from fixtures) | Enhancement candidate? | Evidence |
| --- | --- | --- | --- | --- | --- |
| CloudTrail `eventName` → `rpc.method` | no (maps to `rpc.method`) | partial | `AttachUserPolicy`, `GetCallerIdentity`, `CreateDBInstance`, `PutObject`, `UserAuthentication` | yes | OTel README L486: `eventName` → `rpc.method`; classic `aws.cloudtrail` pipeline L1105–1108 sets `event.action` from same source — OTel uses RPC namespace instead of ECS |
| `rpc.method` | no | yes (as action surrogate) | Same `eventName` values as above | yes | Dashboard "Top Services and Operations" ES\|QL groups by `rpc.method`; de-facto action field on OTel path |
| `event.action` | no | n/a | — | yes | Not in OTel CloudTrail mapping table; absent from dashboard field list |
| `rpc.system` ← `eventType` | no | n/a | `AwsApiCall`, `AwsServiceEvent` | no | OTel README L488; record-type taxonomy, not operation name; dashboard "Event Types" panel |
| `aws.event.category` ← `eventCategory` | no | n/a | `Management`, `Data` | no | OTel README L471; audit stream category, not per-call verb |
| `aws.event.read_only` / `aws.event.management` | no | n/a | boolean facets | no | OTel README L473–475; mutability/management flags, not action labels |
| `rpc.service` ← `eventSource` | no | n/a | `iam.amazonaws.com`, `s3.amazonaws.com` | no | OTel README L487; invoked **service** (Layer 1 target), not the operation |

**Step 2b — per-stream check:**

| Stream | `event.action` in fixtures? | Pipeline maps to `event.action`? | Primary action candidate | Confidence | Evidence |
| --- | --- | --- | --- | --- | --- |
| `aws.cloudtrail.otel` (event records) | no | no (OTel at collection) | CloudTrail `eventName` → `rpc.method` (should also → `event.action`) | high | OTel README CloudTrail table; no package fixtures; classic `aws.cloudtrail` proves `eventName` semantics; dashboard ES\|QL uses `rpc.method` |
| Digest records | no | no | — (no per-event action) | high | OTel README digest table — `aws.cloudtrail.digest.*` only; integrity metadata |

### Actor (semantic)

| Entity | Classification | Entity type (if general) | Confidence | Evidence | Per-stream notes |
| --- | --- | --- | --- | --- | --- |
| IAM user / root / Identity Center user | user | — | high | `user.name` ← `userIdentity.userName`; `user.id` ← `userIdentity.userId`; `aws.principal.arn`, `aws.principal.type` (`IAMUser`, `IdentityCenterUser`, `Root`); `aws.identity_store.arn` for Identity Center | **`aws.cloudtrail.otel`** — API caller principal |
| Assumed role / federated session | user | assumed_role | high | `aws.principal.arn` (e.g. `arn:aws:sts::…:assumed-role/…`); `aws.principal.type` (`AssumedRole`, `FederatedUser`); session issuer under `aws.user_identity.session_context.issuer.*` | **`aws.cloudtrail.otel`** — role name and session embedded in ARN |
| Session issuer (underlying role/user) | user | — | high | `aws.user_identity.session_context.issuer.arn`, `.user_name`, `.type`, `.account_id` when temporary credentials used | **`aws.cloudtrail.otel`** — who issued the session, distinct from assumed-role session name |
| Access key credential | general | aws_access_key | high | `aws.access_key.id` ← `userIdentity.accessKeyId`; dashboard "Access Key Activity" ES\|QL groups by this field | **`aws.cloudtrail.otel`** — credential facet, not a human principal |
| AWS service principal | service | — | high | `aws.principal.type == AWSService`; `aws.user_identity.invoked_by` (e.g. `lambda.amazonaws.com`, `ec2.amazonaws.com`) | **`aws.cloudtrail.otel`** — service-to-service API calls |
| API client (network origin) | host | — | high | `source.address` ← `sourceIPAddress`; overview datatable column alongside access key and RPC fields | **`aws.cloudtrail.otel`** — client IP/endpoint, not a security principal |
| Client software | general | user_agent | moderate | `user_agent.original` ← `userAgent`; dashboard "Client User Agents" ES\|QL normalizes and ranks agents | **`aws.cloudtrail.otel`** — application context (CLI, console, SDK) |
| Cross-account / delegated actor | user | — | medium | `aws.user_identity.session_context.issuer.arn`, `aws.principal.id` during role chaining; `aws.identity_store.arn` for Identity Center on-behalf-of flows | **`aws.cloudtrail.otel`** — schema-supported; not exercised in dashboard ES\|QL |

**Not actors:** `cloud.account.id` ← `recipientAccountId` is the account where the event was recorded (tenancy scope). `aws.user_identity.account_id` is the calling principal's home account (scope context). Digest records under `aws.cloudtrail.digest.*` describe log-file integrity, not an API caller.

### Actor (ECS candidates)

| ECS / vendor field | Role | Mapped today? | Mapping correct? | Confidence | Evidence |
| --- | --- | --- | --- | --- | --- |
| `user.id` | Principal user ID | yes (OTel) | yes | high | OTel README: `userIdentity.userId` → `user.id` |
| `user.name` | IAM / Identity Center username | yes (OTel) | yes | high | OTel README: `userIdentity.userName` → `user.name` |
| `aws.principal.arn` | Canonical principal ARN | yes (OTel) | yes | high | OTel README: `userIdentity.arn` → `aws.principal.arn`; primary actor identifier for IAM/STS |
| `aws.principal.type` | Principal class | yes (OTel) | yes | high | OTel README: `userIdentity.type` → `aws.principal.type` |
| `aws.principal.id` | Principal ID | yes (OTel) | yes | high | OTel README: `userIdentity.principalId` → `aws.principal.id` |
| `aws.access_key.id` | Access key used | yes (OTel) | yes | high | OTel README + dashboard ES\|QL "Access Key Activity" |
| `aws.user_identity.session_context.issuer.*` | Session issuer identity | yes (OTel) | yes | high | OTel README maps issuer type, ARN, account, userName, principalId |
| `aws.user_identity.invoked_by` | AWS service caller name | yes (OTel) | yes | high | OTel README: `userIdentity.invokedBy`; service-principal actor facet |
| `aws.identity_store.arn` | Identity Center store | yes (OTel) | yes | moderate | OTel README: `userIdentity.identityStoreArn` |
| `aws.user_identity.account_id` | Caller home account | yes (OTel) | yes | high | OTel README; scope context, not the interactive actor |
| `source.address` | Client IP / endpoint | yes (OTel) | yes | high | OTel README: `sourceIPAddress` → `source.address`; dashboard datatable |
| `user_agent.original` | Client application | yes (OTel) | yes | moderate | OTel README + dashboard "Client User Agents" ES\|QL |
| `client.user.*` / `user.entity.id` / `service.entity.id` / `host.entity.id` | Security Solution entity enrichment | no | n/a | — | Classic `aws.cloudtrail` pipeline only; absent on OTel path |
| `destination.user.*` / `destination.host.*` | De-facto target identity | no | n/a | — | Not used (`destination_identity_hits.csv` has no row) |

**Mapping note:** "Mapped today?" reflects OTel `awslogsencodingextension` output at collection time. No Elastic ingest pipeline exists in this package to verify or override mappings.

### Target (semantic)

| Layer | Description | Entity | Classification | Entity type (if general) | Confidence | Evidence | Per-stream notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 — Platform / cloud service | AWS API endpoint invoked | S3, EC2, IAM, Lambda, … | service | — | high | `rpc.service` ← `eventSource` (e.g. `s3.amazonaws.com`); dashboard "Top Services and Operations" ES\|QL | **`aws.cloudtrail.otel`** — invoked AWS service; no `cloud.service.name` set by OTel |
| 2 — Resource / object | Resource acted upon in the API call | S3 bucket, EC2 instance, IAM role, … | general | aws_resource | high | `aws.resources[]` (ARN, type, accountId per element); `aws.request.parameters` / `aws.response.elements` carry resource names and IDs per `rpc.method` | **`aws.cloudtrail.otel`** — primary audit target for mutating and data-access events |
| 3 — Content / artifact | Single API request instance | CloudTrail request / event ID | general | api_request | high | `aws.request_id` ← `requestID`; `aws.cloudtrail.event_id` ← `eventID` | **`aws.cloudtrail.otel`** — correlatable per-call identifier |
| 3 — Content / artifact | Request / response payload | Parameters and created resource details | general | request_payload / response_payload | moderate | `aws.request.parameters`, `aws.response.elements` (nested maps); resource identity varies by operation | **`aws.cloudtrail.otel`** — may embed target resource names not in `aws.resources` |
| 3 — Content / artifact | Event classification | Management vs data, read-only | general | api_event_class | moderate | `rpc.system` ← `eventType` (`AwsApiCall`, `AwsServiceEvent`); `aws.event.read_only`, `aws.event.management`; dashboard "Event Types" panel | **`aws.cloudtrail.otel`** — record class, not a standalone resource |
| 3 — Content / artifact | Digest log integrity record | S3 digest file metadata | general | cloudtrail_digest | low | `aws.cloudtrail.digest.*` (S3 bucket/object, time bounds, log file hashes) | Digest record type only — integrity verification, not an API actor/target pair |

**Not targets:** `aws.error.code` / `aws.error.message` are outcome metadata (dashboard derives success vs failure). `cloud.region` and `cloud.account.id` are regional and tenancy scope. `server.address` from TLS client host header is low-confidence DNS context only.

### Target (ECS candidates)

| ECS / vendor field | Layer | Classification | Mapped today? | Mapping correct? | ECS target bucket | Enhancement candidate? | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `rpc.service` | 1 | service | yes (OTel) | yes | `cloud.service.name` / `service.target.name` | yes | OTel README: `eventSource` → `rpc.service`; dashboard ES\|QL; not copied to `cloud.service.name` |
| `rpc.method` | — | — | yes (OTel) | yes (as action) | context-only | yes | OTel README: `eventName` → `rpc.method`; **event action**, not target — should also populate `event.action` (classic `aws.cloudtrail` L1105–1108) |
| `rpc.system` | 3 | general (api_event_class) | yes (OTel) | yes | context-only | no | OTel README: `eventType` → `rpc.system`; dashboard "Event Types" |
| `aws.resources[]` | 2 | general (aws_resource) | yes (OTel) | yes | `service.target.entity.id` / `entity.target.id` | yes | OTel README: CloudTrail `resources[]` array with ARN/type/accountId; canonical Layer 2 target |
| `aws.request.parameters` | 2–3 | general (request_payload) | yes (OTel) | partial | `service.target.entity.id` | yes | OTel README; nested map — resource identity operation-dependent |
| `aws.response.elements` | 2–3 | general (response_payload) | yes (OTel) | partial | `service.target.entity.id` | yes | OTel README; often carries created resource ARNs on mutating calls |
| `aws.request_id` | 3 | general (api_request) | yes (OTel) | yes | context-only | no | OTel README: `requestID` → `aws.request_id` |
| `aws.cloudtrail.event_id` | 3 | general (api_request) | yes (OTel) | yes | context-only | no | OTel README: `eventID` → `aws.cloudtrail.event_id` |
| `cloud.region` | — | general (aws_region) | yes (OTel) | yes | context-only | no | OTel README: `awsRegion` → `cloud.region` |
| `cloud.account.id` | — | general (aws_account) | yes (OTel) | yes | context-only | no | OTel README: `recipientAccountId` → `cloud.account.id`; event recipient account |
| `cloud.service.name` | 1 | service | no | n/a | `service.target.name` | yes | Not set by OTel CloudTrail mapping; Layer 1 gap vs classic integrations |
| `server.address` | — | general (dns_host) | partial | partial | context-only | no | OTel README: `tlsDetails.clientProvidedHostHeader`; TLS context only |
| `user.target.*` / `host.target.*` / `service.target.*` / `entity.target.*` | — | — | no | n/a | — | yes (downstream) | Not populated; classic `aws.cloudtrail` pipeline sets these via entity enrichment |
| `destination.user.*` / `destination.host.*` | — | — | no | n/a | — | no | Not used |

### Gaps and mapping notes

- **`event.action` gap (primary):** OTel maps CloudTrail `eventName` → `rpc.method` but does **not** set ECS `event.action`. Classic `aws.cloudtrail` sets `event.action: '{{{json.eventName}}}'` (`default.yml` L1105–1108). Enhancement: downstream ingest copy `rpc.method` → `event.action`, or extend OTel encoding to emit both fields.
- **No Elastic ingest pipeline or fixtures:** Actor/target/action ECS quality depends entirely on OTel `awslogsencodingextension` defaults. Cannot verify `Mapping correct?` beyond OTel README semantics, classic `aws.cloudtrail` parity, and dashboard field usage.
- **Dashboard field emphasis vs full schema:** Bundled ES\|QL uses `rpc.service`, `rpc.method`, `rpc.system`, `aws.access_key.id`, `aws.error.code`, `user_agent.original`, and `source.address` — not `event.action`, `user.name`, `aws.principal.arn`, or `aws.resources`. IAM and resource investigations require querying OTel-mapped fields directly or extending dashboards.
- **Layer 1 gap:** `rpc.service` holds the invoked AWS API endpoint (e.g. `iam.amazonaws.com`) but OTel does not set `cloud.service.name`. Enhancement: derive short service name from `rpc.service` or add downstream ingest normalization.
- **Layer 2 not in official target fields:** `aws.resources[]` semantically represents affected AWS resources but remains vendor/OTel namespace only. Classic `aws.cloudtrail` promotes resource ARNs to `service.target.entity.id` / `user.target.entity.id` via ingest pipeline entity enrichment — absent on OTel path.
- **No Security Solution entity enrichment:** Classic pipeline sets `user.entity.id`, `service.entity.id`, `user.target.entity.id`, `related.entity`, etc. (`packages/aws/data_stream/cloudtrail/elasticsearch/ingest_pipeline/default.yml`). OTel path has no equivalent; `target_enhancement_packages.csv` = **none** for all buckets.
- **No de-facto `destination.*` targets:** Unlike email/auth integrations, CloudTrail does not map affected users/hosts to `destination.user.*` or `destination.host.*`.
- **Optional `aws.user_identity` prefix:** OTel feature gate `extension.awslogsencoding.cloudtrail.enable.user.identity.prefix` moves `aws.principal.*` and `aws.access_key.id` under `aws.user_identity.*` — field paths differ but semantics unchanged.
- **Digest records:** Separate record type with `aws.cloudtrail.digest.*` metadata; no `userIdentity`, `eventName`, or per-event action. Treat as integrity telemetry, not API audit events.
- **Correlate with classic integration:** For `event.action`, entity visualization, and typed target buckets, use classic **`aws.cloudtrail`** post-ingest enrichment or add downstream ingest processors on `aws.cloudtrail.otel` indices.

### Per-stream notes

#### aws.cloudtrail.otel

Single dataset for CloudTrail management and data events ingested via ECF for AWS or standalone OTel collector (`awss3receiver` + `awslogsencodingextension` format `cloudtrail`). OTel maps `userIdentity` → `user.*` / `aws.principal.*` / `aws.access_key.id`, `eventName` → **`rpc.method`** (not `event.action`), and `resources[]` → `aws.resources`. **`event.action` is absent** — query `rpc.method` for operation names (e.g. `AttachUserPolicy`, `GetCallerIdentity`); dashboard "Top Services and Operations" already groups by `rpc.service` + `rpc.method`. Actor is best interpreted as **user** (IAM, assumed role, federated) or **service** (AWS service principal); supplementary **host** (client IP) and **general** facets (access key, user agent). Target is Layer 1 **invoked AWS API** (`rpc.service`), Layer 2 **affected resource** (`aws.resources`, request/response maps), and Layer 3 **request instance** (`aws.request_id`, `aws.cloudtrail.event_id`).

#### Digest records

CloudTrail log-file validation digests mapped to `aws.cloudtrail.digest.*` (S3 bucket/object, time bounds, log file hashes). No `eventName`, **`event.action`**, or `userIdentity` — integrity verification only; actor/target audit semantics do not apply.

## Example Event Graph (illustrative — no package fixtures)

**Package type: assets-with-sibling** — `packages/aws_cloudtrail_otel/` ships Kibana dashboards only (no `data_stream/`, no `sample_event.json`, no ingest pipelines). CloudTrail records are ingested **outside** this package via ECF for AWS or a standalone OpenTelemetry Collector (`awslogsencodingextension`, `format: cloudtrail`); bundled dashboards query customer indices filtered to **`aws.cloudtrail.otel`** (dashboard control literal — Tier B).

Patterns below are **field/schema illustrations** from dashboard ES|QL (Tier B) or **sibling stand-in** field layouts from `packages/aws/data_stream/cloudtrail/` (OTel README maps the same CloudTrail JSON at collection time). They are **not** single indexed documents. Do **not** treat dashboard JSON as fixtures.

**Common-sense check (read aloud):** IAM admin attaches policy to a **different** user; STS identity lookup targets the **STS API service**, not the caller's home account; S3 upload targets the **object resource**, not the uploader.

Digest records (`aws.cloudtrail.digest.*`) have no per-event actor/action/target chain — omitted.

### Pattern 1: Dashboard — API volume by service and operation

**Log type:** `aws.cloudtrail.otel` (index `logs*`, dashboard filter) · **Evidence:** `packages/aws_cloudtrail_otel/kibana/dashboard/aws_cloudtrail_otel-9bfbe31c-e775-4ee4-9e34-a449e603d109.json` (Tier B)

```
Principal (aws.access_key.id) → API call (rpc.method grouped with rpc.service) → invoked AWS API (rpc.service)
```

Example one-liner (field paths only):

```
principal (aws.access_key.id) → API operation (rpc.method) → invoked AWS API (rpc.service)
```

#### Actor (schema)

| Field | Source in indexed data (not a sample value) |
| --- | --- |
| type | user — from `aws.access_key.id` (Access Key Activity panel ES\|QL) |
| type | host — supplementary from `source.address` (overview datatable column alongside RPC fields) |

#### Event action (schema)

| Field | Source |
| --- | --- |
| action | derived label from `rpc.method` (CloudTrail `eventName` on OTel path) |
| source_field | `rpc.method` |
| source_value | — (no operation literals in dashboard JSON; aggregate only) |

**Not mapped to ECS `event.action` today** — OTel maps `eventName` → `rpc.method` only.

#### Target (schema)

| Field | Source in indexed data (not a sample value) |
| --- | --- |
| type | service — Layer 1 invoked API from `rpc.service` (Top Services and Operations ES\|QL: `STATS … BY rpc.service, rpc.method`) |

### Pattern 2: Dashboard — success vs failure outcome

**Log type:** `aws.cloudtrail.otel` · **Evidence:** same dashboard JSON (Tier B)

```
API caller context (implicit) → outcome (aws.error.code present or absent) → API error taxonomy (aws.error.code)
```

Example one-liner:

```
principal (not named in panel ES\|QL) → Fail/Success (CASE on aws.error.code) → error code (aws.error.code)
```

#### Actor (schema)

| Field | Source in indexed data (not a sample value) |
| --- | --- |
| — | Dashboard outcome panel does not group by `aws.principal.*` or `user.name` |

#### Event action (schema)

| Field | Source |
| --- | --- |
| action | `Fail` or `Success` |
| source_field | `aws.error.code` |
| source_value | `Fail` / `Success` (dashboard `EVAL` literals only — not CloudTrail `eventName`) |

#### Target (schema)

| Field | Source in indexed data (not a sample value) |
| --- | --- |
| type | general — outcome metadata; `aws.error.code` values ranked in Error Codes panel |

### Pattern 3: Sibling stand-in — IAM policy attachment (OTel field layout)

**Log type:** `aws.cloudtrail.otel` (expected after OTel encoding) · **Evidence:** `packages/aws/data_stream/cloudtrail/_dev/test/pipeline/test-attach-user-policy-json.log-expected.json` (**sibling stand-in** — classic Agent ingest shape; OTel maps `userIdentity` → `aws.principal.*` / `user.name`, `eventName` → `rpc.method`, `requestParameters.userName` → `aws.request.parameters.userName`)

```
Assumed role (aws.principal.arn, aws.principal.type) → AttachUserPolicy (rpc.method) → IAM user (aws.request.parameters.userName)
```

**Read-aloud:** assumed-role session attaches a policy to **another** IAM user — not a self-referential target.

#### Actor (schema)

| Field | Source in indexed data (not a sample value) |
| --- | --- |
| id | `aws.principal.arn` |
| name | `aws.user_identity.session_context.issuer.user_name` (session issuer role name when `aws.principal.type` = `AssumedRole`) |
| type | user |
| sub_type | assumed_role — from `aws.principal.type` |

#### Event action (schema)

| Field | Source |
| --- | --- |
| action | `AttachUserPolicy` |
| source_field | `rpc.method` |
| source_value | `AttachUserPolicy` (literal from sibling `event.original` / classic `event.action`; OTel uses `rpc.method`) |

#### Target (schema)

| Field | Source in indexed data (not a sample value) |
| --- | --- |
| id | `aws.request.parameters.userName` |
| type | user |
| sub_type | aws_iam_user |
| type | service — Layer 1 `rpc.service` = `iam.amazonaws.com` (invoked API, parallel to user target) |

### Pattern 4: Sibling stand-in — STS GetCallerIdentity (OTel field layout)

**Log type:** `aws.cloudtrail.otel` · **Evidence:** `packages/aws/data_stream/cloudtrail/_dev/test/pipeline/test-get-caller-identity-json.log-expected.json` (**sibling stand-in**)

```
IAM user (aws.principal.arn, user.name) → GetCallerIdentity (rpc.method) → STS API (rpc.service)
```

**Read-aloud:** user looks up caller identity against **STS** — not `cloud.account.id` / recipient account (tenancy scope only).

#### Actor (schema)

| Field | Source in indexed data (not a sample value) |
| --- | --- |
| id | `aws.principal.arn` |
| name | `user.name` |
| type | user |

#### Event action (schema)

| Field | Source |
| --- | --- |
| action | `GetCallerIdentity` |
| source_field | `rpc.method` |
| source_value | `GetCallerIdentity` (sibling stand-in literal) |

#### Target (schema)

| Field | Source in indexed data (not a sample value) |
| --- | --- |
| id | `rpc.service` (e.g. `sts.amazonaws.com` from CloudTrail `eventSource`) |
| type | service |
| sub_type | aws_api |

### Pattern 5: Sibling stand-in — S3 PutObject (OTel field layout)

**Log type:** `aws.cloudtrail.otel` · **Evidence:** `packages/aws/data_stream/cloudtrail/_dev/test/pipeline/test-put-object-json.log-expected.json` (**sibling stand-in**)

```
IAM user (aws.principal.arn, user.name) → PutObject (rpc.method) → S3 object (aws.resources[].arn)
```

**Read-aloud:** user uploads data to an **S3 object** — not to themselves or only the bucket account ID.

#### Actor (schema)

| Field | Source in indexed data (not a sample value) |
| --- | --- |
| id | `aws.principal.arn` |
| name | `user.name` |
| type | user |

#### Event action (schema)

| Field | Source |
| --- | --- |
| action | `PutObject` |
| source_field | `rpc.method` |
| source_value | `PutObject` (sibling stand-in literal) |

#### Target (schema)

| Field | Source in indexed data (not a sample value) |
| --- | --- |
| id | `aws.resources[].arn` |
| type | general |
| sub_type | aws_resource |
| type | service — Layer 1 `rpc.service` = `s3.amazonaws.com` |

## ES|QL Entity Extraction

**Package type: assets-with-sibling** — field paths inferred from bundled dashboard ES|QL (Tier B), OTel CloudTrail mapping semantics (OTel Collector Contrib README, v0.138.0 per package README), and **sibling evidence** from `packages/aws/data_stream/cloudtrail/` fixtures where README-compatible OTel field layout applies. This package defines **no** Elastic Agent data streams, ingest pipelines, or test fixtures in-repo.

**Router:** `data_stream.dataset == "aws.cloudtrail.otel"` — from `manifest.yml` `discovery.datasets` and CloudTrail Logs Overview dashboard filter control, **not** from Agent `policy_templates` / `data_stream/` entries. **`event.action` is absent** on the OTel path; use **`rpc.method`** for operation routing and as the `event.action` fallback. Digest records (`aws.cloudtrail.digest.*`) excluded.

**Array constraint:** `aws.resources` is a CloudTrail array of objects `[{arn, type, accountId}]`. ES|QL flattens this to a multi-value field `aws.resources.arn`. Array indexing (`aws.resources[0].arn`) is **invalid ES|QL syntax**. The sibling fixture `test-put-object-json.log-expected.json` confirms that a single S3 PutObject event produces **two** resource entries (`AWS::S3::Object` and `AWS::S3::Bucket`) with no guaranteed ordering — `MV_FIRST(aws.resources.arn)` is therefore ambiguous. `entity.target.id` from `aws.resources.arn` is **ingest-only** for S3 events.

### Dataset inventory

| data_stream.dataset | Stream role | Actor classification(s) | Target classification(s) | Extraction |
| --- | --- | --- | --- | --- |
| `aws.cloudtrail.otel` | API audit (management/data) | user, host, service | user, service, general | partial (Tier B + sibling evidence) |
| `aws.cloudtrail.digest.*` | log-file integrity | — | — | none |

### Field mapping plan

#### Actor mappings

| Output column | Source field(s) | Condition | Confidence | Notes |
| --- | --- | --- | --- | --- |
| `user.id` | `aws.principal.arn` | `data_stream.dataset == "aws.cloudtrail.otel" AND aws.principal.type IN ("IAMUser", "AssumedRole", "FederatedUser", "Root", "IdentityCenterUser")` | medium | **vendor fallback** when ECS `user.id` empty; ARN is canonical principal identifier; sibling evidence |
| `user.name` | `aws.user_identity.session_context.issuer.user_name` | `data_stream.dataset == "aws.cloudtrail.otel" AND aws.principal.type == "AssumedRole"` | low | **vendor fallback** — session issuer role name when `user.name` empty |
| `host.ip` | `source.address` | `data_stream.dataset == "aws.cloudtrail.otel"` | medium | **vendor fallback** — OTel `sourceIPAddress` → `source.address`; dashboard datatable (Tier B) |
| `service.name` | `aws.user_identity.invoked_by` | `data_stream.dataset == "aws.cloudtrail.otel" AND aws.principal.type == "AWSService"` | low | **vendor fallback** — service-principal caller name when `service.name` empty |

**Detection predicate:** standard `actor_exists` (ECS user/host/service/entity columns only). `aws.principal.arn` is intentionally **not** in `actor_exists` so ARN can populate `user.id` when ECS user columns are empty.

#### Target mappings

| Output column | Source field(s) | Condition | Confidence | Notes |
| --- | --- | --- | --- | --- |
| `service.target.name` | `rpc.service` | `data_stream.dataset == "aws.cloudtrail.otel" AND rpc.method == "GetCallerIdentity"` | medium | **fallback** — STS API as Layer 1 target; sibling evidence Pattern 4 |
| `service.target.name` | `rpc.service` | `data_stream.dataset == "aws.cloudtrail.otel" AND rpc.method IN ("PutObject", "GetObject")` | medium | **fallback** — S3 API as Layer 1 target |
| `user.target.id` | `aws.request.parameters.userName` | `data_stream.dataset == "aws.cloudtrail.otel" AND rpc.method == "AttachUserPolicy"` | medium | **fallback** — sibling evidence (`test-attach-user-policy-json.log-expected.json`) |
| `user.target.name` | `aws.request.parameters.userName` | `data_stream.dataset == "aws.cloudtrail.otel" AND rpc.method == "AttachUserPolicy"` | medium | **fallback** — sibling evidence |
| `entity.target.id` | `aws.resources.arn` (multi-value) | S3 PutObject/GetObject | — | **ingest-only** — sibling fixture shows two resources per S3 event (Object + Bucket); `MV_FIRST` ordering not guaranteed; cannot reliably identify correct ARN at query time |

#### Event action mappings

| Output column | Source field(s) | Condition | Confidence | Notes |
| --- | --- | --- | --- | --- |
| `event.action` | `rpc.method` | `data_stream.dataset == "aws.cloudtrail.otel" AND rpc.method IS NOT NULL` | high | **vendor fallback** — CloudTrail `eventName` surrogate; absent at collection on OTel path |

### Detection flags (mandatory)

```esql
| EVAL
  actor_exists = user.id IS NOT NULL OR user.name IS NOT NULL OR user.email IS NOT NULL
    OR host.id IS NOT NULL OR host.ip IS NOT NULL OR host.name IS NOT NULL
    OR service.id IS NOT NULL OR service.name IS NOT NULL
    OR entity.id IS NOT NULL OR entity.name IS NOT NULL,
  target_exists = user.target.id IS NOT NULL OR user.target.name IS NOT NULL OR user.target.email IS NOT NULL
    OR host.target.id IS NOT NULL OR host.target.ip IS NOT NULL OR host.target.name IS NOT NULL
    OR service.target.id IS NOT NULL OR service.target.name IS NOT NULL
    OR entity.target.id IS NOT NULL OR entity.target.name IS NOT NULL,
  action_exists = event.action IS NOT NULL
```

**Semantics:** When `actor_exists` is true, actor output columns keep their current values (classic `aws.cloudtrail` entity enrichment or downstream ingest). When false, apply OTel vendor fallbacks. Same for `target_exists` / `action_exists`. OTel indices typically have empty `*.target.*` and `event.action`, so fallbacks apply.

### Combined ES|QL — actor fields

Column-level preserve: `CASE(col IS NOT NULL, col, cond AND src IS NOT NULL, src, null)`.

```esql
| EVAL
  user.id = CASE(
    user.id IS NOT NULL, user.id,
    data_stream.dataset == "aws.cloudtrail.otel" AND aws.principal.type IN ("IAMUser", "AssumedRole", "FederatedUser", "Root", "IdentityCenterUser") AND aws.principal.arn IS NOT NULL, aws.principal.arn,
    null
  ),
  user.name = CASE(
    user.name IS NOT NULL, user.name,
    data_stream.dataset == "aws.cloudtrail.otel" AND aws.principal.type == "AssumedRole" AND aws.user_identity.session_context.issuer.user_name IS NOT NULL, aws.user_identity.session_context.issuer.user_name,
    null
  ),
  host.ip = CASE(
    host.ip IS NOT NULL, host.ip,
    data_stream.dataset == "aws.cloudtrail.otel" AND source.address IS NOT NULL, source.address,
    null
  ),
  service.name = CASE(
    service.name IS NOT NULL, service.name,
    data_stream.dataset == "aws.cloudtrail.otel" AND aws.principal.type == "AWSService" AND aws.user_identity.invoked_by IS NOT NULL, aws.user_identity.invoked_by,
    null
  )
```

### Combined ES|QL — event action

```esql
| EVAL
  event.action = CASE(
    event.action IS NOT NULL, event.action,
    data_stream.dataset == "aws.cloudtrail.otel" AND rpc.method IS NOT NULL, rpc.method,
    null
  )
```

### Combined ES|QL — target fields

Column-level preserve. For `entity.target.id` from `aws.resources.arn`: the sibling fixture `test-put-object-json.log-expected.json` shows **two** resources per S3 PutObject event (`AWS::S3::Object` and `AWS::S3::Bucket`) with no guaranteed ordering. `MV_FIRST(aws.resources.arn)` cannot reliably identify the S3 object ARN vs. the bucket ARN. `entity.target.id` is therefore **omitted** from the query-time EVAL and documented as ingest-only below.

```esql
| EVAL
  service.target.name = CASE(
    service.target.name IS NOT NULL, service.target.name,
    data_stream.dataset == "aws.cloudtrail.otel" AND rpc.method == "GetCallerIdentity" AND rpc.service IS NOT NULL, rpc.service,
    data_stream.dataset == "aws.cloudtrail.otel" AND rpc.method IN ("PutObject", "GetObject") AND rpc.service IS NOT NULL, rpc.service,
    null
  ),
  user.target.id = CASE(
    user.target.id IS NOT NULL, user.target.id,
    data_stream.dataset == "aws.cloudtrail.otel" AND rpc.method == "AttachUserPolicy" AND aws.request.parameters.userName IS NOT NULL, aws.request.parameters.userName,
    null
  ),
  user.target.name = CASE(
    user.target.name IS NOT NULL, user.target.name,
    data_stream.dataset == "aws.cloudtrail.otel" AND rpc.method == "AttachUserPolicy" AND aws.request.parameters.userName IS NOT NULL, aws.request.parameters.userName,
    null
  )
```

### Full pipeline fragment (optional)

Unscoped `FROM logs-*` — dataset routing in `CASE` fallback branches only (no `WHERE data_stream.dataset`):

```esql
FROM logs-*
| EVAL
  actor_exists = user.id IS NOT NULL OR user.name IS NOT NULL OR user.email IS NOT NULL
    OR host.id IS NOT NULL OR host.ip IS NOT NULL OR host.name IS NOT NULL
    OR service.id IS NOT NULL OR service.name IS NOT NULL
    OR entity.id IS NOT NULL OR entity.name IS NOT NULL,
  target_exists = user.target.id IS NOT NULL OR user.target.name IS NOT NULL OR user.target.email IS NOT NULL
    OR host.target.id IS NOT NULL OR host.target.ip IS NOT NULL OR host.target.name IS NOT NULL
    OR service.target.id IS NOT NULL OR service.target.name IS NOT NULL
    OR entity.target.id IS NOT NULL OR entity.target.name IS NOT NULL,
  action_exists = event.action IS NOT NULL
| EVAL
  user.id = CASE(
    user.id IS NOT NULL, user.id,
    data_stream.dataset == "aws.cloudtrail.otel" AND aws.principal.type IN ("IAMUser", "AssumedRole", "FederatedUser", "Root", "IdentityCenterUser") AND aws.principal.arn IS NOT NULL, aws.principal.arn,
    null
  ),
  user.name = CASE(
    user.name IS NOT NULL, user.name,
    data_stream.dataset == "aws.cloudtrail.otel" AND aws.principal.type == "AssumedRole" AND aws.user_identity.session_context.issuer.user_name IS NOT NULL, aws.user_identity.session_context.issuer.user_name,
    null
  ),
  host.ip = CASE(
    host.ip IS NOT NULL, host.ip,
    data_stream.dataset == "aws.cloudtrail.otel" AND source.address IS NOT NULL, source.address,
    null
  ),
  service.name = CASE(
    service.name IS NOT NULL, service.name,
    data_stream.dataset == "aws.cloudtrail.otel" AND aws.principal.type == "AWSService" AND aws.user_identity.invoked_by IS NOT NULL, aws.user_identity.invoked_by,
    null
  ),
  event.action = CASE(
    event.action IS NOT NULL, event.action,
    data_stream.dataset == "aws.cloudtrail.otel" AND rpc.method IS NOT NULL, rpc.method,
    null
  ),
  service.target.name = CASE(
    service.target.name IS NOT NULL, service.target.name,
    data_stream.dataset == "aws.cloudtrail.otel" AND rpc.method == "GetCallerIdentity" AND rpc.service IS NOT NULL, rpc.service,
    data_stream.dataset == "aws.cloudtrail.otel" AND rpc.method IN ("PutObject", "GetObject") AND rpc.service IS NOT NULL, rpc.service,
    null
  ),
  user.target.id = CASE(
    user.target.id IS NOT NULL, user.target.id,
    data_stream.dataset == "aws.cloudtrail.otel" AND rpc.method == "AttachUserPolicy" AND aws.request.parameters.userName IS NOT NULL, aws.request.parameters.userName,
    null
  ),
  user.target.name = CASE(
    user.target.name IS NOT NULL, user.target.name,
    data_stream.dataset == "aws.cloudtrail.otel" AND rpc.method == "AttachUserPolicy" AND aws.request.parameters.userName IS NOT NULL, aws.request.parameters.userName,
    null
  )
| KEEP @timestamp, data_stream.dataset, event.action, rpc.method, rpc.service, user.id, user.name, host.ip, service.name, service.target.name, user.target.id, user.target.name
```

### Streams excluded

- **Digest records** (`aws.cloudtrail.digest.*`) — integrity metadata only; no `userIdentity`, `rpc.method`, or actor/target extraction.

### Gaps and limitations

- **`entity.target.id` — ingest-only (array constraint):** `aws.resources` is a CloudTrail array of objects. ES|QL flattens it to multi-value `aws.resources.arn`. Array indexing (`aws.resources[0].arn`) is **not valid ES|QL syntax**. The sibling fixture `test-put-object-json.log-expected.json` shows **two** resources for a single PutObject event: `AWS::S3::Object` (`arn:aws:s3:::elastic-cspm-cloudtrail-test-bucket/test.json`) and `AWS::S3::Bucket` (`arn:aws:s3:::elastic-cspm-cloudtrail-test-bucket`). `MV_FIRST(aws.resources.arn)` ordering is not guaranteed — the S3 object ARN and bucket ARN cannot be reliably distinguished at query time. Populate `entity.target.id` via ingest pipeline (e.g., Painless script iterating `resources[]` by type) or use the classic `aws.cloudtrail` enrichment path which already sets `service.target.entity.id`.
- **Tier B ceiling** — dashboard ES|QL aggregates `rpc.service`, `rpc.method`, `rpc.system`, `aws.access_key.id`, `aws.error.code`, `user_agent.original`; it does not reference `aws.principal.arn`, `user.name`, or `aws.resources` — operation-specific `CASE` branches rely on **sibling evidence**, not package fixtures.
- **`event.action`** — absent at collection on OTel path; fallback copies `rpc.method` only when `action_exists` is false.
- **No Agent `data_stream/` definition** — router value `aws.cloudtrail.otel` from `discovery.datasets` + dashboard filter, not ingest-pipeline-verified.
- **Classic entity enrichment absent** — if downstream ingest populates `user.target.*` / `service.target.*`, `target_exists` preserves them; OTel-only indices rely on guarded fallbacks.
- **`user.domain` / `user.email` / `host.target.*`** — no defensible OTel sources; omitted.
- **`entity.id` for access keys** — `aws.access_key.id` is an actor facet; not mapped to `entity.id` to avoid conflating credential with principal.
