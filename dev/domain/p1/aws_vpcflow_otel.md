# aws_vpcflow_otel

## Product Domain (AWS VPC Flow Logs via OTel)

Amazon VPC Flow Logs capture metadata about IP traffic flowing through network interfaces in a VPC, subnet, or individual ENI. Each record summarizes a network flow—source and destination addresses and ports, protocol, packet and byte counts, flow start/end times, and whether traffic was accepted or rejected by security groups and network ACLs. Organizations enable flow logs for network visibility, capacity planning, anomaly detection, and security investigations (for example, identifying rejected connections or unexpected east-west traffic).

The Elastic **AWS VPC Flow Logs OpenTelemetry Assets** package is a content integration that ships Kibana dashboards for telemetry ingested via OpenTelemetry—not an Elastic Agent log shipper. Collection is typically configured with the EDOT Cloud Forwarder (ECF) for AWS or a standalone OpenTelemetry Collector using the `awss3receiver`, `awslogsencodingextension` (VPC flow plain-text format), and `elasticsearchexporter`. Flow log files land in S3 (often under `AWSLogs/<account-id>/`) and are polled via SQS notifications; the OTel pipeline parses records into ECS-aligned documents indexed under the `aws.vpcflow.otel` dataset.

This package complements the classic Elastic Agent **AWS** integration (`aws.vpcflow` data stream) by targeting the OTel ingestion path. It provides three linked dashboards—Overview, Traffic Analysis, and Interface Analysis—for monitoring flow volume, rejection rates, bandwidth, per-interface behavior, and rejected-traffic drill-down across cloud accounts.

## Data Collected (brief)

Logs only (no metrics). The package expects data already ingested with `data_stream.dataset: aws.vpcflow.otel` via OpenTelemetry; it does not define its own Elastic Agent data streams or ingest pipelines.

Each document represents one VPC flow log record. Key fields surfaced in dashboards and typical OTel mappings include:

| Field area | Examples |
|---|---|
| **Network (ECS)** | `source.address`, `destination.address`, `source.port`, `destination.port`, `network.protocol.name`, `network.interface.name` |
| **AWS VPC flow (OTel)** | `aws.vpc.flow.action` (ACCEPT/REJECT), `aws.vpc.flow.bytes`, `aws.vpc.flow.packets` |
| **Cloud context** | `cloud.account.id` |

Standard VPC flow log attributes (version, VPC/subnet/instance IDs, TCP flags, log status, packet-level addresses, ECS task metadata, etc.) may also be present depending on the flow log format version and OTel encoding configuration. Collection requires AWS S3 bucket storage for flow logs, SQS queue notifications, and an OTel pipeline (ECF for AWS or collector with `awslogs_encoding/vpcflow`).

## Expected Audit Log Entities

Evidence is from `packages/aws_vpcflow_otel/docs/README.md`, bundled dashboard ES\|QL (`packages/aws_vpcflow_otel/_dev/shared/kibana/*.yaml`), and the OpenTelemetry `awslogsencodingextension` VPC flow field mapping ([OTel Collector Contrib README](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/extension/encoding/awslogsencodingextension#vpc-flow-log-record-fields), tested at v0.138.0 per package README). This integration is **dashboards-only** — it expects data already ingested with `data_stream.dataset: aws.vpcflow.otel` via ECF for AWS or a standalone OTel collector; there are no Elastic Agent data streams, ingest pipelines, `fields.yml`, or package test fixtures.

Each document is one **VPC flow log record** — network flow telemetry, not identity-centric audit logs. Rejected flows (`aws.vpc.flow.action == "REJECT"`) are audit-adjacent for security-group/NACL investigations but still lack authenticated principals. Actor and target are inferred from the flow 5-tuple (`source.*` / `destination.*`), well-known ports, and disposition fields. There is no `user.*` identity. ECS `*.target.*` fields are **not populated** (no row in `target_fields_audit.csv`). `destination.user.*` / `destination.host.*` are **not used** (absent from `destination_identity_hits.csv`). `target_enhancement_packages.csv` classifies `aws_vpcflow_otel` as **none** with no pipeline actor or destination identity evidence in this package.

**`event.action` is absent on the OTel ingestion path.** OTel maps the VPC flow `action` field to **`aws.vpc.flow.action`** (`ACCEPT` / `REJECT`) only — it does not set `event.action`, `event.outcome`, or `event.type`. The classic Elastic Agent **`aws.vpcflow`** data stream copies `aws.vpcflow.action` → `event.action` and derives `event.outcome` / `event.type` (`allowed` / `denied`) in post-ingest pipeline (`packages/aws/data_stream/vpcflow/elasticsearch/ingest_pipeline/default.yml` L122–141); the OTel path does not. Bundled dashboards filter and aggregate on **`aws.vpc.flow.action`** directly (Overview, Traffic Analysis, Interface Analysis filter controls and breakdown panels).

| Stream | `event.action` in fixtures? | Pipeline maps to `event.action`? | Primary action candidate | Confidence | Evidence |
| --- | --- | --- | --- | --- | --- |
| **`aws.vpcflow.otel`** | no (no package fixtures) | no (OTel encoding only) | `aws.vpc.flow.action` (`ACCEPT`, `REJECT`) | high | OTel README: `action` → `aws.vpc.flow.action`; dashboard ES\|QL filters `aws.vpc.flow.action == "REJECT"` / `"ACCEPT"` (`traffic.yaml` L138–139, L222–223, L328; `overview.yaml` L60, L196–197; `interface.yaml` L159–160, L280–281) |

### Event action (semantic)

What operation or activity does each stream record?

| Action (normalized label) | Classification | Confidence | Evidence | Per-stream notes |
| --- | --- | --- | --- | --- |
| Flow accepted (security group / NACL allow) | data_access | high | `aws.vpc.flow.action: ACCEPT`; "Accept vs Reject Over Time" and accept/reject KPI panels (`overview.yaml` L196–197; `interface.yaml` L280–281) | **`aws.vpcflow.otel`** — permitted flow summary |
| Flow rejected (security group / NACL deny) | data_access | high | `aws.vpc.flow.action: REJECT`; "Top Rejected Ports", "Top Source IPs - Detailed", "Detailed Rejection Logs" (`traffic.yaml` L276–330) | **`aws.vpcflow.otel`** — audit-adjacent deny; primary security investigation filter |
| Rejection cause (supplementary) | configuration_change | medium | `aws.vpc.flow.reject_reason` when present (OTel README: `reject-reason` field, format v6+) | **`aws.vpcflow.otel`** — explains *why* a REJECT occurred; not a separate verb from REJECT |
| Network connection observed | connection | high | Implicit per-record semantics — one flow interval per document | **`aws.vpcflow.otel`** — no explicit "connect" verb; classic pipeline sets `event.type: [connection]` but OTel does not |

There is no per-event API operation, authentication verb, or admin action — VPC flow logs record **network disposition** (allow/deny) for an observed flow, not who initiated a configuration change.

### Event action (ECS candidates)

| ECS / vendor field | Mapped to `event.action` today? | Mapping correct? | Recommended `event.action` value (from fixtures) | Enhancement candidate? | Evidence |
| --- | --- | --- | --- | --- | --- |
| `event.action` | no | n/a | — | — | Absent from OTel VPC flow encoding; no package fixtures |
| `aws.vpc.flow.action` | no (vendor/OTel only) | yes (as disposition) | `ACCEPT`, `REJECT` | **yes** — copy to `event.action` (matches classic `aws.vpcflow` pipeline) | OTel README: `action` → `aws.vpc.flow.action`; dashboard primary action dimension (`traffic.yaml` L24 filter control; all three dashboards) |
| `aws.vpc.flow.reject_reason` | no | n/a | e.g. SG rule mismatch codes (format v6+) | partial — supplement `event.reason`, not primary `event.action` | OTel README: `reject-reason` → `aws.vpc.flow.reject_reason`; classic pipeline copies to `event.reason` (`default.yml` L142–145) |
| `event.outcome` | no | n/a | `success` (ACCEPT) / `failure` (REJECT) | **yes** — derive from `aws.vpc.flow.action` | Classic `aws.vpcflow` pipeline sets outcome from action (`default.yml` L122–129); OTel path omits |
| `event.type` (`allowed` / `denied`) | no | n/a | `allowed`, `denied` | partial — belongs in `event.type`, not `event.action`; classic pipeline appends these (`default.yml` L130–137) | Distinct from `event.action` per ECS Event field-set; OTel omits both |
| `event.category` / `event.type` (`connection`) | no | n/a | `[network]`, `[connection]` | partial — stream-level classification, not per-flow verb | Classic `aws.vpcflow` pipeline sets statically (`default.yml` L21–26); OTel omits |
| `network.io.direction` | no | n/a | `ingress` / `egress` (format v5+ `flow-direction`) | no — traffic direction context, not action verb | OTel README: `flow-direction` → `network.io.direction`; not in dashboard ES\|QL |

### Actor (semantic)

| Entity | Classification | Entity type (if general) | Confidence | Evidence | Per-stream notes |
| --- | --- | --- | --- | --- | --- |
| Flow source endpoint | host | — | high | `source.address`, `source.port`; Traffic Analysis "Unique Source IPs", "Top Source IPs", and "Top Source IPs - Detailed" group by `source.address` (`traffic.yaml`; `aws_vpcflow_otel-traffic.json`) | Default for all flow records on `aws.vpcflow.otel` |
| Flow initiator heuristic | host | — | medium | Ephemeral `source.port` toward well-known `destination.port` (e.g. client `:49152 → :443`); VPC flow logs expose tuple order only — no explicit client/server flag | Inferred from port pairing; not a separate field |
| Rejected-flow initiator | host | — | high | `source.address`, `source.port` when `aws.vpc.flow.action == "REJECT"`; "Top Source IPs - Detailed" and "Detailed Rejection Logs" panels filter on REJECT (`traffic.yaml`) | Security investigation context |
| Packet-level / NAT source | host | — | medium | OTel maps `pkt-srcaddr` → `source.address` when populated; may differ from `srcaddr` (`awslogsencodingextension` VPC flow mapping) | Format versions with packet-level fields |
| ECS task–originated workload | host or service | — | medium | `aws.ecs.task.id`, `aws.ecs.task.arn`, `aws.ecs.container.id`, `aws.ecs.service.name` when present in OTel output (format v3+); not referenced in bundled dashboards | Optional enrichment on flow records |
| AWS managed service source | service | — | medium | `aws.vpc.flow.source.service` ← `pkt-src-aws-service` (format v5+); not surfaced in dashboard ES\|QL | Rare; AWS-internal service attribution |
| Network interface (ENI) | — | — | high | **Not the actor** — observation point only: `network.interface.name` ← `interface-id`; Interface Analysis filters and aggregates by interface (`interface.yaml`) | Scope anchor, not flow peer |
| Cloud account | — | — | high | **Not the actor** — tenancy scope: `cloud.account.id`; Overview/Interface "Traffic by Cloud Account" and account KPIs (`overview.yaml`, `interface.yaml`) | Multi-account visibility only |

No **user** actor is populated; VPC flow logs carry IP/port tuples only — no `user.name` / `user.id` in dashboard field lists or OTel VPC flow schema.

### Actor (ECS candidates)

| ECS / vendor field | Role | Mapped today? | Mapping correct? | Confidence | Evidence |
| --- | --- | --- | --- | --- | --- |
| `source.address` | Flow origin host | yes (OTel) | yes | high | `srcaddr` / `pkt-srcaddr` → `source.address` (`awslogsencodingextension` VPC flow table); dashboard ES\|QL on `source.address` (`traffic.yaml`, `interface.yaml`) |
| `source.port` | Flow origin port | yes (OTel) | yes | high | `srcport` → `source.port`; dashboard filter control (`traffic.yaml` L40) |
| `aws.vpc.flow.source.service` | AWS service attribution | yes (OTel) | yes | medium | `pkt-src-aws-service` → `aws.vpc.flow.source.service` (format v5+); not in dashboard field lists |
| `aws.ecs.task.id`, `aws.ecs.task.arn`, `aws.ecs.container.id`, `aws.ecs.service.name` | Container/workload origin | yes (OTel) | partial | medium | ECS metadata fields on format v3+ flows; vendor-only, not mapped to `host.*` / `service.*` ECS in OTel encoding |
| `host.id` | EC2 instance hosting ENI | yes (OTel) | yes | medium | `instance-id` → `host.id` per OTel mapping; not used in bundled dashboards |
| `network.interface.name` | ENI observation point | yes (OTel) | n/a | high | `interface-id` → `network.interface.name`; identifies where flow was captured, not who initiated it |
| `cloud.account.id` | AWS account scope | yes (OTel) | n/a | high | `account-id` → `cloud.account.id`; tenancy context, not actor |
| `cloud.region` | AWS region scope | yes (OTel) | n/a | medium | `region` → `cloud.region`; not referenced in dashboards |

### Target (semantic)

| Layer | Description | Entity | Classification | Entity type (if general) | Confidence | Evidence | Per-stream notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 — Network protocol / service | Application protocol or well-known service on destination port | TCP/443, UDP/53, … | service | — | high | `destination.port` + `network.protocol.name`; "Top Destination Ports", "Top Rejected Ports", protocol breakdown panels across all three dashboards (`overview.yaml`, `traffic.yaml`, `interface.yaml`) | Primary service-layer target |
| 2 — Host / endpoint | IP peer receiving or serving traffic | Internal server, external host, blocked endpoint | host | — | high | `destination.address`, `destination.port`; "Top Destination IPs", "Unique Destination IPs", rejection drill-down (`traffic.yaml` L328–330; `interface.yaml`) | Default flow peer |
| 2 — AWS managed service destination | AWS-internal service receiving traffic | S3, DynamoDB, … | service | — | medium | `aws.vpc.flow.destination.service` ← `pkt-dst-aws-service` (format v5+); not in dashboard ES\|QL | Optional format v5+ enrichment |
| 2 — ECS task–targeted workload | Container/service receiving traffic | ECS task/service | host or service | — | medium | ECS metadata on destination-side flows when present in OTel output; not used in dashboards | Format v3+ only |
| 3 — Flow instance / disposition | Bytes, packets, accept/reject disposition for this flow record | Single flow summary | general | network_flow | high | `aws.vpc.flow.bytes`, `aws.vpc.flow.packets`, `aws.vpc.flow.action`; rejection table shows tuple + volume (`traffic.yaml` L328–330) | All records; disposition is event action, not entity target |

**Observation context (not flow peer):** `network.interface.name` identifies the ENI where the flow was logged — infrastructure anchor (`general`, network-interface), not the remote destination.

### Target (ECS candidates)

| ECS / vendor field | Layer | Classification | Mapped today? | Mapping correct? | ECS target bucket | Enhancement candidate? | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `destination.address` | 2 | host | yes (OTel) | yes | context-only (network peer) | partial → `host.target.ip` | `dstaddr` / `pkt-dstaddr` → `destination.address`; "Top Destination IPs" ES\|QL (`traffic.yaml` L394–395) — network semantics, not official ECS audit target |
| `destination.port` | 1/2 | service/host | yes (OTel) | yes | context-only | partial → `host.target.port` / `service.target.name` | `dstport` → `destination.port`; well-known ports imply service layer |
| `network.protocol.name` | 1 | service | yes (OTel) | yes | context-only | partial → `service.target.name` | `protocol` → `network.protocol.name`; protocol breakdown panels |
| `aws.vpc.flow.destination.service` | 2 | service | yes (OTel) | yes | — | yes → `service.target.name` | `pkt-dst-aws-service`; vendor-only, no ECS target mapping |
| `aws.vpc.flow.bytes`, `aws.vpc.flow.packets` | 3 | general | yes (OTel) | n/a | context-only | no | Flow volume metrics on rejection drill-down (`traffic.yaml` L329–330) |
| `aws.vpc.flow.reject_reason` | 3 | general | yes (OTel) | n/a | context-only | no | Deny explanation when security group/NACL blocks flow; action semantics documented under Event action |
| `network.interface.name` | — | general | yes (OTel) | n/a | context-only | no | ENI observation point; Interface Analysis aggregates (`interface.yaml`) — not remote peer |
| `aws.vpc.id`, `aws.vpc.subnet.id`, `host.id` | 2 | host | yes (OTel) | partial | context-only | partial → `host.target.id` | VPC/subnet/instance IDs from OTel encoding; infrastructure context, not in dashboards |

### Gaps and mapping notes

- **`event.action` gap on OTel path** — `aws.vpc.flow.action` (`ACCEPT` / `REJECT`) is the canonical per-flow verb but remains vendor-namespaced; OTel encoding does not copy to `event.action`. Classic **`aws.vpcflow`** pipeline does (`default.yml` L138–141). Recommended enhancement: downstream ingest processor or OTel exporter normalization to set `event.action` ← `aws.vpc.flow.action`, plus `event.outcome` and `event.type` parity with classic integration.
- **No ECS `*.target.*` fields** — flow peers live under `destination.*` as network endpoints; `target_enhancement_packages.csv` classifies this package as **none** (no Tier-A target mapping, no pipeline evidence in-package).
- **`destination.*` is network context, not de-facto user/host audit target** — unlike firewall auth or email logs, VPC flow records never populate `destination.user.*` or `destination.host.*`; all destination fields are 5-tuple peers.
- **Dashboard-only evidence** — no `sample_event.json` or `*-expected.json`; classifications rely on dashboard ES\|QL field usage (`_dev/shared/kibana/*.yaml`) plus OTel `awslogsencodingextension` VPC flow attribute mapping documented upstream.
- **Rich vendor fields not surfaced in dashboards** — `aws.ecs.*`, `aws.vpc.flow.source.service`, `aws.vpc.flow.destination.service`, `host.id`, `aws.vpc.id`, `network.io.direction`, and `aws.vpc.flow.reject_reason` may exist in ingested documents but are absent from bundled panel KEEP/filter clauses.
- **`network.interface.name` vs flow peers** — ENI identifies where traffic was observed (scope/filter dimension), not actor or remote target; do not conflate with `source.address` / `destination.address`.
- **No user identity** — VPC flow logs have no authenticated principal; ephemeral ports and IP addresses are the only actor signals.
- **Correlate with classic integration** — For `event.action` / `event.outcome` / ECS target enrichment parity, use classic **`aws.vpcflow`** post-ingest pipeline or add downstream processors on `aws.vpcflow.otel` indices.

### Per-stream notes

#### aws.vpcflow.otel

Single dataset for VPC (and Transit Gateway) flow logs ingested via ECF for AWS or standalone OTel collector (`awss3receiver` + `awslogsencodingextension` format `vpcflow`). OTel maps flow 5-tuple to `source.*` / `destination.*`, disposition to **`aws.vpc.flow.action`**, and cloud context to `cloud.account.id`, `cloud.region`, `network.interface.name`, etc. Per-event **action** is flow allow/deny (`ACCEPT` / `REJECT`) — not an API or admin verb. Actor is **host** (source IP/port) or occasionally **service** (AWS-internal `aws.vpc.flow.source.service` / `aws.vpc.flow.destination.service`). Target is Layer 1 **protocol/service** (`destination.port`, `network.protocol.name`), Layer 2 **flow peer** (`destination.address`), and Layer 3 **flow instance** (bytes/packets/disposition). All three dashboards query the same dataset; Traffic Analysis provides the richest actor/target/action drill-down (source/destination IPs, ports, rejection table).

## Example Event Graph (illustrative — no package fixtures)

**Package type: assets-with-sibling (dashboards-only)** — `packages/aws_vpcflow_otel/` ships Kibana dashboards and discovery metadata only; no Elastic Agent `data_stream/`, ingest pipelines, or `sample_event.json`. VPC flow records are ingested **outside** this package via ECF for AWS or a standalone OpenTelemetry Collector (`awslogsencodingextension`, format `vpcflow`); bundled dashboards query customer indices where `data_stream.dataset == "aws.vpcflow.otel"` (manifest discovery `aws.vpcflow.otel`; all dashboard filters and ES|QL use `data_stream.dataset`, not `event.dataset`).

Patterns below are **field/schema illustrations** from bundled dashboard ES|QL (Tier B) — **not** single indexed documents collected by this package. On the OTel path, disposition is **`aws.vpc.flow.action`** (`ACCEPT` / `REJECT`); **`event.action` is not set** (classic `aws.vpcflow` Agent pipeline copies `aws.vpcflow.action` → `event.action` — different encoding). Sibling **`packages/aws/data_stream/vpcflow/`** fixtures may be cited **only** for plain-text VPC flow field-layout comparison; they are **not** OTel-ingested events for this package.

**Common-sense read-aloud (schema):** “Flow source endpoint did allow/deny disposition to destination peer or service.” `network.interface.name` is observation scope (ENI), not actor or remote target.

### Pattern 1: Permitted flow trend (ACCEPT / REJECT over time)

**Log type:** `data_stream.dataset == "aws.vpcflow.otel"` · **Evidence:** `packages/aws_vpcflow_otel/_dev/shared/kibana/overview.yaml` (Tier B — "Accept vs Reject Over Time", L196–197)

```
host (source.address, source.port) → aws.vpc.flow.action (ACCEPT | REJECT) → service/host (destination.address, destination.port, network.protocol.name)
```

**Read-aloud:** “Source host permitted or denied traffic to a destination peer or well-known port/protocol.”

#### Actor (schema)

| Field | Source in indexed data (not a sample value) |
| --- | --- |
| type | host — `source.address`, `source.port` in dashboard controls and Top Source panels (`traffic.yaml` L37–40, L418+) |

#### Event action (schema)

| Field | Source |
| --- | --- |
| action | flow accepted / flow rejected (normalized labels) |
| source_field | `aws.vpc.flow.action` |
| source_value | `ACCEPT`, `REJECT` (filter literals in dashboard ES\|QL — not `event.action`) |

#### Target (schema)

| Field | Source in indexed data (not a sample value) |
| --- | --- |
| type | service or host — `destination.port`, `network.protocol.name`, `destination.address` (Overview protocol breakdown L120+; classic OTel maps `protocol` → `network.protocol.name`) |

**Scope context (not target):** `cloud.account.id`, `network.interface.name` — dashboard filters only.

### Pattern 2: Rejected-flow security drill-down

**Log type:** `data_stream.dataset == "aws.vpcflow.otel" AND aws.vpc.flow.action == "REJECT"` · **Evidence:** `packages/aws_vpcflow_otel/_dev/shared/kibana/traffic.yaml` (Tier B — Security Deep Dive, L276–330)

```
host (source.address) → REJECT (aws.vpc.flow.action filter literal) → host/service (destination.address, destination.port, network.protocol.name)
```

**Read-aloud:** “Source host had traffic rejected toward a destination IP/port or protocol bucket.” Audit-adjacent (SG/NACL deny) but still no authenticated user principal.

#### Actor (schema)

| Field | Source in indexed data (not a sample value) |
| --- | --- |
| type | host — `source.address`; "Top Source IPs - Detailed" and rejection table group/filter on source (`traffic.yaml` L328–330 KEEP list) |

#### Event action (schema)

| Field | Source |
| --- | --- |
| action | flow rejected |
| source_field | `aws.vpc.flow.action` |
| source_value | `REJECT` |

#### Target (schema)

| Field | Source in indexed data (not a sample value) |
| --- | --- |
| type | host — `destination.address`; service layer — `destination.port`, `network.protocol.name` ("Top Rejected Ports", "Rejected Traffic by Protocol") |

**Not in dashboard KEEP:** `aws.vpc.flow.reject_reason`, `aws.vpc.flow.destination.service` — may exist on ingested OTel documents (format v5+) but absent from panel field lists.

### Pattern 3: Per-interface disposition

**Log type:** `data_stream.dataset == "aws.vpcflow.otel"` · **Evidence:** `packages/aws_vpcflow_otel/_dev/shared/kibana/interface.yaml` (Tier B — Interface Traffic Analysis, L159–160; Traffic by Cloud Account L279–281)

```
host (source.address) → aws.vpc.flow.action → host (destination.address) · scope: network.interface.name (ENI)
```

**Read-aloud:** “Source host allowed or denied traffic to a destination peer, observed on a specific ENI.” ENI is **scope**, not the flow peer target.

#### Actor (schema)

| Field | Source in indexed data (not a sample value) |
| --- | --- |
| type | host — `source.address` (per-interface source/destination IP stats L87–102) |

#### Event action (schema)

| Field | Source |
| --- | --- |
| action | flow accepted / flow rejected |
| source_field | `aws.vpc.flow.action` |
| source_value | `ACCEPT`, `REJECT` (`EVAL is_accepted` / `is_rejected` panels L280–281) |

#### Target (schema)

| Field | Source in indexed data (not a sample value) |
| --- | --- |
| type | host — `destination.address` |

**Scope context (not actor/target):** `network.interface.name`, `cloud.account.id`.

### Optional read-aloud check — sibling field layout only

One **common-sense graph test** using disclosed tuple values from classic Agent ingest (same plain-text VPC flow line; OTel would index `aws.vpc.flow.action` instead of `event.action` / `aws.vpcflow.action`). **Not collected by `aws_vpcflow_otel`.**

**Evidence:** `packages/aws/data_stream/vpcflow/_dev/test/pipeline/test-extra-samples.log-expected.json` (last event; sibling Tier A, stand-in for OTel path)

**Read-aloud:** “Host 172.31.16.139 had traffic rejected to host 89.160.20.156 over ICMP.” — coherent; source ≠ destination.

| Node | Disclosed value | OTel-oriented field |
| --- | --- | --- |
| Actor ip | `172.31.16.139` | `source.address` |
| Action | `REJECT` | `aws.vpc.flow.action` (not `event.action`) |
| Target ip | `89.160.20.156` | `destination.address` |
| Target protocol | `icmp` | `network.protocol.name` |

## ES|QL Entity Extraction

**Package type: assets-with-sibling (dashboards-only).** Field paths inferred from bundled dashboard ES|QL (Tier B) and OTel `awslogsencodingextension` VPC flow mapping (package README / upstream docs). This package defines **no** ingest pipelines or test fixtures in-repo. Router: **`data_stream.dataset == "aws.vpcflow.otel"`** per `manifest.yml` discovery and all dashboard filters (`_dev/shared/kibana/*.yaml`, Kibana saved objects). Sibling **`packages/aws/data_stream/vpcflow/`** expected JSON may cite field **layout** only (e.g. `aws.vpcflow.pkt_dst_service` → OTel `aws.vpc.flow.destination.service`) — **sibling evidence**, not OTel-ingested documents.

VPC flow logs are **network telemetry**: actor is the flow source endpoint (`source.address` / `source.port`); target is the destination peer (`destination.address`) or protocol/service layer (`network.protocol.name`, optional `aws.vpc.flow.destination.service`). No `user.*` identity. Pass 4 is **fill-gaps-only** — preserve existing `host.*`, `host.target.*`, `service.target.*`, and `event.action` when already populated. **Pass 4 (tautology + CASE syntax):** no `CASE(col, col, …)` identity fallbacks; actor/target/action columns use **column-level** `IS NOT NULL` preserve (not `CASE(actor_exists|target_exists|action_exists, <col>, …)`) so partial enrichment (e.g. `host.id` from `instance-id` or `host.target.ip` without `host.target.name`) does not block `source.address` / `destination.address` fallbacks. `source.address` / `destination.address` are excluded from `actor_exists` / `target_exists` so 5-tuple peers remain valid fallbacks. All `CASE` use odd-arity defaults or valid **3-arg** forms — never **4-arg** `CASE(flag, col, bare_field, null)`.

### Dataset inventory

| Router (`data_stream.dataset`) | Stream role | Actor classification(s) | Target classification(s) | Extraction |
| --- | --- | --- | --- | --- |
| `aws.vpcflow.otel` | network flow (ACCEPT/REJECT via `aws.vpc.flow.action`) | host | host, service | partial — Tier B |

### Field mapping plan

#### Actor mappings

| Output column | Source field(s) | Condition (dataset + optional) | Confidence | Notes |
| --- | --- | --- | --- | --- |
| `host.ip` | `host.ip` | `host.ip IS NOT NULL` | medium | **preserve existing** — column-level |
| `host.ip` | `source.address` | `data_stream.dataset == "aws.vpcflow.otel" AND source.address IS NOT NULL` | medium | **vendor fallback** — Tier B; `source.address` not in `actor_exists` |
| `host.name` | `host.name` | `host.name IS NOT NULL` | low | **preserve existing** — column-level |
| `host.name` | `source.address` | `data_stream.dataset == "aws.vpcflow.otel" AND source.address IS NOT NULL` | low | **vendor fallback** — IP-as-label; independent of `host.ip` / `host.id` |

#### Target mappings

| Output column | Source field(s) | Condition (dataset + optional) | Confidence | Notes |
| --- | --- | --- | --- | --- |
| `host.target.ip` | `host.target.ip` | `host.target.ip IS NOT NULL` | medium | **preserve existing** — column-level |
| `host.target.ip` | `destination.address` | `data_stream.dataset == "aws.vpcflow.otel" AND destination.address IS NOT NULL` | medium | **vendor fallback** — Tier B (`traffic.yaml` L328–395); `destination.address` not in `target_exists` |
| `host.target.name` | `host.target.name` | `host.target.name IS NOT NULL` | low | **preserve existing** — column-level |
| `host.target.name` | `destination.address` | `data_stream.dataset == "aws.vpcflow.otel" AND destination.address IS NOT NULL` | low | **vendor fallback** — network peer IP label; independent of `host.target.ip` |
| `service.target.name` | `service.target.name` | `service.target.name IS NOT NULL` | medium | **preserve existing** — column-level |
| `service.target.name` | `aws.vpc.flow.destination.service` | `data_stream.dataset == "aws.vpcflow.otel" AND aws.vpc.flow.destination.service IS NOT NULL` | medium | **vendor fallback** — **sibling evidence** only |
| `service.target.name` | `network.protocol.name` | `data_stream.dataset == "aws.vpcflow.otel" AND network.protocol.name IS NOT NULL` | low | **vendor fallback** — protocol Tier B |
| `entity.target.type` | `entity.target.type` | `entity.target.type IS NOT NULL` | low | **preserve existing** — column-level |
| `entity.target.type` | literal `"service"` / `"host"` | per guards below | low | **fallback** classification helper only |

#### Event action mappings

| Output column | Source field(s) | Condition (dataset + optional) | Confidence | Notes |
| --- | --- | --- | --- | --- |
| `event.action` | `event.action` | `event.action IS NOT NULL` | medium | **preserve existing** — column-level (not `action_exists` in `CASE`) |
| `event.action` | `aws.vpc.flow.action` | `data_stream.dataset == "aws.vpcflow.otel" AND aws.vpc.flow.action IS NOT NULL` | medium | **vendor fallback** — OTel path omits `event.action` (Pass 2) |

Omit `user.*`, `entity.*` actor columns, and well-known-port **semantic literals** (no indexed service name in Tier B dashboards).

### Detection flags (mandatory — run first)

Network-only integration: `actor_exists` / `target_exists` omit `user.*` / `user.target.*` (no identity fields on this dataset). **`source.address` / `destination.address` are intentionally excluded** from the flags so flow 5-tuple peers can populate `host.ip` / `host.target.*` when ECS columns are empty. Mapped actor/target/action columns use **column-level** `IS NOT NULL` preserve in subsequent `EVAL` blocks (not flag-wide `CASE(actor_exists|target_exists|action_exists, col, …)`).

```esql
| EVAL
  actor_exists = host.id IS NOT NULL OR host.ip IS NOT NULL OR host.name IS NOT NULL
    OR service.id IS NOT NULL OR service.name IS NOT NULL
    OR entity.id IS NOT NULL OR entity.name IS NOT NULL,
  target_exists = host.target.id IS NOT NULL OR host.target.ip IS NOT NULL OR host.target.name IS NOT NULL
    OR service.target.id IS NOT NULL OR service.target.name IS NOT NULL
    OR entity.target.id IS NOT NULL OR entity.target.name IS NOT NULL,
  action_exists = event.action IS NOT NULL
```

**Semantics:** `actor_exists` / `target_exists` document whether any ECS identity column is already set (e.g. downstream enrichment). Per-column `CASE(host.ip IS NOT NULL, host.ip, …)` applies fallbacks when that output column is empty even if `host.id` or another actor column is populated.

### Optional classification helpers (when needed)

Set `entity.target.type` in the **fallback** branch only (correct ECS name — not `target.entity.type`):

```esql
| EVAL
  entity.target.type = CASE(
    entity.target.type IS NOT NULL, entity.target.type,
    data_stream.dataset == "aws.vpcflow.otel" AND aws.vpc.flow.destination.service IS NOT NULL, "service",
    data_stream.dataset == "aws.vpcflow.otel", "host",
    null
  )
```

Do not use `destination.port IN (22, 443, 80)` without package fixture proof — heuristic omitted.

### Combined ES|QL — actor fields

```esql
| EVAL
  host.ip = CASE(
    host.ip IS NOT NULL, host.ip,
    data_stream.dataset == "aws.vpcflow.otel" AND source.address IS NOT NULL, source.address,
    null
  ),
  host.name = CASE(
    host.name IS NOT NULL, host.name,
    data_stream.dataset == "aws.vpcflow.otel" AND source.address IS NOT NULL, source.address,
    null
  )
```

### Combined ES|QL — event action

```esql
| EVAL
  event.action = CASE(
    event.action IS NOT NULL, event.action,
    data_stream.dataset == "aws.vpcflow.otel" AND aws.vpc.flow.action IS NOT NULL, aws.vpc.flow.action,
    null
  )
```

Filters and dashboards may still prefer **`aws.vpc.flow.action`** for ACCEPT/REJECT panels; this block only normalizes `event.action` when empty.

### Combined ES|QL — target fields

```esql
| EVAL
  host.target.ip = CASE(
    host.target.ip IS NOT NULL, host.target.ip,
    data_stream.dataset == "aws.vpcflow.otel" AND destination.address IS NOT NULL, destination.address,
    null
  ),
  host.target.name = CASE(
    host.target.name IS NOT NULL, host.target.name,
    data_stream.dataset == "aws.vpcflow.otel" AND destination.address IS NOT NULL, destination.address,
    null
  ),
  service.target.name = CASE(
    service.target.name IS NOT NULL, service.target.name,
    data_stream.dataset == "aws.vpcflow.otel" AND aws.vpc.flow.destination.service IS NOT NULL, aws.vpc.flow.destination.service,
    data_stream.dataset == "aws.vpcflow.otel" AND network.protocol.name IS NOT NULL, network.protocol.name,
    null
  )
```

### Full pipeline fragment (optional)

Unscoped `FROM logs-*` — dataset routing in `CASE` fallback branches only (no `WHERE data_stream.dataset`):

```esql
FROM logs-*
| EVAL
  actor_exists = host.id IS NOT NULL OR host.ip IS NOT NULL OR host.name IS NOT NULL
    OR service.id IS NOT NULL OR service.name IS NOT NULL
    OR entity.id IS NOT NULL OR entity.name IS NOT NULL,
  target_exists = host.target.id IS NOT NULL OR host.target.ip IS NOT NULL OR host.target.name IS NOT NULL
    OR service.target.id IS NOT NULL OR service.target.name IS NOT NULL
    OR entity.target.id IS NOT NULL OR entity.target.name IS NOT NULL,
  action_exists = event.action IS NOT NULL
| EVAL
  host.ip = CASE(
    host.ip IS NOT NULL, host.ip,
    data_stream.dataset == "aws.vpcflow.otel" AND source.address IS NOT NULL, source.address,
    null
  ),
  host.name = CASE(
    host.name IS NOT NULL, host.name,
    data_stream.dataset == "aws.vpcflow.otel" AND source.address IS NOT NULL, source.address,
    null
  ),
  event.action = CASE(
    event.action IS NOT NULL, event.action,
    data_stream.dataset == "aws.vpcflow.otel" AND aws.vpc.flow.action IS NOT NULL, aws.vpc.flow.action,
    null
  ),
  host.target.ip = CASE(
    host.target.ip IS NOT NULL, host.target.ip,
    data_stream.dataset == "aws.vpcflow.otel" AND destination.address IS NOT NULL, destination.address,
    null
  ),
  host.target.name = CASE(
    host.target.name IS NOT NULL, host.target.name,
    data_stream.dataset == "aws.vpcflow.otel" AND destination.address IS NOT NULL, destination.address,
    null
  ),
  service.target.name = CASE(
    service.target.name IS NOT NULL, service.target.name,
    data_stream.dataset == "aws.vpcflow.otel" AND aws.vpc.flow.destination.service IS NOT NULL, aws.vpc.flow.destination.service,
    data_stream.dataset == "aws.vpcflow.otel" AND network.protocol.name IS NOT NULL, network.protocol.name,
    null
  )
| KEEP @timestamp, data_stream.dataset, aws.vpc.flow.action, event.action, source.address, destination.address, destination.port, network.protocol.name, host.ip, host.name, host.target.ip, host.target.name, service.target.name
```

### Streams excluded

- None — single OTel flow dataset (`aws.vpcflow.otel`) only; classic Agent **`aws.vpcflow`** is a different `data_stream.dataset` (out of scope for this package router).

### Gaps and limitations

- **No package fixtures** — mappings are Tier B (dashboard ES|QL) plus OTel encoding docs; confidence capped at medium/low for vendor service fields.
- **`event.outcome` / `event.type`** — not set on OTel path; classic `aws.vpcflow` pipeline derives these from action (`packages/aws/data_stream/vpcflow/elasticsearch/ingest_pipeline/default.yml` L122–137); omit from Pass 4 or add downstream ingest.
- **`aws.vpc.flow.destination.service`** — **sibling evidence** (`test-v5-all-fields.log-expected.json` `pkt_dst_service`); not referenced in bundled dashboard ES|QL; validate in customer indices before relying on `service.target.name` fallback branch.
- **Well-known port → service name** (e.g. `:443` → HTTPS) — not indexed; no semantic literals in `CASE`.
- **`network.interface.name`** — ENI observation point / dashboard filter; not actor or remote target (Pass 3 scope context).
- **`destination.*` is network peer context** — mapped to `host.target.*` for cross-integration query normalization only; ingest does not populate official ECS `*.target.*` on this path (`target_enhancement_packages.csv` = none).
- **`host.id`** — OTel may set from `instance-id`; not used in dashboards; preserved when present — does not block `host.ip` / `host.name` fallbacks from `source.address` (column-level preserve).
- **Pass 4 tautology cleanup** — no `CASE(col, col, …)` branches; `source.address` / `destination.address` excluded from detection flags; actor/target/action `EVAL` uses per-column `IS NOT NULL` preserve (not `CASE(actor_exists|target_exists|action_exists, <col>, …)`).
- **Pass 4 CASE syntax (§10)** — all mapped `CASE` use odd-arity defaults (`null`) or valid **3-arg** preserve/fallback; never **4-arg** `CASE(flag, col, bare_field, null)` (bare field parses as a condition). `event.action` preserve is `event.action IS NOT NULL`, not `action_exists`. Full pipeline fragment aligned with combined `EVAL` blocks.
- **Classic parity** — For full `event.action` / `event.outcome` / `event.type` at ingest, use Agent `aws.vpcflow` pipeline or downstream processors on `aws.vpcflow.otel` indices.
