# ti_misp

## Product Domain

MISP (Malware Information Sharing Platform, now the Open Source Threat Intelligence and Sharing Platform) is an open-source threat intelligence platform for collecting, storing, correlating, and sharing structured cyber threat information. Organizations use MISP to centralize indicators of compromise (IOCs), malware analysis, incident context, and related threat data in a standardized format, making intelligence reusable across security tools and trusted communities.

Threat intelligence sharing is a core MISP capability. The platform supports granular distribution models and sharing groups so organizations can exchange events and attributes with partners, sector communities, and federated MISP instances while respecting confidentiality policies. Built-in correlation links related indicators, campaigns, and events; decaying models track indicator freshness over time; and a REST automation API enables integration with SIEMs, IDS/IPS, firewalls, and other defensive systems.

Key capabilities include structured event and attribute management (IPs, domains, file hashes, URLs, and richer object templates), automated synchronization between instances, enrichment and workflow automation, and export to machine-readable formats for detection and blocking. Common use cases include aggregating OSINT and commercial feeds into a single hub, collaborative incident analysis across CSIRTs and ISACs, operationalizing IOCs for indicator-matching and threat hunting, and pushing actionable intelligence to downstream security controls.

## Data Collected (brief)

The integration uses the MISP REST API to poll threat intelligence indicators from a running MISP instance via Elastic Agent. It collects two data streams: **Threat** (event-level indicators with event, attribute, object, and organization context) and **Threat Attributes** (granular attribute data from `/attributes/restSearch`, including decay scores and IOC expiration metadata), with configurable polling intervals, filters, and support for active-only indicator indices via Elastic transforms.

## Expected Audit Log Entities

This integration does **not** collect MISP audit or user-activity logs. MISP exposes separate audit APIs for console/API actions (logins, event edits, attribute changes); neither stream polls those endpoints. Both streams are threat-intelligence enrichment (`event.kind: enrichment`, `event.category: threat`, `event.type: indicator`) and are treated below as **audit-adjacent** sources where actor/target semantics still help entity analytics.

No ECS `*.target.*` fields are populated (`target_enhancement_packages.csv`: `ti_misp,none`). No `destination.user.*` or `destination.host.*` in pipelines (`destination_identity_hits.csv`: not listed). Targets here are **IOC observables** (what an indicator describes), not entities acted upon in an audit event.

**`event.action` is absent** on both streams — not present in `sample_event.json`, any `*-expected.json`, or either ingest pipeline. Pipelines statically set `event.kind`, `event.category`, and `event.type` only (`threat/default.yml` L10–18; `threat_attributes/default.yml` L10–18). These are enrichment snapshots of published MISP attributes, not per-operation audit verbs.

### Event action (semantic)

Neither stream records a meaningful per-event operation verb. Documents represent **polled IOC attribute state** from MISP REST APIs (`/events/restSearch` on **threat**, `/attributes/restSearch` on **threat_attributes**), not user or API actions at ingest time. There is no login, create, update, or delete action indexed on each document.

| Action (normalized label) | Classification | Confidence | Evidence | Per-stream notes |
| --- | --- | --- | --- | --- |
| *(no per-event action)* | — | high | `event.action` absent from all fixtures and pipelines; no vendor `action` / `operation` / `event_type` field in MISP poll payloads | Both streams — enrichment indicator documents, not audit events |
| Threat indicator enrichment (ECS taxonomy) | data_access | high | Static pipeline sets: `event.kind: enrichment`, `event.category: [threat]`, `event.type: [indicator]` | Describes ECS event class, **not** a mapped `event.action` value |

Do not substitute `event.type: indicator` or `event.category: threat` for `event.action` — they classify the ECS event, not the verb performed.

### Event action (ECS candidates)

| ECS / vendor field | Mapped to `event.action` today? | Mapping correct? | Recommended `event.action` value (from fixtures) | Enhancement candidate? | Evidence |
| --- | --- | --- | --- | --- | --- |
| `event.action` | no | n/a | — | no | Not set in pipelines or fixtures |
| `event.type` | no (taxonomy, not action) | n/a | `indicator` | no | Static `set: [indicator]` both pipelines L16–18; ECS event type, not operation verb |
| `event.category` | no (taxonomy, not action) | n/a | `threat` | no | Static `set: [threat]` both pipelines L13–15 |
| `misp.attribute.type` | no | n/a | e.g. `md5`, `ip-dst`, `domain`, `sha256` | no | MISP IOC observable type → `threat.indicator.type`; describes indicator shape, not user/API action (`threat/sample_event.json`: `sha256`; `threat/.../test-misp-sample-ndjson.log-expected.json`: `md5`, `domain\|ip`) |
| `misp.attribute.category` | no | n/a | e.g. `Payload delivery`, `Network activity`, `External analysis` | no | MISP attribute taxonomy in fixtures; context label, not an action verb |
| `misp.event.published` | no | n/a | — | no | Boolean publish state on parent event (e.g. `published: true` in threat expected fixtures); state metadata, not indexed action |

No vendor field in polled MISP JSON names a console/API operation suitable for `event.action`. True MISP audit actions (e.g. `login`, `edit`, `publish`) live on the separate MISP audit API, which this integration does not ingest.

### Actor (semantic)

| Entity | Classification | Entity type (if general) | Confidence | Evidence | Per-stream notes |
| --- | --- | --- | --- | --- | --- |
| MISP event creator | user | — | medium | `misp.event.event_creator_email` → `user.email`; `user.roles: ["reporting_user"]` appended when email is set (both pipelines). `threat/sample_event.json`: `admin@admin.test`; `threat_attributes/.../test-misp-sample-ndjson.log-expected.json`: `user@example.com` | Present only when source event includes `event_creator_email`; absent in most OSINT fixtures (CIRCL, ESET, CUDESO) |
| Creating / publishing organization | general | organization | high | **threat**: full `misp.orgc.id`, `misp.orgc.name`, `misp.orgc.uuid`, `misp.orgc.local` retained (e.g. `"CIRCL"`, `"ESET"`, `"CUDESO"` in `threat/.../test-misp-sample-ndjson.log-expected.json`). **threat_attributes**: `misp.event.orgc_id` only; no `misp.orgc.name` in fixtures | **threat** has richer org creator context; **threat_attributes** reduces to org IDs |
| External intel feed source (via provider) | general | organization | medium | Pipeline intent: `threat.indicator.provider` ← `misp.event.Orgc.name` when `Orgc.local == 'false'` (**threat** stream only). **threat_attributes** statically sets `provider: misp` | External org name mapping is broken in **threat** fixtures (see Gaps); **threat_attributes** never sets external provider name |

Most OSINT-sourced documents have **no ECS `user.*` actor**; the creating organization under `misp.orgc.*` (or `misp.event.orgc_id`) is the primary actor proxy.

### Actor (ECS candidates)

| ECS / vendor field | Role | Mapped today? | Mapping correct? | Confidence | Evidence |
| --- | --- | --- | --- | --- | --- |
| `user.email` | Event creator (reporting user) | yes (when `event_creator_email` present) | yes | high | `rename: misp.event.event_creator_email → user.email` in both pipelines; fixtures above |
| `user.roles` | Creator role hint | yes (when email set) | partial | medium | Static append `"reporting_user"` — descriptive, not from MISP role API |
| `misp.orgc.id` / `.name` / `.uuid` / `.local` | Creating organization | yes (**threat** only) | yes | high | `rename: misp.event.Orgc → misp.orgc`; CIRCL/ESET/CUDESO in threat expected fixtures |
| `misp.event.orgc_id` | Creating org ID | yes | yes | high | Retained on both streams; sole org actor field on **threat_attributes** |
| `organization.id` | Hosting MISP instance org | yes (**threat_attributes** only) | n/a | high | `rename: misp.event.org_id → organization.id`; `sample_event.json` / expected fixtures — scope context, not event creator |
| `threat.indicator.provider` | External feed / publishing org name | yes | no | medium | **threat** pipeline sets from `Orgc.name` when `Orgc.local == 'false'`, but condition compares to string `'false'` while fixtures have boolean `local: false` — CIRCL/ESET events still show `provider: "misp"`. **threat_attributes** always `misp` |
| `threat.feed.name` | Feed platform label | yes (static) | n/a | high | `set: "MISP"` — identifies feed, not a human actor |
| Tag `user_id` (raw JSON) | Tag author | no | n/a | low | Present in raw `Tag[].user_id` (e.g. `"0"`) but stripped with `misp.tag` removal; not mapped to `user.id` |

### Target (semantic)

Each document is one MISP attribute (IOC), not an audited object change. Targets are **indicator observables** layered as follows:

| Layer | Description | Entity | Classification | Entity type (if general) | Confidence | Evidence | Per-stream notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 — Platform / feed | Threat intel platform and feed identity | MISP / MISP feed | service | — | high | `threat.feed.name: "MISP"` (static, both pipelines); dashboards use `threat.indicator.provider` for feed breakdown | Layer 1 is the TI platform, not a cloud API target |
| 2 — Event / case context | Parent MISP event the IOC belongs to | MISP event | general | threat_event | high | `misp.event.id`, `misp.event.info`, `misp.event.uuid`, `misp.event.threat_level_id` in fixtures (e.g. `"OSINT - New Arena Crysis Ransomware Variant Released"`, Nitro APT event) | Same event metadata on both streams; **threat_attributes** adds decay fields on attributes |
| 3 — IOC observable | The attribute value acted upon for detection | varies by `misp.attribute.type` | host / user / service / general | file_artifact, registry_key, autonomous_system, untyped_text, … | high (typed IOCs); medium (unmapped types) | Pipeline maps `misp.attribute.type` → `threat.indicator.*`; examples below | **threat** prefers `misp.object.attribute` over outer attribute when object exists (`sample_event.json` sha256 from file object) |

Layer 3 examples from fixtures:

| `misp.attribute.type` | Classification | ECS / vendor evidence |
| --- | --- | --- |
| `ip-src`, `ip-dst`, `ip-dst\|port`, `domain\|ip` | host | `threat.indicator.ip` (e.g. `89.160.20.156`, `89.160.20.156\|2222`); `threat.indicator.url.domain` + `threat.indicator.ip` for `domain\|ip` |
| `hostname`, `domain` | host | `threat.indicator.url.domain` (e.g. `xenserver.ddns.net`) |
| `email-src`, `email-dst` | user | `threat.indicator.email.address` (e.g. `claudiobonadio88@gmail.com`, `lisa.cuddy@wind0ws.kz`) — IOC email, not audit principal |
| `url`, `link`, `uri` | service | `threat.indicator.url.*` (e.g. `http://get.adobe.com/stats/...`, VirusTotal reference links) |
| `md5`, `sha256`, `sha1`, `filename\|sha256` | general | file_artifact | `threat.indicator.file.hash.*`, `threat.indicator.file.name` (e.g. Dharma md5, Nitro sha256, `google_update_checker.js`) |
| `regkey` | general | registry_key | `threat.indicator.registry.key` (e.g. `HKLM\SOFTWARE\Microsoft\Active`) |
| `AS` | general | autonomous_system | `threat.indicator.as.number` (e.g. `48031` in **threat_attributes** fixture) |
| `email-subject` | general | email_subject | `threat.indicator.email.subject` (e.g. `"Subject Payment"` — **threat_attributes** only) |
| `text`, `comment` | general | untyped_indicator | `misp.attribute.value` retained when type not mapped (e.g. `"Nitro"` text attribute) |
| `mutex`, `mime-type`, `cpe` | general | mutex / mime / software | Type set on **threat_attributes** pipeline only; value often remains vendor-only |

`ip-src` vs `ip-dst` direction is **not preserved** — both map to `threat.indicator.ip`.

### Target (ECS candidates)

| ECS / vendor field | Layer | Classification | Mapped today? | Mapping correct? | ECS target bucket | Enhancement candidate? | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `threat.feed.name` | 1 | service | yes | n/a | context-only | no | Static `"MISP"`; feed identity, not `service.target.*` |
| `threat.indicator.provider` | 1 | general (organization) | yes | no | context-only | no | Intended external org name; broken boolean/string check on **threat**; static `misp` on **threat_attributes** |
| `misp.event.id` / `.info` / `.uuid` | 2 | general | yes | yes | context-only | no | Event case context in all fixtures |
| `misp.object.name` / `.meta_category` | 2 | general | yes (**threat** when object present) | yes | context-only | no | File object context in `threat/sample_event.json` |
| `threat.indicator.ip` | 3 | host | yes | partial | context-only | no | IOC IP/host observable; `ip-src`/`ip-dst` direction lost |
| `threat.indicator.url.domain` | 3 | host | yes | yes | context-only | no | Domain/hostname IOCs |
| `threat.indicator.port` | 3 | host | yes | yes | context-only | no | From `ip-*\|port` grok (e.g. port `2222`) |
| `threat.indicator.email.address` | 3 | user | yes | partial | context-only | no | Email IOC value — threat observable, not audit `user.target.*` |
| `threat.indicator.email.subject` | 3 | general | yes (**threat_attributes**) | yes | context-only | no | `email-subject` type |
| `threat.indicator.url.full` / `.original` | 3 | service | yes | yes | context-only | no | URL/link/uri IOCs; defanged URL kept as-is (`hxxp://bad[.]example[.]com/...`) |
| `threat.indicator.file.hash.*` / `.file.name` | 3 | general | yes | yes | context-only | no | Hash and filename IOCs |
| `threat.indicator.registry.key` | 3 | general | yes | yes | context-only | no | `regkey` attributes |
| `threat.indicator.as.number` | 3 | general | yes | yes | context-only | no | AS attributes |
| `threat.indicator.mac` | 3 | host | yes (when type present) | yes | context-only | no | `mac-address` / `mac-eui-64` pipeline branches |
| `threat.indicator.type` | 3 | — | yes | yes | context-only | no | ECS indicator type enum from MISP attribute type |
| `misp.attribute.type` / `.uuid` / `.category` | 3 | — | yes | yes | context-only | no | Canonical vendor IOC metadata retained after value removal |
| `misp.attribute.value` | 3 | varies | partial | yes | context-only | no | Removed when `threat.indicator.type` is set; retained for unmapped types (`text`, `comment`) |
| `misp.context.attribute.*` | 3 | — | yes (**threat** with objects) | yes | context-only | no | Outer attribute kept as context when object attribute is primary |
| `destination.user.*` / `destination.host.*` | — | — | no | n/a | n/a | no | Not used |
| `user.target.*` / `host.target.*` / `service.target.*` | — | — | no | n/a | n/a | no | Not applicable for TI enrichment; audit CSV confirms `none` |

### Gaps and mapping notes

- **No true audit stream** — actor/target tables describe TI enrichment semantics only. MISP audit API (user logins, event edits) is out of scope for this package.
- **`event.action` gap** — no pipeline mapping and no vendor operation field in polled payloads. `misp.attribute.type` (IOC type) and `event.type: indicator` are **not** suitable substitutes for `event.action`; mapping them would conflate observable classification with audit verbs. No enhancement recommended unless a future stream ingests MISP audit logs.
- **`threat.indicator.provider` bug** — **threat** pipeline checks `misp.event.Orgc.local == 'false'` (string) before rename; JSON fixtures use boolean `false`, so external org names (`CIRCL`, `ESET`) never replace `"misp"` in expected output despite `misp.orgc.local: false` and `misp.orgc.name` being present. **threat_attributes** has no external-provider logic at all.
- **Actor org vs hosting org** — `misp.orgc.*` (creator) vs `organization.id` / `misp.event.org_id` (instance host on **threat_attributes**) are distinct; only creator org belongs in actor analysis. **threat** pipeline removes `misp.org` (hosting org) during cleanup.
- **Tag `user_id` unmapped** — MISP tag author IDs are discarded with tag cleanup; no `user.id` or `related.user` enrichment.
- **IOC email ≠ audit user target** — `email-src`/`email-dst` map to `threat.indicator.email.address` (threat observable). These are not de-facto `destination.user.*` targets and should not migrate to `user.target.*`.
- **Direction loss on IP attributes** — `ip-src` and `ip-dst` both become `threat.indicator.ip` with no `source.*`/`destination.*` split; MISP directional semantics live only in `misp.attribute.type`.
- **Unmapped attribute types** — `text`, `comment`, and some `email-message` types keep value under `misp.attribute.*` only; no ECS threat indicator fields.
- **Stream differences** — **threat_attributes** adds decay metadata (`misp.attribute.decayed`, `decay_score`, `decayed_at`), `organization.id`, `email-subject`, defanged URL handling, and extra types (`mutex`, `mime-type`, `cpe`); lacks full `misp.orgc.*` on polled attribute payloads.
- **target-fields-audit alignment** — CSV row `ti_misp,none,false,...` matches: no ECS `*.target.*` population and no enhancement path for standard audit target buckets on IOC enrichment data.

### Per-stream notes

**threat (`ti_misp.threat`)** — Polls event-centric API responses from `/events/restSearch`. One document per attribute (object attribute preferred over standalone attribute when `misp.object` exists). Richest actor context via `misp.orgc.*` and optional `user.email`. No `event.action`; static ECS taxonomy only. Galaxy/tag metadata flattened to `tags` and `threat.indicator.marking.tlp`.

**threat_attributes (`ti_misp.threat_attributes`)** — Polls `/attributes/restSearch` for granular attributes with decay/expiration lifecycle. Maps hosting org to `organization.id`. Supports active-IOC transform source labeling (`labels.is_ioc_transform_source`). Same IOC type → ECS mapping as **threat**, plus `email-subject` and defanged URL samples not present in **threat** fixtures. No `event.action`; decay scripts compute `misp.attribute.decayed` / `decayed_at` but do not index lifecycle verbs.

## Example Event Graph

These examples come from the **threat** and **threat_attributes** streams. Neither stream ingests MISP audit logs; documents are polled IOC enrichment snapshots (`event.kind: enrichment`, `event.type: indicator`). There is no indexed `event.action` — the action label below describes the ECS event class, not a console/API verb.

### Example 1: File hash IOC from object attribute

**Stream:** `ti_misp.threat` · **Fixture:** `packages/ti_misp/data_stream/threat/sample_event.json`

```
Actor (user, admin@admin.test) → indicator enrichment → Target (file hash sha256)
```

#### Actor

| Field | Value |
| --- | --- |
| id | admin@admin.test |
| name | admin@admin.test |
| type | user |
| sub_type | reporting_user |

**Field sources:**

- `id ← user.email` (renamed from `misp.event.event_creator_email`)
- `name ← user.email`
- `sub_type ← user.roles[0]` (static append `"reporting_user"` when email is set)

Creating organization **ORGNAME** (`misp.orgc.id: 1`, `misp.orgc.uuid: 78acad2d-cc2d-4785-94d6-b428a0070488`) is also present as a secondary actor proxy.

#### Event action

| Field | Value |
| --- | --- |
| action | indicator enrichment |
| source_field | `event.kind` |
| source_value | `enrichment` |

**Not mapped to ECS `event.action` today** — `event.action` is absent from fixtures and pipelines; `event.kind` classifies the document as enrichment, not an audit operation verb.

#### Target

| Field | Value |
| --- | --- |
| id | f33c27745f2bd87344be790465ef984a972fd539dc83bd4f61d4242c607ef1ee |
| type | general |
| sub_type | file_artifact |

**Field sources:**

- `id ← threat.indicator.file.hash.sha256` (from object attribute `misp.attribute.type: sha256`, preferred over outer `filename` attribute)
- Parent event context: `misp.event.info` = `"Test event 3 objects and attributes"`, `misp.object.name` = `"file"`

#### Mermaid

```mermaid
flowchart LR
  A["Actor: admin@admin.test"] --> E["indicator enrichment"]
  E --> T["Target: sha256 file IOC"]
```

### Example 2: OSINT domain|ip network indicator

**Stream:** `ti_misp.threat` · **Fixture:** `packages/ti_misp/data_stream/threat/_dev/test/pipeline/test-misp-sample-ndjson.log-expected.json` (second expected event)

```
Actor (organization, CIRCL) → indicator enrichment → Target (host, your-ip.getmyip.com / 89.160.20.156)
```

#### Actor

| Field | Value |
| --- | --- |
| id | 55f6ea5e-2c60-40e5-964f-47a8950d210f |
| name | CIRCL |
| type | general |
| sub_type | organization |

**Field sources:**

- `id ← misp.orgc.uuid`
- `name ← misp.orgc.name`
- `sub_type` inferred from creating-org semantics (`misp.orgc.local: false` — external publishing org)

No `user.email` on this OSINT event; creating organization is the primary actor.

#### Event action

| Field | Value |
| --- | --- |
| action | indicator enrichment |
| source_field | `event.kind` |
| source_value | `enrichment` |

**Not mapped to ECS `event.action` today.**

#### Target

| Field | Value |
| --- | --- |
| id | 5bf30242-8ef4-4c52-a2d7-0b7b0a016219 |
| name | your-ip.getmyip.com |
| type | host |
| ip | 89.160.20.156 |

**Field sources:**

- `id ← misp.attribute.uuid`
- `name ← threat.indicator.url.domain` (from `misp.attribute.type: domain|ip`)
- `ip ← threat.indicator.ip`
- Event case context: `misp.event.info` = `"OSINT - New Arena Crysis Ransomware Variant Released"`

#### Mermaid

```mermaid
flowchart LR
  A["Actor: CIRCL"] --> E["indicator enrichment"]
  E --> T["Target: your-ip.getmyip.com"]
```

### Example 3: Decayed URL reference link (attributes stream)

**Stream:** `ti_misp.threat_attributes` · **Fixture:** `packages/ti_misp/data_stream/threat_attributes/sample_event.json`

```
Actor (organization, orgc_id 2) → indicator enrichment → Target (service, labs.opendns.com URL)
```

#### Actor

| Field | Value |
| --- | --- |
| id | 2 |
| type | general |
| sub_type | organization |

**Field sources:**

- `id ← misp.event.orgc_id` (sole org creator field on **threat_attributes** — no `misp.orgc.name` in this fixture)
- Hosting MISP instance org: `organization.id: 1` (scope context, not the publishing actor)

No `user.email` on this fixture.

#### Event action

| Field | Value |
| --- | --- |
| action | indicator enrichment |
| source_field | `event.kind` |
| source_value | `enrichment` |

**Not mapped to ECS `event.action` today.** Decay state (`misp.attribute.decayed: true`, `decayed_at: 2014-10-08T07:14:05.000Z`) is lifecycle metadata, not an indexed action verb.

#### Target

| Field | Value |
| --- | --- |
| id | 542e4cbd-ee78-4a57-bfb8-1fda950d210b |
| name | labs.opendns.com |
| type | service |

**Field sources:**

- `id ← misp.attribute.uuid`
- `name ← threat.indicator.url.domain`
- Full URL: `threat.indicator.url.full` = `http://labs.opendns.com/2014/10/02/opendns-and-bash/`
- Event case context: `misp.event.info` = `"OSINT ShellShock scanning IPs from OpenDNS"`

#### Mermaid

```mermaid
flowchart LR
  A["Actor: orgc_id 2"] --> E["indicator enrichment"]
  E --> T["Target: labs.opendns.com"]
```

## ES|QL Entity Extraction

**Package type: agent-backed** (`policy_templates`, two `data_stream/` directories with Tier A fixtures and ingest pipelines). Router: **`data_stream.dataset`** (`ti_misp.threat`, `ti_misp.threat_attributes` per `sample_event.json` and dashboards). Secondary discriminator: **`misp.attribute.type`** for IOC target classification. Neither stream ingests MISP audit logs — documents are polled threat-indicator enrichment (`event.kind: enrichment`, `event.type: indicator`), not per-operation audit events. Pass 4 is **fill-gaps-only**: detection flags (`actor_exists`, `target_exists`, `action_exists`) run first for query semantics; **mapped columns use column-level preserve** (`<col> IS NOT NULL`), not `CASE(actor_exists, <col>, …)` / `CASE(target_exists, <col>, …)` — e.g. `entity.id` from org fallback must not block `user.id` from `user.email` when the creator email is set (Pass 4 §10). No ECS `*.target.*` at ingest today (`target-fields-audit`: `ti_misp,none`). **`event.action` is absent** on both streams — no event-action `EVAL` block. **`user.email` omitted** from actor `EVAL` (ingest-only; pipeline rename only).

### Dataset inventory

| data_stream.dataset | Stream role | Actor classification(s) | Target classification(s) | Extraction |
| --- | --- | --- | --- | --- |
| `ti_misp.threat` | threat enrichment (events API) | user, general (organization) | host, user, service, general (IOC) | partial |
| `ti_misp.threat_attributes` | threat enrichment (attributes API) | general (organization) | host, user, service, general (IOC) | partial |

### Field mapping plan

#### Actor mappings

| Output column | Source field(s) | Condition (dataset + optional) | Confidence | Notes |
| --- | --- | --- | --- | --- |
| `user.id` | `user.id` | `data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes")` | high | **preserve existing** |
| `user.id` | `user.email` | `data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND user.email IS NOT NULL` | high | **vendor fallback** — creator email as id when `user.id` empty |
| `user.name` | `user.name` | `data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes")` | high | **preserve existing** |
| `user.name` | `user.email` | `data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND user.email IS NOT NULL` | high | **vendor fallback** — no separate name at ingest |
| `user.email` | `misp.event.event_creator_email` → `user.email` | `data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes")` | high | **ingest-only — no ES\|QL** — pipeline rename only; vendor field removed at ingest; **omit** — `CASE(…, user.email, …, user.email, null)` is identity no-op |
| `entity.id` | `entity.id` | `data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes")` | high | **preserve existing** |
| `entity.id` | `misp.orgc.uuid` | `data_stream.dataset == "ti_misp.threat" AND user.email IS NULL` | high | **vendor fallback** — creating org (OSINT fixtures: CIRCL/ESET) |
| `entity.id` | `misp.event.orgc_id` | `data_stream.dataset == "ti_misp.threat_attributes" AND user.email IS NULL` | high | **vendor fallback** — sole org creator field on attributes stream |
| `entity.name` | `entity.name` | `data_stream.dataset == "ti_misp.threat"` | high | **preserve existing** |
| `entity.name` | `misp.orgc.name` | `data_stream.dataset == "ti_misp.threat" AND user.email IS NULL` | high | **vendor fallback** |
| `entity.type` | `entity.type` | `data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes")` | high | **preserve existing** |
| `entity.type` | `"organization"` | `data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND user.email IS NULL` | medium | **semantic literal** — publishing org when no `user.email` |
| `entity.sub_type` | `"reporting_user"` | `data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND user.email IS NOT NULL` | medium | **semantic literal** — aligns with ingest `user.roles` |

#### Target mappings

| Output column | Source field(s) | Condition (dataset + optional) | Confidence | Notes |
| --- | --- | --- | --- | --- |
| `service.target.name` | `service.target.name` | `data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes")` | high | **preserve existing** |
| `service.target.name` | `threat.feed.name` | `data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes")` | high | **vendor fallback** — static `"MISP"` (Layer 1 platform) |
| `service.target.name` | `threat.indicator.url.domain` | `data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND misp.attribute.type IN ("url", "link", "uri")` | high | **vendor fallback** — URL IOC endpoint (Pass 3 example 3) |
| `host.target.ip` | `host.target.ip` | `data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes")` | high | **preserve existing** |
| `host.target.ip` | `threat.indicator.ip` | `data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND misp.attribute.type IN ("ip-src", "ip-dst", "ip-dst\|port", "domain\|ip")` | high | **vendor fallback** — `ip-src`/`ip-dst` direction not preserved |
| `host.target.name` | `host.target.name` | `data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes")` | high | **preserve existing** |
| `host.target.name` | `threat.indicator.url.domain` | `data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND misp.attribute.type IN ("domain", "hostname", "domain\|ip")` | high | **vendor fallback** |
| `host.target.port` | `threat.indicator.port` | `data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND misp.attribute.type == "ip-dst\|port"` | high | **vendor fallback** — fixture port `2222` |
| `user.target.email` | `user.target.email` | `data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes")` | high | **preserve existing** |
| `user.target.email` | `threat.indicator.email.address` | `data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND misp.attribute.type IN ("email-src", "email-dst")` | high | **vendor fallback** — IOC email observable, not audit principal |
| `entity.target.id` | `entity.target.id` | `data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes")` | high | **preserve existing** |
| `entity.target.id` | `threat.indicator.file.hash.sha256` | `data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND misp.attribute.type == "sha256"` | high | **vendor fallback** |
| `entity.target.id` | `threat.indicator.file.hash.md5` | `data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND misp.attribute.type == "md5"` | high | **vendor fallback** |
| `entity.target.id` | `threat.indicator.file.hash.sha1` | `data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND misp.attribute.type IN ("sha1", "filename\|sha1")` | high | **vendor fallback** |
| `entity.target.id` | `misp.attribute.uuid` | `data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes")` | high | **vendor fallback** — default IOC id (Pass 3 `domain\|ip`, `link`) |
| `entity.target.name` | `threat.indicator.registry.key` | `data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND misp.attribute.type == "regkey"` | high | **vendor fallback** |

#### Event action mappings

| Output column | Source field(s) | Condition (dataset + optional) | Confidence | Notes |
| --- | --- | --- | --- | --- |
| — | — | — | — | `event.action` absent; do not map `event.type` / `misp.attribute.type` as verbs (Pass 2) |

### Detection flags (mandatory — run first)

**Tuned predicate:** `actor_exists` **excludes `user.email`** — ingest maps `misp.event.event_creator_email` → `user.email` only (no `user.id` / `user.name`), so creator promotion must run when those columns are empty. `target_exists` uses standard `*.target.*` columns (unpopulated at ingest today). **Actor/target `EVAL` blocks use column-level preserve** (`<col> IS NOT NULL`) — not `CASE(actor_exists, <col>, …)` / `CASE(target_exists, <col>, …)` — so one populated sibling column does not block fallbacks on empty columns (Pass 4 §10).

```esql
| EVAL
  actor_exists = user.id IS NOT NULL OR user.name IS NOT NULL
    OR entity.id IS NOT NULL OR entity.name IS NOT NULL,
  target_exists = user.target.id IS NOT NULL OR user.target.name IS NOT NULL OR user.target.email IS NOT NULL
    OR host.target.id IS NOT NULL OR host.target.ip IS NOT NULL OR host.target.name IS NOT NULL
    OR service.target.id IS NOT NULL OR service.target.name IS NOT NULL
    OR entity.target.id IS NOT NULL OR entity.target.name IS NOT NULL,
  action_exists = event.action IS NOT NULL
```

**Semantics:** `actor_exists` / `target_exists` / `action_exists` are query-time helpers only. Mapped columns use **column-level** `CASE(<col> IS NOT NULL, <col>, …)` — not `CASE(actor_exists, user.id, user.email, null)` (4 args — `user.email` is a **condition**, not a value) or `CASE(actor_exists, user.id, …)` when `entity.id` alone satisfies the flag.

### Combined ES|QL — actor fields

**ES|QL `CASE` arity:** Arguments are **(condition, value)** pairs; odd count → last arg is default. Use **5-arg** `CASE(user.id IS NOT NULL, user.id, data_stream.dataset IN (…) AND user.email IS NOT NULL, user.email, null)` — not **4-arg** `CASE(actor_exists, user.id, user.email, null)` or `CASE(user.id IS NOT NULL, user.id, user.email, null)` (3rd arg `user.email` is a **condition**, not a value).

Omitted from actor `EVAL` (ingest-only — no alternate query-time source): `user.email` (`misp.event.event_creator_email` renamed at ingest; no `CASE(…, user.email, …, user.email, null)`).

```esql
| EVAL
  user.id = CASE(
    user.id IS NOT NULL, user.id,
    data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND user.email IS NOT NULL, user.email,
    null
  ),
  user.name = CASE(
    user.name IS NOT NULL, user.name,
    data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND user.email IS NOT NULL, user.email,
    null
  ),
  entity.id = CASE(
    entity.id IS NOT NULL, entity.id,
    data_stream.dataset == "ti_misp.threat" AND user.email IS NULL AND misp.orgc.uuid IS NOT NULL, misp.orgc.uuid,
    data_stream.dataset == "ti_misp.threat_attributes" AND user.email IS NULL AND misp.event.orgc_id IS NOT NULL, TO_STRING(misp.event.orgc_id),
    null
  ),
  entity.name = CASE(
    entity.name IS NOT NULL, entity.name,
    data_stream.dataset == "ti_misp.threat" AND user.email IS NULL AND misp.orgc.name IS NOT NULL, misp.orgc.name,
    null
  ),
  entity.type = CASE(
    entity.type IS NOT NULL, entity.type,
    data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND user.email IS NOT NULL, "user",
    data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND user.email IS NULL, "organization",
    null
  ),
  entity.sub_type = CASE(
    entity.sub_type IS NOT NULL, entity.sub_type,
    data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND user.email IS NOT NULL, "reporting_user",
    null
  )
```

### Combined ES|QL — event action

Not produced — `event.action` is absent from fixtures and pipelines on both streams; `event.type: indicator` and `misp.attribute.type` classify IOC shape, not audit verbs (Pass 2).

### Combined ES|QL — target fields

```esql
| EVAL
  service.target.name = CASE(
    service.target.name IS NOT NULL, service.target.name,
    data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND misp.attribute.type IN ("url", "link", "uri") AND threat.indicator.url.domain IS NOT NULL, threat.indicator.url.domain,
    data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND threat.feed.name IS NOT NULL, threat.feed.name,
    null
  ),
  host.target.ip = CASE(
    host.target.ip IS NOT NULL, host.target.ip,
    data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND misp.attribute.type IN ("ip-src", "ip-dst", "ip-dst|port", "domain|ip") AND threat.indicator.ip IS NOT NULL, threat.indicator.ip,
    null
  ),
  host.target.name = CASE(
    host.target.name IS NOT NULL, host.target.name,
    data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND misp.attribute.type IN ("domain", "hostname", "domain|ip") AND threat.indicator.url.domain IS NOT NULL, threat.indicator.url.domain,
    null
  ),
  host.target.port = CASE(
    host.target.port IS NOT NULL, host.target.port,
    data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND misp.attribute.type == "ip-dst|port" AND threat.indicator.port IS NOT NULL, threat.indicator.port,
    null
  ),
  user.target.email = CASE(
    user.target.email IS NOT NULL, user.target.email,
    data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND misp.attribute.type IN ("email-src", "email-dst") AND threat.indicator.email.address IS NOT NULL, threat.indicator.email.address,
    null
  ),
  entity.target.id = CASE(
    entity.target.id IS NOT NULL, entity.target.id,
    data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND misp.attribute.type == "sha256" AND threat.indicator.file.hash.sha256 IS NOT NULL, threat.indicator.file.hash.sha256,
    data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND misp.attribute.type == "md5" AND threat.indicator.file.hash.md5 IS NOT NULL, threat.indicator.file.hash.md5,
    data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND misp.attribute.type IN ("sha1", "filename|sha1") AND threat.indicator.file.hash.sha1 IS NOT NULL, threat.indicator.file.hash.sha1,
    data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND misp.attribute.uuid IS NOT NULL, misp.attribute.uuid,
    null
  ),
  entity.target.name = CASE(
    entity.target.name IS NOT NULL, entity.target.name,
    data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND misp.attribute.type == "regkey" AND threat.indicator.registry.key IS NOT NULL, threat.indicator.registry.key,
    null
  ),
  entity.target.type = CASE(
    entity.target.type IS NOT NULL, entity.target.type,
    data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND misp.attribute.type IN ("ip-src", "ip-dst", "ip-dst|port", "domain|ip", "hostname", "domain"), "host",
    data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND misp.attribute.type IN ("email-src", "email-dst"), "user",
    data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND misp.attribute.type IN ("url", "link", "uri"), "service",
    data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND misp.attribute.type IN ("md5", "sha256", "sha1", "filename|sha256", "filename|sha1", "regkey"), "general",
    null
  )
```

### Full pipeline fragment (optional)

```esql
FROM logs-*
| EVAL
  actor_exists = user.id IS NOT NULL OR user.name IS NOT NULL
    OR entity.id IS NOT NULL OR entity.name IS NOT NULL,
  target_exists = user.target.id IS NOT NULL OR user.target.name IS NOT NULL OR user.target.email IS NOT NULL
    OR host.target.id IS NOT NULL OR host.target.ip IS NOT NULL OR host.target.name IS NOT NULL
    OR service.target.id IS NOT NULL OR service.target.name IS NOT NULL
    OR entity.target.id IS NOT NULL OR entity.target.name IS NOT NULL,
  action_exists = event.action IS NOT NULL
| EVAL
  user.id = CASE(user.id IS NOT NULL, user.id, data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND user.email IS NOT NULL, user.email, null),
  user.name = CASE(user.name IS NOT NULL, user.name, data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND user.email IS NOT NULL, user.email, null),
  entity.id = CASE(entity.id IS NOT NULL, entity.id, data_stream.dataset == "ti_misp.threat" AND user.email IS NULL AND misp.orgc.uuid IS NOT NULL, misp.orgc.uuid, data_stream.dataset == "ti_misp.threat_attributes" AND user.email IS NULL AND misp.event.orgc_id IS NOT NULL, TO_STRING(misp.event.orgc_id), null),
  entity.name = CASE(entity.name IS NOT NULL, entity.name, data_stream.dataset == "ti_misp.threat" AND user.email IS NULL AND misp.orgc.name IS NOT NULL, misp.orgc.name, null),
  entity.type = CASE(entity.type IS NOT NULL, entity.type, data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND user.email IS NOT NULL, "user", data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND user.email IS NULL, "organization", null),
  entity.sub_type = CASE(entity.sub_type IS NOT NULL, entity.sub_type, data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND user.email IS NOT NULL, "reporting_user", null)
| EVAL
  service.target.name = CASE(service.target.name IS NOT NULL, service.target.name, data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND misp.attribute.type IN ("url", "link", "uri") AND threat.indicator.url.domain IS NOT NULL, threat.indicator.url.domain, data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND threat.feed.name IS NOT NULL, threat.feed.name, null),
  host.target.ip = CASE(host.target.ip IS NOT NULL, host.target.ip, data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND misp.attribute.type IN ("ip-src", "ip-dst", "ip-dst|port", "domain|ip") AND threat.indicator.ip IS NOT NULL, threat.indicator.ip, null),
  host.target.name = CASE(host.target.name IS NOT NULL, host.target.name, data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND misp.attribute.type IN ("domain", "hostname", "domain|ip") AND threat.indicator.url.domain IS NOT NULL, threat.indicator.url.domain, null),
  host.target.port = CASE(host.target.port IS NOT NULL, host.target.port, data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND misp.attribute.type == "ip-dst|port" AND threat.indicator.port IS NOT NULL, threat.indicator.port, null),
  user.target.email = CASE(user.target.email IS NOT NULL, user.target.email, data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND misp.attribute.type IN ("email-src", "email-dst") AND threat.indicator.email.address IS NOT NULL, threat.indicator.email.address, null),
  entity.target.id = CASE(entity.target.id IS NOT NULL, entity.target.id, data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND misp.attribute.type == "sha256" AND threat.indicator.file.hash.sha256 IS NOT NULL, threat.indicator.file.hash.sha256, data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND misp.attribute.type == "md5" AND threat.indicator.file.hash.md5 IS NOT NULL, threat.indicator.file.hash.md5, data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND misp.attribute.type IN ("sha1", "filename|sha1") AND threat.indicator.file.hash.sha1 IS NOT NULL, threat.indicator.file.hash.sha1, data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND misp.attribute.uuid IS NOT NULL, misp.attribute.uuid, null),
  entity.target.name = CASE(entity.target.name IS NOT NULL, entity.target.name, data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND misp.attribute.type == "regkey" AND threat.indicator.registry.key IS NOT NULL, threat.indicator.registry.key, null),
  entity.target.type = CASE(entity.target.type IS NOT NULL, entity.target.type, data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND misp.attribute.type IN ("ip-src", "ip-dst", "ip-dst|port", "domain|ip", "hostname", "domain"), "host", data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND misp.attribute.type IN ("email-src", "email-dst"), "user", data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND misp.attribute.type IN ("url", "link", "uri"), "service", data_stream.dataset IN ("ti_misp.threat", "ti_misp.threat_attributes") AND misp.attribute.type IN ("md5", "sha256", "sha1", "filename|sha256", "filename|sha1", "regkey"), "general", null)
| KEEP @timestamp, data_stream.dataset, misp.attribute.type, user.email, user.id, entity.id, entity.name, entity.type, host.target.ip, host.target.name, entity.target.id, service.target.name
```

### Streams excluded

*(none — both streams use partial TI enrichment extraction above)*

### Gaps and limitations

- **No MISP audit API** — console logins and event edits are out of scope; no `event.action` block.
- **`threat.indicator.provider` bug** — external org names may not replace `"misp"` due to boolean/string comparison; do not use as actor source until fixed.
- **`organization.id`** on **threat_attributes** — hosting instance org, not publishing actor; excluded from actor mapping.
- **Unmapped attribute types** (`text`, `comment`, `mutex`, `mime-type`, `cpe`) — value under `misp.attribute.*` only; typed target columns omitted.
- **IOC email ≠ audit user target** — `user.target.email` is threat-observable semantics (Pass 2/3), not IAM acted-upon user.
- **`ip-src` / `ip-dst` direction** — both map to `threat.indicator.ip`; ES|QL cannot restore MISP directional semantics.
- **Pass 2 alignment** — ingest-time `*.target.*` promotion from `threat.indicator.*` remains preferred; Pass 4 fills gaps without overwriting populated values.
- **Pass 4 tautology cleanup (§10)** — `user.email` omitted from actor `EVAL` (ingest-only; pipeline rename, no query-time vendor path); `user.id` / `user.name` fallbacks use `user.email` only when those columns are empty; no `CASE(col, col, …)` identity branches on mapped columns.
- **Pass 4 CASE syntax** — all `CASE` in actor/target blocks use column-level **5-arg** / **7-arg** / **9-arg** preserve (`<col> IS NOT NULL`, not `CASE(actor_exists, <col>, …)` or `CASE(target_exists, <col>, …)`). Never **4-arg** `CASE(actor_exists, col, bare_field, null)` or `CASE(col IS NOT NULL, col, bare_field, null)` (bare field parses as a **condition**). Full pipeline fragment aligned with combined `EVAL` blocks. Detection flags are helpers only.
