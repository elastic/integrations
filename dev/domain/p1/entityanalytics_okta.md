# entityanalytics_okta

## Product Domain (Okta entity analytics)

Okta is a cloud identity and access management (IAM) platform that serves as the authoritative directory for workforce and customer identities in many enterprises. Okta stores user accounts, group memberships, role assignments, and registered devices, exposing them through the Okta Management API (Core API v1). Security teams use this identity inventory to understand who exists in the environment, which accounts are privileged, how devices are enrolled, and how identity posture changes over time.

Entity Analytics in Elastic Security consumes identity inventory—not authentication or system logs—to build a living graph of users and devices for risk scoring, user behavior analytics (UBA), and context enrichment during investigations. The Okta Entity Analytics integration connects Elastic Agent to an Okta tenant via the REST API, periodically synchronizing user and device objects into Elasticsearch. Unlike event-driven log sources, this integration treats identities as assets: it performs full synchronizations on a configurable interval (default 24 hours) and ships incremental updates for changed, added, or removed objects between syncs (default every 15 minutes).

Core Okta concepts reflected in collected data include user lifecycle and profile attributes (login, email, name, department, manager, status), optional group membership and role enrichment, credential provider metadata, and registered devices (platform, serial number, disk encryption, secure hardware, status, associated users). Authentication to Okta supports API tokens, OAuth2 (service app with JWK/PEM), or the Okta Integration Network (OIN) Elastic app. Ingest pipelines normalize raw Okta API responses into ECS-aligned user, device, and asset fields and route documents to separate user and device data streams.

## Data Collected (brief)

- **Entity sync** (`entityanalytics_okta.entity`): Primary collection stream from the Elastic Agent entity-analytics input; polls Okta Management API endpoints (`/api/v1/users`, `/api/v1/devices`) for user and/or device objects depending on dataset selection (`users`, `devices`, or `all`). Events include full-sync write markers and incremental change notifications (`event.action` such as `user-discovered`, `device-discovered`, `started`).
- **Users** (`entityanalytics_okta.user`): Okta user account inventory routed from the entity stream. Includes user ID, status, lifecycle timestamps (created, activated, last login, password changed), profile attributes (login, email, name, title, department, manager, address, phone), credential provider, optional group memberships (`entityanalytics_okta.groups.*`), optional role assignments (`entityanalytics_okta.roles.*`), and ECS `user.*` profile and account fields.
- **Devices** (`entityanalytics_okta.device`): Okta registered device inventory routed from the entity stream. Includes device ID, status, platform, display name, serial number, disk encryption, secure hardware, registration state, associated users, and ECS `device.*` / `asset.*` mapping.
- **Identity context**: `labels.identity_source` tags the originating Okta tenant; `event.kind: asset` and IAM-oriented categorization support Entity Analytics workflows in Elastic Security.

## Expected Audit Log Entities

This integration performs **Okta entity inventory sync over the Management API**, not Okta System Log or other administrative audit streams. Elastic Agent polls `/api/v1/users` and `/api/v1/devices` on a schedule and ships snapshots and deltas of user and device objects; it does **not** ingest authentication events, admin actions, or lifecycle change audit records. Every document is an identity asset record (`event.kind: asset`); **actor/target audit semantics do not apply**. Fields below describe **inventory subjects** (the Okta object being synchronized), not an initiating principal or an acted-upon audit target. No ECS `user.target.*`, `host.target.*`, `service.target.*`, or `entity.target.*` fields are populated; the package does not appear in `destination_identity_hits.csv` (no `destination.user.*` / `destination.host.*`). Target-fields audit classified this package as **`none`** (`dev/target-fields-audit/out/target_enhancement_packages.csv`).

**`event.action` is partially populated.** Sync boundary markers retain agent-supplied `started` and `completed` (`sample_event.json`: `started`; pipeline allows both values). Inventory rows arrive from the agent with incremental sync markers (`user-discovered`, `user-modified`, `device-discovered`, `device-modified` per README and pipeline test inputs) but `default.yml`, `user.yml`, and `device.yml` **remove** `event.action` unless the value is `started` or `completed` (L9–12 / L17–20) — incremental sync semantics are not preserved in routed `user`/`device` output. This is inventory sync action vocabulary, not Okta System Log audit verbs (login, admin policy change, MFA enrollment).

Evidence: `packages/entityanalytics_okta/data_stream/entity/sample_event.json`, `_dev/test/pipeline/test-user.json-expected.json`, `_dev/test/pipeline/test-device.json-expected.json`, ingest pipelines `default.yml`, `user.yml`, `device.yml`, `routing_rules.yml`, and `data_stream/*/fields/fields.yml`.

### Event action (semantic)

Entity Analytics Okta records **sync lifecycle and change markers**, not per-object Okta System Log audit. Actions describe whether a full sync started/completed or an object was discovered/modified during incremental polling — not who changed an Okta user, device, group, or app, or what security operation occurred.

| Action (normalized label) | Classification | Confidence | Evidence | Per-stream notes |
| --- | --- | --- | --- | --- |
| `started` | administration | high | `sample_event.json`; README full-sync write marker | Full-sync boundary marker; `event.kind: asset`; no inventory payload; `host.name` = Okta tenant domain |
| `completed` | administration | high | Pipeline allows pass-through (`default.yml` L9–12); README describes bounded full sync | Full-sync boundary marker; same pipeline logic as `started`; not present in pipeline test fixtures |
| `user-discovered` | administration | high | README sample user document | Agent-emitted incremental/discovery marker for user objects; **stripped** from pipeline output |
| `user-modified` | administration | high | Input `test-user.json` events 1–2 (`event.action: user-modified`) | Agent-emitted change marker for updated user metadata; **stripped** from pipeline output |
| `device-discovered` | administration | high | README sample device document | Agent-emitted discovery marker for registered devices; **stripped** from pipeline output |
| `device-modified` | administration | high | Input `test-device.json` event 0 (`event.action: device-modified`) | Agent-emitted change marker for updated device metadata; **stripped** from pipeline output |

Inventory asset rows (`entityanalytics_okta.user`, `entityanalytics_okta.device`) have **no per-event action** in fixtures after ingest — only static `event.kind: asset` and `event.type` / `event.category` set by `user.yml`/`device.yml`. There is no meaningful security audit verb (e.g. `user.login`, `policy.updated`, `application.assigned`) in this integration.

### Event action (ECS candidates)

| ECS / vendor field | Mapped to `event.action` today? | Mapping correct? | Recommended `event.action` value (from fixtures) | Enhancement candidate? | Evidence |
| --- | --- | --- | --- | --- | --- |
| Agent `event.action` → retained | partial | yes (for markers) | `started`, `completed` | no | Pass-through on sync markers; `sample_event.json`: `started`; `default.yml` L9–12 |
| Agent `event.action` → removed | no (stripped) | n/a | `user-discovered`, `user-modified`, `device-discovered`, `device-modified` | yes | `default.yml` / `user.yml` / `device.yml` `remove` when action ≠ `started`/`completed`; input in `test-user.json`/`test-device.json`, absent in expected output |
| `event.type` | no | n/a | — | no | Static `['user','info']` (user) or `['info']` (device) — asset classification, not operation verb |
| `event.category` | no | n/a | — | no | Static `['iam']` (user) or `['host']` (device) — category, not action |
| `event.kind` | no | n/a | — | no | Always `asset` — document kind, not action |
| `entityanalytics_okta.user.status` / `entityanalytics_okta.device.status` | no | n/a | — | no | Okta lifecycle status (`ACTIVE`, etc.) — object state, not sync action |

**Step 2b — per-stream check:**

| Stream | `event.action` in fixtures? | Pipeline maps to `event.action`? | Primary action candidate | Confidence | Evidence |
| --- | --- | --- | --- | --- | --- |
| `entityanalytics_okta.entity` | yes (markers only) | partial (pass-through + strip) | Agent `event.action` (`started`/`completed` retained; discovery/change actions removed before routing) | high | `default.yml` L9–12; `sample_event.json`: `started`; routed objects have no action |
| `entityanalytics_okta.user` | no (stripped) | removes non-marker actions | Agent `event.action`: `user-discovered`, `user-modified` (input only) | high | `test-user.json` input vs `test-user.json-expected.json` — inventory rows lack `event.action` |
| `entityanalytics_okta.device` | no (stripped) | removes non-marker actions | Agent `event.action`: `device-discovered`, `device-modified` (input only) | high | `test-device.json` input vs `test-device.json-expected.json` — no `event.action` in output |

### Actor (semantic)

No audit actor exists on any stream. Management API synchronization is performed by Elastic Agent using configured API token, OAuth2, or OIN credentials; the collector identity is not recorded on events. Sync boundary markers (`event.action`: `started`, `completed`) carry only `labels.identity_source` and `host.name` (Okta tenant domain) — no operator. Incremental change actions from the agent (`user-discovered`, `user-modified`, `device-discovered`, `device-modified`) are **removed** by pipeline unless `started`/`completed` (`user.yml`/`device.yml`/`default.yml` L9–12 / L17–20). Inventory rows populate `user.*` or `device.*`/`asset.*` for the **described Okta object**, not the party that triggered ingestion.

| Entity | Classification | Entity type (if general) | Confidence | Evidence | Per-stream notes |
| --- | --- | --- | --- | --- | --- |
| — | — | — | high | No ECS `user.*`, `client.user.*`, `source.*`, or vendor principal fields on any fixture or pipeline step | **All streams** — actor/target audit classification does not apply |

**Note:** For Okta directory-change and authentication audit (who signed in, who modified users/groups/apps, MFA events), use the Okta System Log integration — not this package.

### Actor (ECS candidates)

| ECS / vendor field | Role | Mapped today? | Mapping correct? | Confidence | Evidence |
| --- | --- | --- | --- | --- | --- |
| — | — | no | n/a | high | No actor identity fields in pipelines or fixtures |

`user.*` on user/device records identifies the **inventory subject**, not an audit actor — do not interpret as caller/principal. `host.name` holds the Okta tenant domain (`okta_domain` → `host.name`, `default.yml` L26–28), not an endpoint actor.

### Target (semantic)

Inventory subjects only — not audit targets. Each document describes one Okta object at sync time; there is no separate actor and no layered "acted-upon" semantics.

| Layer | Description | Entity | Classification | Entity type (if general) | Confidence | Evidence | Per-stream notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 2 — Resource / object | Okta user account (inventory subject) | User account | user | — | high | ECS `user.*`, `asset.*` (`asset.type: okta_user`); vendor `entityanalytics_okta.user.*`; fixture: `isaac.brock@example.com` / Okta ID `00ub0oNGTSWTBKOLGLNR` | **`entityanalytics_okta.user`** — routed when `user.id` present (`routing_rules.yml`) |
| 2 — Resource / object | Okta registered device (inventory subject) | Registered endpoint | host | — | high | ECS `device.id`, `device.serial_number`, `os.platform`, `asset.*` (`asset.type: okta_device`); vendor `entityanalytics_okta.device.*`; fixture: `guo4a5u7YAHhjXrMK0g4` / `Example Device name 1` | **`entityanalytics_okta.device`** — routed when `device.id` present |
| 2 — Resource / object | Embedded group membership | Okta group | general | okta-group | high | `entityanalytics_okta.groups[]` with `id`, `profile.name`; rolled into `user.group.id` / `user.group.name` (`user.yml` L228–243) | **user** — enrichment when group lookup enabled; related identity context, not audit target |
| 2 — Resource / object | Embedded role assignment | Okta admin/app role | general | okta-role | high | `entityanalytics_okta.roles[]` with `id`, `label`, `type`, `assignment_type`; rolled into `user.roles` (`user.yml` L244–297); fixture: `Application administrator`, `ORG_ADMIN` | **user** — enrichment when role lookup enabled; privilege context, not audit target |
| 2 — Resource / object | Device-associated users | Linked Okta user | user | — | high | `okta.users[]` → `related.user` appends (`device.yml` L133–176); fixture: `00ub0oNGTSWTBKOLGLNR`, `isaac.brock@example.com` | **device** — associated-user context on device records |
| — | Sync boundary marker | Full-sync start/complete | — | — | high | `event.action`: `started`/`completed`; no entity payload | **`entityanalytics_okta.entity`** — `sample_event.json` |

Layer 1 (platform service) and Layer 3 (content/artifact) do not apply — no invoked API operation or per-action payload; this is periodic Management API inventory, not an auditable operation.

### Target (ECS candidates)

Fields below are **inventory subject identity**, not ECS audit-target mappings. Enhancement to `*.target.*` does not apply.

| ECS / vendor field | Layer | Classification | Mapped today? | Mapping correct? | ECS target bucket | Enhancement candidate? | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `user.id` | 2 | user | yes | partial (inventory subject) | n/a | no | Agent sets `user.id` for routing; pipeline does not copy `okta.id` → `user.id`. Fixture: `user.id: 00u5tvodynDjUCNKn697` vs `entityanalytics_okta.user.id` / `asset.id: 00ub0oNGTSWTBKOLGLNR` |
| `user.name` | 2 | user | yes | yes (inventory subject) | n/a | no | `copy_from: entityanalytics_okta.user.profile.login` (`user.yml` L314–317); `isaac.brock@example.com` |
| `user.email` | 2 | user | yes | yes (inventory subject) | n/a | no | `copy_from: entityanalytics_okta.user.profile.email` (L324–327) |
| `user.full_name` | 2 | user | yes | yes (inventory subject) | n/a | no | `copy_from: entityanalytics_okta.user.profile.display_name` (L430–433); `Isaac Brock` |
| `user.group.id` / `user.group.name` | 2 | general | yes | yes (membership context) | n/a | no | foreach on `entityanalytics_okta.groups` (L228–243); `Everyone` / `OGYzMDMwYjFmODBiNjli` |
| `user.roles` | 2 | general | yes | yes (privilege context) | n/a | no | foreach on `entityanalytics_okta.roles` (L249–264); role IDs and labels |
| `user.account.*` / `user.profile.*` / `user.organization.*` / `user.geo.*` | 2 | user | yes | yes (inventory attributes) | n/a | no | lifecycle dates, status flags, department, manager, address from `okta.profile.*` |
| `asset.id` / `asset.name` / `asset.type` / `asset.status` / `asset.create_date` / `asset.last_updated` / `asset.last_seen` / `asset.vendor` | 2 | user / host | yes | yes (inventory subject) | n/a | no | `asset.id` ← `entityanalytics_okta.user.id` or `entityanalytics_okta.device.id`; `asset.vendor` ← credential provider name |
| `device.id` / `device.serial_number` | 2 | host | yes | yes (inventory subject) | n/a | no | Agent sets `device.id` for routing; `device.serial_number` ← `okta.profile.serialNumber` (`device.yml` L193–196) |
| `os.platform` | 2 | host | yes | yes (inventory attribute) | n/a | no | lowercase from `okta.profile.platform` (L177–180); `windows` |
| `host.name` | — | general | yes | yes (tenant scope) | n/a | no | Okta tenant domain (`trial-xxxxxxx-admin.okta.com`); deployment scope, not inventory subject |
| `related.user` | 2 | user | yes | yes (enrichment bag) | n/a | no | appends Okta user ID, login, email, names, employee number (`user.yml` L51–56, L308–641); device associated users (`device.yml` L133–176) |
| `labels.identity_source` | — | general | yes | yes (deployment scope) | n/a | no | tags originating Okta tenant instance; not an actor or target |
| `entityanalytics_okta.user.*` | 2 | user | yes (vendor) | n/a | n/a | no | profile, credentials, lifecycle timestamps, `_links`, `_embedded` |
| `entityanalytics_okta.device.*` | 2 | host | yes (vendor) | n/a | n/a | no | disk encryption, secure hardware, registration state, `_links`, associated users |
| `entityanalytics_okta.groups[]` | 2 | general | yes (vendor) | n/a | n/a | no | nested group objects with `id`, `profile.name`, `profile.description` |
| `entityanalytics_okta.roles[]` | 2 | general | yes (vendor) | n/a | n/a | no | role assignments with `id`, `label`, `type`, `assignment_type`, `status` |
| `destination.user.*` / `destination.host.*` | — | — | no | n/a | n/a | no | Not present in pipelines; package absent from `destination_identity_hits.csv` |

### Gaps and mapping notes

- **Inventory sync, not audit:** All three data streams (`entity`, `user`, `device`) ship Management API inventory snapshots/deltas. Actor/target audit enhancement does not apply; use the Okta System Log integration for change attribution and authentication audit.
- **No ECS `*.target.*` today:** Aligns with `target_enhancement_packages.csv` (`priority=none`, all signal flags false). `user.*` and `device.*` describe the synced object, not an audit acted-upon entity.
- **`event.action` stripped for inventory rows:** Agent emits `user-discovered`, `user-modified`, `device-discovered`, and `device-modified` on incremental sync events (`test-user.json`, `test-device.json`, README) but `default.yml`/`user.yml`/`device.yml` remove `event.action` unless `started`/`completed`. Only full-sync boundary markers retain action in Elasticsearch output. **Enhancement candidate:** preserve agent discovery/change actions on routed `user`/`device` documents if incremental sync semantics are needed downstream.
- **`event.action` is sync vocabulary, not Okta audit:** Even when preserved (`started`/`completed`), actions describe Entity Analytics sync lifecycle — not Okta System Log events (login, admin policy change, MFA enrollment, app assignment).
- **`user.*` is inventory subject, not actor:** Pipeline maps Okta user account attributes to ECS `user.*` (e.g. `isaac.brock@example.com` in fixtures). Semantically correct for Entity Analytics asset records; must not be interpreted as the API sync operator.
- **`user.id` vs `asset.id` divergence:** Pipeline sets `asset.id` from `okta.id` (`entityanalytics_okta.user.id`) but does not overwrite agent-supplied `user.id` used for routing. Canonical Okta user ID is `entityanalytics_okta.user.id` / `asset.id`; `user.id` may differ in edge cases.
- **No `destination.*` de-facto targets:** Unlike email/auth integrations, no pipeline maps identity to `destination.user.*` or `destination.host.*`.
- **Embedded groups and roles are membership/privilege context:** `entityanalytics_okta.groups[]` and `entityanalytics_okta.roles[]` enrich user records and drive ECS `user.group.*` / `user.roles`; not separate audit targets.
- **Sync markers carry no entity:** `started`/`completed` events (`sample_event.json`) mark full-sync boundaries only; `host.name` identifies tenant, not an endpoint inventory subject.

### Per-stream notes

#### `entityanalytics_okta.entity`

Primary collection stream from the Elastic Agent entity-analytics input. `default.yml` routes API payloads to `user.yml` or `device.yml` based on `user.id` / `device.id` presence; routed documents land on `entityanalytics_okta.user` or `entityanalytics_okta.device` per `routing_rules.yml`. Sync markers (`sample_event.json`: `event.action: started`) have no actor or inventory subject — only `labels.identity_source` and `host.name`. **Action semantics:** only `started`/`completed` survive ingest; discovery/change actions on routed payloads are stripped before routing.

#### `entityanalytics_okta.user`

Routed user account inventory (`routing_rules.yml`: `ctx.user?.id != null`). Maps Okta user attributes to ECS `user.*` and `asset.*` (`asset.type: okta_user`) with rich vendor detail under `entityanalytics_okta.user.*`. Optional group enrichment populates `entityanalytics_okta.groups[]` and ECS `user.group.*`; optional role enrichment populates `entityanalytics_okta.roles[]` and `user.roles`. Example fixture: `Isaac Brock` with `Everyone` group membership and admin role assignments. **Action semantics:** agent sends `user-discovered` or `user-modified` on input; pipeline removes `event.action` — output has no per-object sync action.

#### `entityanalytics_okta.device`

Routed registered device inventory (`routing_rules.yml`: `ctx.device?.id != null`). Maps device attributes to ECS `device.*`, `os.platform`, and `asset.*` (`asset.type: okta_device`). Vendor fields retain disk encryption, secure hardware, registration state, and API links. Associated Okta users populate `related.user`. Example fixture: Windows device `guo4a5u7YAHhjXrMK0g4` with serial `XXDDRFCFRGF3M8MD6D` linked to user `isaac.brock@example.com`. **Action semantics:** agent sends `device-discovered` or `device-modified` on input; pipeline removes `event.action` — output has no per-object sync action.

## Example Event Graph

Examples are drawn from `entityanalytics_okta.entity` (collection stream), `entityanalytics_okta.user`, and `entityanalytics_okta.device` (routed inventory). These streams poll the Okta Management API for user and device objects — they are **identity asset snapshots and sync deltas**, not Okta System Log audit events.

**No per-event Actor → action → Target graph applies.** Elastic Agent performs scheduled API synchronization; the collector/API credential identity is not recorded on events. Fields such as `user.*` and `device.*` describe the **inventory subject** (the Okta object being synchronized), not an audit actor or an acted-upon target. Routed user and device fixtures have no `event.action` after ingest (`test-user.json-expected.json`, `test-device.json-expected.json`). For authentication, admin, and lifecycle change audit (who signed in, who modified a user or app), use the Okta System Log integration.

### Note: sync boundary markers (action only)

The only Elasticsearch output fixture retaining `event.action` is a full-sync start marker on the entity stream — it carries sync lifecycle semantics but no actor entity and no inventory subject payload, so it does not form a complete Actor → action → Target chain.

**Stream:** `entityanalytics_okta.entity` · **Fixture:** `packages/entityanalytics_okta/data_stream/entity/sample_event.json`

```
(no actor) → started → (no target)
```

#### Event action

| Field | Value |
| --- | --- |
| action | started |
| source_field | `event.action` |
| source_value | `started` |

**Field sources:** `action` ← `event.action` (`started`); tenant scope only via `host.name` ← Okta domain (`trial-xxxxxxx-admin.okta.com`); `event.kind: asset`; no `user.*` or `device.*` inventory payload on this document.

Agent input for incremental sync may include `user-discovered`, `user-modified`, `device-discovered`, or `device-modified` (`test-user.json`, `test-device.json`), but `default.yml` / `user.yml` / `device.yml` strip those values from routed output — inventory rows ship as static asset records without a per-object sync action in Elasticsearch.

## ES|QL Entity Extraction

**Package type: agent-backed (Tier A).** Three log data streams from `manifest.yml` route on **`data_stream.dataset`**: `entityanalytics_okta.entity` (collection + sync markers), `entityanalytics_okta.user` (routed user inventory), `entityanalytics_okta.device` (routed device inventory). Fixtures: `sample_event.json`, `test-user.json-expected.json`, `test-device.json-expected.json`. Cross-package queries use unscoped `FROM logs-*` (no `WHERE data_stream.dataset` filter); embed `data_stream.dataset == "entityanalytics_okta.user"` (etc.) in every CASE fallback branch when EVAL is added. This integration performs **Okta Management API entity inventory sync**, not Okta System Log audit. Documents are identity **asset records** (`event.kind: asset`); Pass 3 confirms **no per-event Actor → action → Target graph** on routed inventory rows. ECS `user.*` / `device.*` / `asset.*` describe the **inventory subject**, not an audit principal or acted-upon target. **No `EVAL` / `CASE` blocks are produced** — all three datasets under **Streams excluded**; do not promote inventory `user.*` / `device.*` into audit actor/target columns or `user.target.*` / `host.target.*`. **Pass 4 (CASE syntax + tautology):** ingest populates identity columns from Okta API payloads (`user.yml` / `device.yml` / `default.yml`) with no alternate query-time vendor path — omit columns from ES|QL rather than **4-arg** `CASE(actor_exists|target_exists|action_exists, col, bare_field, null)` (bare field parses as a **condition**, not a fallback) or **4-arg** `CASE(flag, col, col, null)` (identity no-op). Even valid **3-arg** `CASE(user.name IS NOT NULL, user.name, user.full_name)` is omitted: both fields describe the inventory subject (`test-user.json-expected.json`), not audit principal rename, and `actor_exists` true from `user.email` must not gate `user.name` via flag-based preserve.

### Dataset inventory

| data_stream.dataset | Stream role | Actor classification(s) | Target classification(s) | Extraction |
| --- | --- | --- | --- | --- |
| `entityanalytics_okta.entity` | collection + sync markers | — | — | none |
| `entityanalytics_okta.user` | user inventory | — | — | none |
| `entityanalytics_okta.device` | device inventory | — | — | none |

### Field mapping plan

No actor or target destination columns are populated. Inventory sync semantics (Pass 2/3); the Elastic Agent API/OAuth collector identity is not indexed. Query-time `CASE` on `user.id`, `user.name`, `user.email`, `user.full_name`, or `device.id` would conflate Okta directory asset records with audit actor/target identity. Columns below are **ingest-only — omit from ES|QL** (no alternate indexed source for audit extraction).

#### Actor mappings

| Output column | Source field(s) | Condition (dataset + optional) | Confidence | Notes |
| --- | --- | --- | --- | --- |
| — | — | — | — | No audit actor on any stream |
| `user.id` | — | — | high | **ingest-only** — agent sets for routing; pipeline does not copy `okta.id` → `user.id`; canonical Okta ID is `entityanalytics_okta.user.id` / `asset.id` (`user.yml` L41–49); inventory subject, not API operator; **omit from ES\|QL** |
| `user.name` | — | `data_stream.dataset == "entityanalytics_okta.user"` | high | **ingest-only — omit from ES\|QL** — `copy_from: entityanalytics_okta.user.profile.login` (`user.yml` L314–317); forbidden **4-arg** `CASE(actor_exists, user.name, user.full_name, null)` (3rd arg is condition); valid **3-arg** `CASE(user.name IS NOT NULL, user.name, user.full_name)` still omitted (inventory subject, not audit principal) |
| `user.email` | — | — | high | **ingest-only** — `copy_from: entityanalytics_okta.user.profile.email` (`user.yml` L324–327); **omit from ES\|QL** |
| `user.full_name` | — | — | high | **ingest-only** — `copy_from: entityanalytics_okta.user.profile.display_name` (`user.yml` L430–433); no `user.name` rename at ingest; **omit from ES\|QL** |
| `host.name` | — | — | high | **ingest-only** — `okta_domain` → `host.name` (`default.yml` L26–28); Okta tenant deployment scope, not inventory subject; **omit from ES\|QL** |
| `device.id` | — | — | high | **ingest-only** — agent sets for routing; `asset.id` ← `entityanalytics_okta.device.id` (`device.yml` L41–49); **omit from ES\|QL** |
| `device.serial_number` | — | — | high | **ingest-only** — `okta.profile.serialNumber` → `device.serial_number` (`device.yml` L192–196); **omit from ES\|QL** |

#### Target mappings

| Output column | Source field(s) | Condition (dataset + optional) | Confidence | Notes |
| --- | --- | --- | --- | --- |
| — | — | — | — | No audit target; `user.*` / `device.*` are inventory subject only |
| `user.target.*` / `host.target.*` | — | — | high | **omit** — wiring `user.id` → `user.target.id` or `device.id` → `host.target.id` (or same column in `CASE(target_exists, col, col, null)`) duplicates inventory subject; violates Pass 2/3 |

#### Event action mappings

| Output column | Source field(s) | Condition (dataset + optional) | Confidence | Notes |
| --- | --- | --- | --- | --- |
| `event.action` | — | `data_stream.dataset == "entityanalytics_okta.entity"` | high | **ingest-only on markers — omit from ES\|QL** — pass-through `started`/`completed` only (`default.yml` / `user.yml` / `device.yml` L9–12 / L17–20, `sample_event.json`); no fallback when stripped on inventory rows; forbidden **4-arg** `CASE(action_exists, event.action, event.action, null)` (tautology) |
| — | — | — | — | Sync vocabulary only; not Okta System Log audit verbs; `user-discovered` / `user-modified` / `device-discovered` / `device-modified` removed before routed output |

### Detection flags (mandatory — run first)

Not applicable — all streams excluded (entity inventory sync; no defensible actor/target/action fallback without misclassifying asset fields). Do not emit detection flags solely to wrap tautological `CASE` on ingest-populated columns.

### Combined ES|QL — actor fields

Not applicable — all streams excluded (inventory sync). Do not emit `CASE(actor_exists, user.id, user.id, null)` or map inventory `user.*` / `device.*` as audit actor — ingest-only with no alternate source (`user.yml`, `device.yml`).

### Combined ES|QL — event action

Not applicable — all streams excluded. Preserved `event.action` on sync markers (`started`/`completed`) is ingest pass-through only; no indexed agent action field at query time for inventory rows after pipeline strip.

### Combined ES|QL — target fields

Not applicable — all streams excluded (inventory sync). Do not emit `CASE(target_exists, user.id, user.id, null)` or promote inventory `user.id` / `device.id` to `user.target.*` / `host.target.*`.

### Streams excluded

- **`entityanalytics_okta.entity`** — primary Elastic Agent entity-analytics collection stream; `default.yml` routes API payloads to `user.yml` / `device.yml` per `routing_rules.yml`. Sync boundary markers retain `event.action`: `started`/`completed` (`sample_event.json`: `started`) but carry no actor identity and no inventory subject payload — only `labels.identity_source`, `host.name` (Okta tenant domain, e.g. `trial-xxxxxxx-admin.okta.com`), and `event.kind: asset`.
- **`entityanalytics_okta.user`** — Okta user account inventory routed when `user.id` is present (`routing_rules.yml`); ECS `user.*` / `asset.*` (`asset.type: okta_user`; fixture `isaac.brock@example.com` / Okta ID `00ub0oNGTSWTBKOLGLNR` via `entityanalytics_okta.user.id` / `asset.id`) is the synced object, not an audit actor or target. Agent input may include `user-discovered` / `user-modified`; pipeline removes them before output (`test-user.json` vs `test-user.json-expected.json`).
- **`entityanalytics_okta.device`** — Okta registered device inventory routed when `device.id` is present; ECS `device.id`, `device.serial_number`, `os.platform`, and `asset.*` (`asset.type: okta_device`; fixture `guo4a5u7YAHhjXrMK0g4` / `Example Device name 1`) describe the synced endpoint, not audit semantics. Associated users populate `related.user` only. Agent `device-discovered` / `device-modified` is stripped on output (`test-device.json` vs `test-device.json-expected.json`).

### Gaps and limitations

- **Inventory sync, not audit:** For Okta System Log authentication and admin audit (who signed in, who modified users/groups/apps, MFA events), use the Okta System Log integration — not this package.
- **Target-fields audit `none`:** Package absent from `destination_identity_hits.csv`; no ECS `*.target.*` or `destination.*` in pipelines. Wiring inventory `user.id` / `device.id` into `user.target.*` or actor columns at query time would violate Pass 2/3 semantics.
- **`user.*` must not be wired as actor:** `user.yml` maps Okta profile attributes to ECS `user.*` for Entity Analytics asset records — correct for inventory, incorrect for cross-integration audit principal extraction.
- **`user.id` vs `asset.id`:** Pipeline sets `asset.id` from `entityanalytics_okta.user.id` but does not overwrite agent-supplied `user.id` used for routing; do not use divergent IDs as actor fallback without ingest alignment.
- **`event.action` stripped on inventory rows:** Agent emits `user-discovered`, `user-modified`, `device-discovered`, and `device-modified` (`test-user.json`, `test-device.json`, README) but pipelines remove `event.action` unless `started` or `completed` — incremental discovery semantics do not appear in routed `user`/`device` output.
- **Sync markers are not audit events:** Even retained `started`/`completed` actions mark full-sync boundaries only — Pass 3 graph `(no actor) → started → (no target)`; no layered target.
- **Embedded groups and roles are membership/privilege context:** `entityanalytics_okta.groups[]` / `entityanalytics_okta.roles[]` enrich user records (`user.group.*`, `user.roles`); not separate audit targets for ES|QL extraction.
- **Enhancement path:** Preserve agent discovery/change actions on routed documents or ingest Okta System Log before query-time actor/target normalization is meaningful.
- **No tautological CASE (Pass 4 #10):** `user.id`, `user.name`, `user.email`, `user.full_name`, `host.name`, `device.id`, and `device.serial_number` are ingest-only inventory columns; there is no query-time vendor fallback. Emitting **4-arg** `CASE(actor_exists|target_exists, col, col, null)` or mapping inventory `user.id` / `device.id` to `user.target.*` / `host.target.*` would be an identity no-op or misclassify the synced Okta object.
- **Pass 4 CASE syntax:** No fenced `esql` blocks — entity inventory sync, all streams excluded per `esql-entity-mapping.md` linux example. Anti-patterns above document forbidden **4-arg** flag-based preserve and bare-field-as-condition forms only; no `target.user.*` / `target.entity.type`; no detection-flag wrapper `EVAL` solely to host tautological `CASE`. Package kibana assets contain no `EVAL`/`CASE`.
