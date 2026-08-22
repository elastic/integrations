# entityanalytics_ad

## Product Domain (Active Directory entity analytics)

Microsoft Active Directory (AD) is the dominant on-premises directory service for Windows enterprise environments, storing authoritative identity and access data for users, groups, computers, and service accounts across a domain forest. AD objects are exposed via LDAP and include rich metadata: distinguished names, SIDs, GUIDs, group memberships, account control flags, password and logon timestamps, delegation settings, and organizational attributes. Security teams rely on this directory state to understand who exists in the environment, which accounts are privileged or misconfigured, and how identity posture changes over time.

Entity Analytics in Elastic Security consumes identity inventory—not authentication logs—to build a living graph of users and devices for risk scoring, user behavior analytics (UBA), and context enrichment during investigations. The Active Directory Entity Analytics integration connects Elastic Agent to an AD domain controller over LDAP, periodically synchronizing user and computer account objects into Elasticsearch. Unlike event-driven log sources, this integration treats identities as assets: it performs full synchronizations on a configurable interval (default 24 hours) and ships incremental updates for changed, added, or removed objects between syncs (default every 15 minutes).

Core AD concepts reflected in collected data include user and computer accounts (sAMAccountName, UPN, objectSid, objectGUID), group membership (memberOf), User Account Control (UAC) flags and derived security posture (enabled, locked, password-not-required, delegation trusted, privileged group membership), account lifecycle timestamps (whenCreated, whenChanged, pwdLastSet, lastLogon), and optional group object attributes. Ingest pipelines normalize raw LDAP attributes into ECS-aligned user, asset, and entityanalytics_ad fields, decode UAC bitmasks, and route documents to separate user and device data streams. The integration supports configurable base DN, attribute selection, SSL/TLS, paging, and an identity source label for multi-directory deployments.

## Data Collected (brief)

- **Entity sync** (`entityanalytics_ad.entity`): Primary collection stream from the Elastic Agent entity-analytics input; LDAP lookups against Active Directory return user and/or device objects depending on dataset selection (`users`, `devices`, or `all`). Events include full-sync markers and incremental change notifications (`event.action` such as `user-discovered`, `started`).
- **Users** (`entityanalytics_ad.user`): Active Directory user account inventory routed from the entity stream. Includes distinguished name, sAMAccountName, UPN, mail, objectSid/GUID, group memberships, account status (enabled, locked, expired), UAC-derived flags (delegation, preauth, password policy), logon metadata, and ECS `user.*` profile and account fields.
- **Devices** (`entityanalytics_ad.device`): Active Directory computer account inventory routed from the entity stream. Includes computer account attributes (cn, sAMAccountName, distinguishedName, memberOf, servicePrincipalName), account control and security posture flags, and ECS asset mapping (`asset.type`: `activedirectory_device`).
- **Groups** (embedded): Group object attributes (`entityanalytics_ad.groups.*`) such as cn, distinguishedName, member, memberOf, objectSid/GUID, and group type—optionally with member lists preserved via configuration.
- **Identity context**: `labels.identity_source` tags the originating directory; `asset.*` fields classify entities; IAM-oriented `event.category` and `event.kind: asset` support Entity Analytics workflows in Elastic Security.

## Expected Audit Log Entities

This integration performs **Active Directory entity inventory sync over LDAP**, not administrative or security audit logging. Elastic Agent polls domain controllers on a schedule and ships snapshots and deltas of user and computer account objects; it does **not** ingest Windows Security Event Log, Entra ID audit, or other AD change-audit streams. Every document is an identity asset record (`event.kind: asset`); **actor/target audit semantics do not apply**. Fields below describe **inventory subjects** (the AD object being synchronized), not an initiating principal or an acted-upon audit target. No ECS `user.target.*`, `host.target.*`, `service.target.*`, or `entity.target.*` fields are populated; the package does not appear in `destination_identity_hits.csv` (no `destination.user.*` / `destination.host.*`). Target-fields audit classified this package as **`none`** (`dev/target-fields-audit/out/target_enhancement_packages.csv`).

**`event.action` is partially populated.** Sync boundary markers retain agent-supplied `started` and `completed` (`sample_event.json`, `test-user.json-expected.json` events 0 and last). Inventory rows arrive from the agent with `user-discovered` or `device-discovered` (`test-user.json`, `test-device.json`, README sample) but `default.yml` **removes** `event.action` unless the value is `started` or `completed` (L9–12) — incremental sync semantics are not preserved in routed `user`/`device` output. This is inventory sync action vocabulary, not AD security audit verbs (create/modify/delete attribution).

Evidence: `packages/entityanalytics_ad/data_stream/entity/sample_event.json`, `_dev/test/pipeline/test-user.json-expected.json`, `_dev/test/pipeline/test-device.json-expected.json`, ingest pipelines `default.yml`, `user.yml`, `device.yml`, `entity.yml`, `marker.yml`, and `data_stream/*/fields/fields.yml`.

### Event action (semantic)

Entity Analytics AD records **sync lifecycle and discovery markers**, not per-object AD change audit. Actions describe whether a full sync started/completed or an object was discovered during incremental polling — not who modified an AD object or what security operation occurred.

| Action (normalized label) | Classification | Confidence | Evidence | Per-stream notes |
| --- | --- | --- | --- | --- |
| `started` | administration | high | `sample_event.json`; `test-user.json-expected.json` event 0; input `test-user.json` event 0 | Full-sync boundary marker; `marker.yml` sets `event.kind: asset`, `event.category: [iam]`, `event.type: [info]`; no inventory payload |
| `completed` | administration | high | `test-user.json-expected.json` last event; input `test-user.json` last event | Full-sync boundary marker; same pipeline as `started` |
| `user-discovered` | administration | high | Input `test-user.json` events 1–3; README sample user document | Agent-emitted incremental/discovery marker for user objects; **stripped** from pipeline output (`default.yml` L9–12) |
| `device-discovered` | administration | high | Input `test-device.json` event 0 | Agent-emitted discovery marker for computer accounts; **stripped** from pipeline output |

Inventory asset rows (`entityanalytics_ad.user`, `entityanalytics_ad.device`) have **no per-event action** in fixtures after ingest — only static `event.kind: asset` and `event.type: [user, info]` or `[info]` set by `user.yml`/`device.yml`. There is no meaningful security audit verb (e.g. `user-created`, `password-changed`) in this integration.

### Event action (ECS candidates)

| ECS / vendor field | Mapped to `event.action` today? | Mapping correct? | Recommended `event.action` value (from fixtures) | Enhancement candidate? | Evidence |
| --- | --- | --- | --- | --- | --- |
| Agent `event.action` → retained | partial | yes (for markers) | `started`, `completed` | no | Pass-through on sync markers; `sample_event.json`, `test-user.json-expected.json` |
| Agent `event.action` → removed | no (stripped) | n/a | `user-discovered`, `device-discovered` | yes | `default.yml` L9–12 `remove` when action ≠ `started`/`completed`; input in `test-user.json`/`test-device.json`, absent in expected output |
| `event.type` | no | n/a | — | no | Static `['user','info']` (user) or `['info']` (device/marker) — asset classification, not operation verb |
| `event.category` | no | n/a | — | no | Static `['iam']` on all streams — category, not action |
| `event.kind` | no | n/a | — | no | Always `asset` — document kind, not action |

**Step 2b — per-stream check:**

| Stream | `event.action` in fixtures? | Pipeline maps to `event.action`? | Primary action candidate | Confidence | Evidence |
| --- | --- | --- | --- | --- | --- |
| `entityanalytics_ad.entity` | yes (markers only) | partial (pass-through + strip) | Agent `event.action` (`started`/`completed` retained; `user-discovered`/`device-discovered` removed) | high | `default.yml` L9–12; `sample_event.json`: `started`; unrouted objects have no action |
| `entityanalytics_ad.user` | no (stripped) | removes non-marker actions | Agent `event.action`: `user-discovered` (input only) | high | `test-user.json` input vs `test-user.json-expected.json` — inventory rows lack `event.action` |
| `entityanalytics_ad.device` | no (stripped) | removes non-marker actions | Agent `event.action`: `device-discovered` (input only) | high | `test-device.json` input vs `test-device.json-expected.json` — no `event.action` in output |

### Actor (semantic)

No audit actor exists on any stream. LDAP synchronization is performed by Elastic Agent using configured bind credentials; the collector identity is not recorded on events. Sync boundary markers (`event.action`: `started`, `completed`) carry only `labels.identity_source` and `asset.category: entity` — no operator. Inventory rows populate `user.*` or `host.*`/`device.*` for the **described AD object**, not the party that triggered ingestion.

| Entity | Classification | Entity type (if general) | Confidence | Evidence | Per-stream notes |
| --- | --- | --- | --- | --- | --- |
| — | — | — | high | No ECS `user.*`, `client.user.*`, `source.*`, or vendor principal fields on any fixture or pipeline step | **All streams** — actor/target audit classification does not apply |

**Note:** For AD directory-change audit (who created/modified/deleted objects, logon events, Kerberos tickets), use Windows event log or dedicated AD audit integrations — not this package.

### Actor (ECS candidates)

| ECS / vendor field | Role | Mapped today? | Mapping correct? | Confidence | Evidence |
| --- | --- | --- | --- | --- | --- |
| — | — | no | n/a | high | No actor identity fields in pipelines or fixtures |

`user.*` on user/device records identifies the **inventory subject**, not an audit actor — do not interpret as caller/principal.

### Target (semantic)

Inventory subjects only — not audit targets. Each document describes one AD object at sync time; there is no separate actor and no layered "acted-upon" semantics.

| Layer | Description | Entity | Classification | Entity type (if general) | Confidence | Evidence | Per-stream notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 2 — Resource / object | AD user account (inventory subject) | User account | user | — | high | ECS `user.*`, `asset.*` (`asset.type: activedirectory_user`); vendor `entityanalytics_ad.user.*`; fixture: `Administrator` / SID `S-1-5-21-372676048-1189045421-4047760665-500` | **`entityanalytics_ad.user`** — routed when `user.id` present (`routing_rules.yml`) |
| 2 — Resource / object | AD computer account (inventory subject) | Computer / endpoint | host | — | high | ECS `host.*`, `device.id`, `asset.*` (`asset.type: activedirectory_device`); vendor `entityanalytics_ad.device.*`; fixture: `test12009.org.test.local` / SID `S-1-5-21-1133191089-1850170202-1535859923-274531` | **`entityanalytics_ad.device`** — routed when `device.id` present |
| 2 — Resource / object | Unrouted LDAP directory object | Generic AD entity | general | directory-object | moderate | `entityanalytics_ad.entity.*`, `asset.type: activedirectory_entity` (`entity.yml`); used when `user.id` and `device.id` both absent | **`entityanalytics_ad.entity`** — fallback pipeline |
| 2 — Resource / object | Embedded group membership | AD security/distribution group | general | ad-group | high | `entityanalytics_ad.groups[]` with `distinguished_name`, `object_sid`, `name`, optional `member`; rolled into `user.group.*` via painless script (`user.yml`/`device.yml` L201–251) | **user/device** — enrichment when group lookup enabled; related identity context, not audit target |
| — | Sync boundary marker | Full-sync start/complete | — | — | high | `event.action`: `started`/`completed`; `marker.yml`; no entity payload | **`entityanalytics_ad.entity`** — `sample_event.json`, `test-user.json-expected.json` event 0 |

Layer 1 (platform service) and Layer 3 (content/artifact) do not apply — no invoked API or per-action payload; this is periodic LDAP inventory, not an auditable operation.

### Target (ECS candidates)

Fields below are **inventory subject identity**, not ECS audit-target mappings. Enhancement to `*.target.*` does not apply.

| ECS / vendor field | Layer | Classification | Mapped today? | Mapping correct? | ECS target bucket | Enhancement candidate? | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `user.id` | 2 | user | yes | yes (inventory subject) | n/a | no | `copy_from: activedirectory.user.object_sid` (`user.yml` L144–146); SID in fixtures |
| `user.name` | 2 | user | yes | yes (inventory subject) | n/a | no | `copy_from: activedirectory.user.sam_account_name` (L119–122); `Administrator`, `Guest` |
| `user.email` | 2 | user | yes | yes (inventory subject) | n/a | no | `copy_from: activedirectory.user.mail` (L123–127); `admin@testserver.local` |
| `user.domain` | 2 | user | yes | yes (inventory subject) | n/a | no | gsub on `distinguished_name` (L128–140); `testserver.local` |
| `user.group.id` / `user.group.name` | 2 | general | yes | yes (membership context) | n/a | no | painless group script (L201–251); privileged-group SID check sets `privileged_group_member` |
| `user.account.password_change_date` | 2 | user | yes | yes (inventory attribute) | n/a | no | `date` from `pwd_last_set` (L101–113) |
| `asset.id` / `asset.name` / `asset.type` / `asset.create_date` / `asset.last_updated` | 2 | user / host | yes | yes (inventory subject) | n/a | no | `asset.id` ← `object_sid`; lifecycle dates from `when_created`/`when_changed` |
| `host.name` / `host.hostname` / `host.domain` / `host.os.*` | 2 | host | yes | yes (inventory subject) | n/a | no | `device.yml` L240–264; `test12009.org.test.local`, `Windows 11 Enterprise` |
| `device.id` | 2 | host | yes | yes (inventory subject) | n/a | no | `copy_from: activedirectory.device.object_sid` (L126–128) |
| `related.user` | 2 | user | yes | yes (enrichment bag) | n/a | no | appends sAMAccountName, DN, GUID, mail, UPN (`user.yml` L258–287) |
| `related.hosts` | 2 | host | yes | yes (enrichment bag) | n/a | no | appends `host.name`, DN, GUID (`device.yml` L266–289) |
| `labels.identity_source` | — | general | yes | yes (deployment scope) | n/a | no | tags originating directory instance; not an actor or target |
| `entityanalytics_ad.user.*` | 2 | user | yes (vendor) | n/a | n/a | no | UPN, UAC flags, `member_of`, `privileged_group_member`, logon timestamps, delegation flags |
| `entityanalytics_ad.device.*` | 2 | host | yes (vendor) | n/a | n/a | no | `dns_host_name`, `service_principal_name`, `operating_system`, `member_of`, UAC-derived flags |
| `entityanalytics_ad.groups[]` | 2 | general | yes (vendor) | n/a | n/a | no | nested group objects with `object_sid`, `distinguished_name`, optional `member` |
| `entityanalytics_ad.entity.*` | 2 | general | yes (vendor) | n/a | n/a | no | unrouted LDAP attributes (`entity.yml`) |
| `destination.user.*` / `destination.host.*` | — | — | no | n/a | n/a | no | Not present in pipelines; package absent from `destination_identity_hits.csv` |

### Gaps and mapping notes

- **Inventory sync, not audit:** All three data streams (`entity`, `user`, `device`) ship LDAP inventory snapshots/deltas. Actor/target audit enhancement does not apply; use complementary Windows Security / AD audit integrations for change attribution.
- **No ECS `*.target.*` today:** Aligns with `target_enhancement_packages.csv` (`priority=none`, all signal flags false). `user.*` and `host.*` describe the synced object, not an audit acted-upon entity.
- **`event.action` stripped for inventory rows:** Agent emits `user-discovered` and `device-discovered` on incremental sync events (`test-user.json`, `test-device.json`, README) but `default.yml` removes `event.action` unless `started`/`completed`. Only full-sync boundary markers retain action in Elasticsearch output. **Enhancement candidate:** preserve agent discovery actions on routed `user`/`device` documents if incremental sync semantics are needed downstream.
- **`event.action` is sync vocabulary, not AD audit:** Even when preserved (`started`/`completed`), actions describe Entity Analytics sync lifecycle — not AD object create/modify/delete or security events.
- **`user.*` is inventory subject, not actor:** Pipeline maps AD user account attributes to ECS `user.*` (e.g. `Administrator` in fixtures). Semantically correct for Entity Analytics asset records; must not be interpreted as the LDAP sync operator.
- **Computer accounts use both `host.*` and `user.name`:** `device.yml` sets `user.name` from `sam_account_name` (e.g. `TEST12009$`) alongside `host.*` — computer account naming convention, not a human actor.
- **No `destination.*` de-facto targets:** Unlike email/auth integrations, no pipeline maps identity to `destination.user.*` or `destination.host.*`.
- **Embedded groups are membership context:** `entityanalytics_ad.groups[]` enriches user/device records with group metadata and drives `user.group.*` / `privileged_group_member`; not separate audit targets.
- **Sync markers carry no entity:** `started`/`completed` events (`marker.yml`, `default.yml` L9–12) mark full-sync boundaries only; no inventory subject payload beyond `labels.identity_source`.

### Per-stream notes

#### `entityanalytics_ad.entity`

Primary collection stream from the Elastic Agent entity-analytics input. `default.yml` routes LDAP payloads to `user.yml`, `device.yml`, or `entity.yml` based on `user.id` / `device.id`; unrouted objects and sync markers stay on this dataset. Sync markers (`sample_event.json`: `event.action: started`) have no actor or inventory subject — only `labels.identity_source` and `asset.category: entity`. **Action semantics:** only `started`/`completed` survive ingest; discovery actions on routed payloads are stripped before routing.

#### `entityanalytics_ad.user`

Routed user account inventory (`routing_rules.yml`: `ctx.user?.id != null`). Maps AD user attributes to ECS `user.*` and `asset.*` with rich vendor detail under `entityanalytics_ad.user.*`. Optional group enrichment populates `entityanalytics_ad.groups[]` and ECS `user.group.*`. Example fixture: built-in `Administrator` with Domain/Enterprise/Schema Admins membership and `privileged_group_member: true`. **Action semantics:** agent sends `user-discovered` on input; pipeline removes `event.action` — output has no per-object sync action.

#### `entityanalytics_ad.device`

Routed computer account inventory (`routing_rules.yml`: `ctx.device?.id != null`). Maps computer attributes to ECS `host.*`, `device.id`, and `asset.*` (`asset.type: activedirectory_device`). Vendor fields retain SPNs, OS version, UAC flags, and group memberships. Example fixture: `TEST12009` Windows 11 endpoint with GPOD group memberships. **Action semantics:** agent sends `device-discovered` on input; pipeline removes `event.action` — output has no per-object sync action.

## Example Event Graph

This integration performs **Active Directory entity inventory sync over LDAP**, not security audit logging. Documents are identity **asset records** (`event.kind: asset`) from scheduled Entity Analytics polling — not discrete auditable operations with an initiating principal and an acted-upon target. **No per-event Actor → action → Target graph applies** to routed inventory rows on `entityanalytics_ad.user` or `entityanalytics_ad.device` (fixtures: `test-user.json-expected.json` events 1–3, `test-device.json-expected.json` event 0). Each row describes a single AD object at sync time (`user.*` / `host.*` as inventory subject); the LDAP sync operator (Elastic Agent bind identity) is not recorded on events.

The only events with `event.action` preserved in pipeline output are full-sync **boundary markers** on `entityanalytics_ad.entity` (`started`, `completed`). These mark sync lifecycle boundaries and carry `labels.identity_source` plus `asset.category: entity`, but no actor identity and no inventory subject payload — they are administration markers, not Actor → action → Target audit chains.

Agent input may include `user-discovered` / `device-discovered` on incremental sync events (`test-user.json`, `test-device.json`), but `default.yml` strips `event.action` unless the value is `started` or `completed`, so discovery semantics do not appear in routed `user`/`device` output.

**Inventory subject (not an audit graph):** fixture `test-user.json-expected.json` event 1 describes AD user `Administrator` (`user.id`: `S-1-5-21-372676048-1189045421-4047760665-500`, `user.name`: `Administrator`, `user.email`: `admin@testserver.local`) as a synchronized asset — there is no separate actor or target layer. For AD change attribution (who created/modified/deleted objects), use Windows Security Event Log or dedicated AD audit integrations.

## ES|QL Entity Extraction

**Package type: agent-backed (Tier A).** Three log data streams from `manifest.yml` route on **`data_stream.dataset`**: `entityanalytics_ad.entity` (collection + sync markers), `entityanalytics_ad.user` (routed user inventory), `entityanalytics_ad.device` (routed computer inventory). Fixtures: `sample_event.json`, `test-user.json-expected.json`, `test-device.json-expected.json`. Cross-package queries use unscoped `FROM logs-*` (no `WHERE data_stream.dataset` filter); embed `data_stream.dataset == "entityanalytics_ad.user"` (etc.) in every CASE fallback branch when EVAL is added. This integration performs **LDAP entity inventory sync**, not AD security audit logging. Documents are identity **asset records** (`event.kind: asset`); Pass 3 confirms **no per-event Actor → action → Target graph** on routed inventory rows. ECS `user.*` / `host.*` describe the **inventory subject**, not an audit principal or acted-upon target. Package does not use `destination.*` identity fields (`destination_identity_hits.csv` absence). **No preserve-first `EVAL` blocks are produced** — document all streams under **Streams excluded** rather than promoting inventory fields to `user.target.*` / `host.target.*` or treating `user.id` as an audit actor. **Pass 4 tautology cleanup (§10):** ingest-populated `user.id`, `user.name`, `user.email`, `user.domain`, `host.name`, and `device.id` have no alternate query-time source (LDAP attributes renamed at ingest under `activedirectory.*` / `entityanalytics_ad.*` only) — omit from actor/target/action `EVAL`; do not emit `CASE(actor_exists, col, …, col, null)`, `CASE(<col> IS NOT NULL, <col>, <col>)`, `CASE(action_exists, event.action, …, event.action, null)`, or `CASE(target_exists, user.target.id, user.id, null)` / `host.target.name` ← `host.name` — misclassifies synced AD objects as audit targets.

### Dataset inventory

| data_stream.dataset | Stream role | Actor classification(s) | Target classification(s) | Extraction |
| --- | --- | --- | --- | --- |
| `entityanalytics_ad.entity` | collection + sync markers | — | — | none |
| `entityanalytics_ad.user` | user inventory | — | — | none |
| `entityanalytics_ad.device` | computer inventory | — | — | none |

### Field mapping plan

No actor or target destination columns are populated. Inventory sync semantics (Pass 2/3); the LDAP sync operator (Elastic Agent bind identity) is not indexed. Query-time `CASE` on `user.id`, `user.name`, `host.name`, or `device.id` would conflate directory asset records with audit actor/target identity. Columns below are **ingest-only — omit from ES|QL** (no alternate indexed source for audit extraction; fallback would repeat the same column per §10).

#### Actor mappings

| Output column | Source field(s) | Condition (dataset + optional) | Confidence | Notes |
| --- | --- | --- | --- | --- |
| — | — | — | — | No audit actor on any stream |
| `user.id` | `activedirectory.user.object_sid` → `user.id` | `data_stream.dataset == "entityanalytics_ad.user"` | high | **ingest-only — no ES\|QL** — `user.yml` L144–146; fixture SID `S-1-5-21-372676048-1189045421-4047760665-500`; inventory subject, not LDAP operator; omit — `CASE(actor_exists, user.id, …, user.id, null)` is identity no-op |
| `user.name` | `activedirectory.user.sam_account_name` → `user.name` | `data_stream.dataset == "entityanalytics_ad.user"` | high | **ingest-only — no ES\|QL** — `user.yml` L119–122; omit — `CASE(user.name IS NOT NULL, user.name, user.name)` or 4-arg `CASE(actor_exists, user.name, user.name, null)` (3rd arg is a **condition**, not fallback) |
| `user.email` | `activedirectory.user.mail` → `user.email` | `data_stream.dataset == "entityanalytics_ad.user"` | high | **ingest-only — no ES\|QL** — `user.yml` L123–127; omit — no flat query-time vendor path distinct from output |
| `user.domain` | gsub on `distinguished_name` → `user.domain` | `data_stream.dataset == "entityanalytics_ad.user"` | high | **ingest-only — no ES\|QL** — `user.yml` L128–140; omit — `CASE(actor_exists, user.domain, user.domain, null)` |
| `host.name` / `host.hostname` | `device.yml` L240–264 | `data_stream.dataset == "entityanalytics_ad.device"` | high | **ingest-only — no ES\|QL** — computer inventory subject (e.g. `test12009.org.test.local`); not collection scope; omit from actor `EVAL` |
| `device.id` | `activedirectory.device.object_sid` → `device.id` | `data_stream.dataset == "entityanalytics_ad.device"` | high | **ingest-only — no ES\|QL** — `device.yml` L126–128; omit — `CASE(actor_exists, device.id, device.id, null)` |
| `user.name` (device stream) | `sam_account_name` → `user.name` | `data_stream.dataset == "entityanalytics_ad.device"` | high | **ingest-only — no ES\|QL** — `device.yml` sets `user.name` for computer SAM (e.g. `TEST12009$`); not human audit actor; omit — do not wire as `user.name` fallback on user stream |

#### Target mappings

| Output column | Source field(s) | Condition (dataset + optional) | Confidence | Notes |
| --- | --- | --- | --- | --- |
| — | — | — | — | No audit target; `user.*` / `host.*` are inventory subject only |
| `user.target.id` | — | `data_stream.dataset IN ("entityanalytics_ad.user", "entityanalytics_ad.device")` | high | **omit** — `user.id` is inventory subject; `CASE(target_exists, user.target.id, user.id, null)` mislabels synced account as audit target |
| `host.target.name` | — | `data_stream.dataset == "entityanalytics_ad.device"` | high | **omit** — `host.name` is synced computer identity; `CASE(target_exists, host.target.name, host.name, null)` duplicates subject |
| `user.target.*` / `host.target.*` / `service.target.*` | — | all datasets | high | **omit** — no ECS `*.target.*` at ingest; promotion from inventory columns violates Pass 2/3 |

#### Event action mappings

| Output column | Source field(s) | Condition (dataset + optional) | Confidence | Notes |
| --- | --- | --- | --- | --- |
| `event.action` | agent `event.action` (markers) | `data_stream.dataset == "entityanalytics_ad.entity"` | high | **ingest-only on markers — no ES\|QL** — `default.yml` L9–12 pass-through `started`/`completed` only (`sample_event.json`); omit — `CASE(action_exists, event.action, event.action, null)` or agent-field fallback after strip is identity no-op on inventory rows |
| — | — | — | — | Sync vocabulary only; not AD audit verbs; `user-discovered` / `device-discovered` removed before routed output (`test-user.json`, `test-device.json`) |

**ES|QL `CASE` arity:** Arguments are **(condition, value)** pairs. **4** args → two pairs (3rd arg is a **boolean condition**, not a fallback) — e.g. `CASE(user.name IS NOT NULL, user.name, user.name, null)` parses as “else if `user.name` is truthy, return `null`”, not “else null”. **5** args with dataset routing still tautologizes when fallback repeats the output column — e.g. `CASE(user.id IS NOT NULL, user.id, data_stream.dataset == "entityanalytics_ad.user", user.id, null)`. For inventory-only integrations, omit `EVAL` entirely rather than wrapping ingest-populated columns.

### Detection flags (mandatory — run first)

Not applicable — all streams excluded (entity inventory sync; no defensible preserve-first fallback without misclassifying asset fields). Do not emit detection flags solely to wrap tautological `CASE` on ingest-populated `user.*`, `host.*`, or marker `event.action`.

### Combined ES|QL — actor fields

Not applicable — all streams excluded (inventory sync). Do not emit `CASE(actor_exists, user.id, user.id, null)`, `CASE(actor_exists, user.name, user.name, null)`, `CASE(actor_exists, host.name, host.name, null)`, `CASE(actor_exists, device.id, device.id, null)`, or `CASE(user.id IS NOT NULL, user.id, data_stream.dataset == "entityanalytics_ad.user", user.id, null)` — ingest-only with no alternate source (`user.yml`, `device.yml`).

### Combined ES|QL — event action

Not applicable — all streams excluded. Marker `event.action` (`started`/`completed`) is ingest pass-through only (`default.yml` L9–12). Do not emit `CASE(action_exists, event.action, event.action, null)` or `CASE(action_exists, event.action, data_stream.dataset == "entityanalytics_ad.entity", event.action, null)` — no query-time agent action on routed `user`/`device` rows after strip; do not substitute sync vocabulary for AD audit verbs.

### Combined ES|QL — target fields

Not applicable — all streams excluded (inventory sync). Do not emit `CASE(target_exists, user.target.id, user.id, null)`, `CASE(target_exists, host.target.name, host.name, null)`, `CASE(target_exists, user.target.name, user.name, null)` (device-stream `user.name` is computer SAM), or promote `entityanalytics_ad.user.*` / `entityanalytics_ad.device.*` to `*.target.*`.

### Streams excluded

- **`entityanalytics_ad.entity`** — primary Elastic Agent entity-analytics collection stream; `default.yml` routes LDAP payloads to user/device pipelines. Sync boundary markers retain `event.action`: `started`/`completed` (`sample_event.json`, `test-user.json-expected.json` event 0) but carry no actor identity and no inventory subject payload — only `labels.identity_source` and `asset.category: entity`.
- **`entityanalytics_ad.user`** — AD user account inventory routed when `user.id` is present (`routing_rules.yml`); ECS `user.*` / `asset.*` (e.g. `Administrator`, SID `S-1-5-21-372676048-1189045421-4047760665-500` in fixtures) is the synced object, not an audit actor or target. Agent input may include `user-discovered`; pipeline removes it before output.
- **`entityanalytics_ad.device`** — AD computer account inventory routed when `device.id` is present; ECS `host.*`, `device.id`, and `asset.*` describe the synced endpoint (e.g. `TEST12009$` / `test12009.org.test.local`). `device.yml` also sets `user.name` from SAM account — computer naming convention, not a human audit actor. Agent `device-discovered` is stripped on output.

### Gaps and limitations

- **Inventory sync, not audit:** For AD change attribution (who created/modified/deleted objects, logon events), use Windows Security Event Log or dedicated AD audit integrations — not this package.
- **Target-fields audit `none`:** Package absent from `destination_identity_hits.csv`; no ECS `*.target.*` or `destination.*` in pipelines. Wiring inventory `user.id` / `host.name` into `user.target.*` or actor columns at query time would violate Pass 2/3 semantics.
- **`user.*` must not be wired as actor:** `user.yml` maps AD user attributes to ECS `user.*` for Entity Analytics asset records — correct for inventory, incorrect for cross-integration audit principal extraction.
- **`event.action` stripped on inventory rows:** Agent emits `user-discovered` / `device-discovered` (`test-user.json`, `test-device.json`) but `default.yml` removes `event.action` unless `started` or `completed` — incremental discovery semantics do not appear in routed `user`/`device` output.
- **Sync markers are not audit events:** Even retained `started`/`completed` actions mark full-sync boundaries only — no actor, no layered target.
- **Embedded groups are membership context:** `entityanalytics_ad.groups[]` enriches user/device records; not separate audit targets for ES|QL extraction.
- **Enhancement path:** Preserve agent discovery actions on routed documents or ingest AD audit streams before query-time actor/target normalization is meaningful.
- **Pass 4 tautology cleanup (§10):** `user.id`, `user.name`, `user.email`, `user.domain`, `host.name`, and `device.id` omitted from all `EVAL` blocks — ingest-only with no distinct query-time fallback; `entityanalytics_ad.*` vendor paths stay enrichment context only (do not wire as actor/target fallbacks). No **4-arg** `CASE(col, col, null)` — third argument is a condition, not default.
