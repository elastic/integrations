# Sub-agent prompt: Actor and target classification

Use this prompt when dispatching a sub-agent to append audit-log entity analysis to an existing domain document.

## Variables

| Variable | Description | Example |
| --- | --- | --- |
| `{integration}` | Package name under `packages/` | `wiz` |
| `{output_path}` | Path to the existing domain markdown file | `dev/domain/p1/wiz.md` |
| `{repo_root}` | Absolute path to the integrations repo | `/Users/.../integrations` |

## Scope guardrails

Each sub-agent analyzes **`{integration}` only**. Do not broaden scope to "similar" integrations.

**Allowed reads:**

- `packages/{integration}/**`
- `{output_path}` (this integration's domain doc — the only file under `dev/domain/p1/` you may read)
- `dev/target-fields-audit/out/*.csv` (row for `{integration}` only)
- ECS field reference (external)
- Sibling packages **only when** the target package README explicitly references them for comparison (e.g. `packages/aws/data_stream/vpcflow/` for `aws_vpcflow_otel`) — cite sibling **package** paths, not peer domain docs

**Forbidden:**

- Any other `dev/domain/p1/*.md` file — do not read or copy from peer domain docs (e.g. `suricata.md` when working on `aws_vpcflow_otel`)
- Any other `packages/*/` directory unless named in the target package README as a comparison source
- Reusing prose, tables, or classifications from another integration's analysis

Ground every claim in `{integration}` package evidence. Similar domains (network flows, IDS, OTel dashboards) still require independent analysis per integration.

## Package capability (mandatory check)

Read [package-capability.md](package-capability.md) before Step 1.

| Package type | Evidence allowed | Fixture claims |
| --- | --- | --- |
| **Agent-backed** | Tier A (fixtures, pipelines) + Tier B (dashboards if present) | yes |
| **Assets-only** | Tier B (dashboard ES\|QL, filter literals) + Tier C (external templates) only | **no** — mark `unverifiable in package` for pipeline/mapping |
| **Assets-with-sibling** | Tier B + sibling `packages/…/data_stream/` fixtures **only when README names sibling** | sibling fixtures cited with path; not this package's fixtures |

If **assets-only**: do not write Pass 2 as if `sample_event.json` exists. Add an intro sentence under **Expected Audit Log Entities** stating evidence tier. In ECS candidates tables, use **Evidence tier** column (`A` / `B` / `C`) instead of implying fixture proof.

## ECS reference index

Use ECS docs for **field semantics and intended meaning** — not as proof that this integration maps them correctly.

| Resource | URL |
| --- | --- |
| **ECS field reference** (index — start here) | [elastic.co/docs/reference/ecs/ecs-field-reference](https://www.elastic.co/docs/reference/ecs/ecs-field-reference) |
| Generated field CSV (all fields, single file) | [github.com/elastic/ecs/blob/main/generated/csv/fields.csv](https://github.com/elastic/ecs/blob/main/generated/csv/fields.csv) |
| User | [ecs-user](https://www.elastic.co/docs/reference/ecs/ecs-user) |
| Host | [ecs-host](https://www.elastic.co/docs/reference/ecs/ecs-host) |
| Service | [ecs-service](https://www.elastic.co/docs/reference/ecs/ecs-service) |
| Cloud | [ecs-cloud](https://www.elastic.co/docs/reference/ecs/ecs-cloud) |
| Entity | [ecs-entity](https://www.elastic.co/docs/reference/ecs/ecs-entity) |
| Entity Reference | [ecs-entity_reference](https://www.elastic.co/docs/reference/ecs/ecs-entity_reference) |
| Client / Source / Destination | [ecs-client](https://www.elastic.co/docs/reference/ecs/ecs-client) · [ecs-source](https://www.elastic.co/docs/reference/ecs/ecs-source) · [ecs-destination](https://www.elastic.co/docs/reference/ecs/ecs-destination) |
| Event | [ecs-event](https://www.elastic.co/docs/reference/ecs/ecs-event) |
| Related | [ecs-related](https://www.elastic.co/docs/reference/ecs/ecs-related) |
| Gen AI | [ecs-gen_ai](https://www.elastic.co/docs/reference/ecs/ecs-gen_ai) |

When a field's purpose is unclear, look up its field set in the index above (ECS 9.4.0). Prefer Elastic Docs MCP (`search_docs`) or `get_document_by_url` for specific field definitions.

## Key principles

### Vendor namespace vs ECS

Each integration defines **custom fields** under `{integration}.*` (e.g. `wiz.audit.*`, `aws_bedrock.invocation.*`). These often hold the richest actor/target identity from the vendor API. Many are **not mapped to ECS** — they remain vendor-namespaced even after ingest.

Always inventory **both**:
- **ECS fields** present in `sample_event.json` / pipeline output (`user.*`, `host.*`, `*.target.*`, …)
- **Vendor fields** under `{integration}.*` in `fields/fields.yml` and pipeline output

Do not assume that because ECS defines a field, this integration populates it correctly — or at all.

### Verify mapping intent (do not take ECS for granted)

An ECS field appearing in a document does **not** mean the mapping is semantically correct. For every ECS field cited as actor or target evidence, cross-check:

1. **Pipeline source** — Which vendor field was renamed/copied/set into the ECS field? Read the ingest pipeline step.
2. **Semantic fit** — Does the source field actually represent an actor or target per ECS field-set definitions (see index above)?
3. **Fixture proof** — Do `sample_event.json` and `*-expected.json` show the ECS field populated with the expected entity type?
4. **Known mis-mappings** — Flag cases where ECS fields conflate actor and target (e.g. `user.email` parsed from "For user …" text describing the affected user, not the admin actor), or where only `related.user` is populated but not `user.*`.

Record mapping quality in the ECS candidates tables using **Mapping correct?** (`yes` | `partial` | `no` | `n/a`) with a one-line rationale when not `yes`.

### Destination identity as de-facto target

Many integrations map the **target user or host** to `destination.user.*` or `destination.host.*` / `destination.hostname` — **not** to the official ECS target entity fields (`user.target.*`, `host.target.*`).

This is a common real-world pattern even though [ECS Destination](https://www.elastic.co/docs/reference/ecs/ecs-destination) primarily describes the destination side of a **network connection**. Integrations often reuse it for audit semantics:

| Field | Typical audit meaning (when used as target) | Example integrations |
| --- | --- | --- |
| `destination.user.name` / `.email` / `.id` | User acted upon — recipient, local account, login target | `checkpoint_email`, `fortinet_fortigate`, `o365`, `ping_federate` |
| `destination.host.*` / `destination.hostname` | Host/system acted upon — session target, remote endpoint | `beyondtrust_pra`, `claroty_ctd` |
| `destination.ip` / `destination.domain` | May be network peer **or** target service endpoint — context-dependent | firewalls, proxies, IDS |

**Do not ignore these fields** because `*.target.*` is empty. Treat them as **de-facto target candidates** and assess:

1. **Target vs network context** — Is `destination.user.email` the mail recipient (target) or just the far-end of a flow? Read pipeline source + event type.
2. **Official ECS target gap** — If semantically a target but stored under `destination.*`, mark **Enhancement candidate?** yes for `user.target.*` / `host.target.*` migration.
3. **Mapping correct?** — `destination.user.*` populated from vendor "dstuser" / "recipient" → likely intentional de-facto target. Populated from pure flow 5-tuple → network context only (`partial` or `n/a` for audit target).

**Pass 4 ES|QL note:** De-facto `destination.user.*` / `destination.host.*` map to **`user.target.*` / `host.target.*`** in query-time enrichment — never to `target.user.*` (invalid namespace).

Repo-wide evidence: `dev/target-fields-audit/out/destination_identity_hits.csv` (~29 packages use `destination.user` in pipelines). Check if `{integration}` appears there.

### Event action (`event.action`)

Actor and target answer **who** and **what**; `event.action` answers **what happened** — the verb or operation performed. Per [ECS Event](https://www.elastic.co/docs/reference/ecs/ecs-event), `event.action` records the action taken (e.g. `login`, `InvokeModel`, `user-created`).

**Do not assume integrations populate `event.action`.** Many packages leave it empty even when vendor logs contain a clear operation name elsewhere.

For each audit-like or audit-adjacent stream, check fixtures first:

1. **Is `event.action` populated?** — Search `sample_event.json`, `*-expected.json`, and pipeline `set`/`rename` to `event.action`.
2. **If yes** — Trace pipeline source; assess **Mapping correct?** (same rigor as actor/target).
3. **If no** — Propose **action candidates**: vendor or ECS fields that *should* map to `event.action`, with confidence and per-stream notes.

Common candidate sources (integration-dependent):

| Candidate source | Examples |
| --- | --- |
| Vendor operation / action field | `azure.open_ai.operation_name`, `aws_bedrock.invocation.operation`, `wiz.audit.action` |
| HTTP method + path | `http.request.method` + `url.path` (when the API call *is* the action) |
| Admin / audit event type | `event.type`, vendor `action`, `event_type`, `operationName` |
| Cloud audit API name | CloudTrail `eventName`, GCP audit `methodName`, Azure `operationName` |
| Normalized `event.category` + vendor detail | e.g. category `authentication` + vendor login action |

Rules for action candidates:

- Prefer **vendor-native operation names** already in fixtures over inferred labels.
- Distinguish **API operation** (InvokeModel, ListKey) from **security event** (login, policy-update) — both are valid `event.action` values depending on stream.
- Metrics streams (`event.kind: metric`) typically have **no per-event action** — say so explicitly.
- If multiple candidate fields exist per stream, list all with a recommended primary mapping.
- Mark **Enhancement candidate?** yes when a vendor field clearly names the action but is not copied to `event.action`.

Example gap: `azure_openai` — fixtures have `azure.open_ai.operation_name` (`ListKey`, `ChatCompletions_Create`) but **no** `event.action` in samples or pipeline.

## Prompt template

```
Update {repo_root}/{output_path} by APPENDING a new section (do not remove existing content).

Task: For the Elastic integration "{integration}", analyze what actor and target entities appear in audit and audit-adjacent logs, and what **event action** (`event.action`) is recorded or should be recorded. Produce semantic classifications (user | host | service | general) and ECS field mapping candidates grounded in package evidence.

---

## Step 1 — Read sources (mandatory)

Scope: **{integration} only**. Do not read other `dev/domain/p1/*.md` files or other `packages/*/` directories except as allowed in Scope guardrails above.

**First:** classify package type per [package-capability.md](package-capability.md).

1. {repo_root}/{output_path} — existing domain doc from the domain-knowledge pass (this file only)
2. packages/{integration}/ — manifest.yml, docs/README.md
3. **If agent-backed:** packages/{integration}/data_stream/*/sample_event.json, *-expected.json, ingest pipelines, fields.yml
4. **If assets-only:** packages/{integration}/kibana/dashboard/*.json, kibana/search/*.json, _dev/shared/kibana/*.yaml — extract field names and filter literals from ES|QL only; **do not** treat dashboard JSON as event fixtures
5. If present: dev/target-fields-audit/out/*.csv — row for this package
6. ECS field reference — https://www.elastic.co/docs/reference/ecs/ecs-field-reference
7. Sibling package paths **only if** README explicitly references them (assets-with-sibling)
8. Web / external vendor templates only when in-repo evidence is Tier B/C

---

## Step 2 — Field inventory (mandatory before writing)

Scan pipelines, fields.yml, sample_event.json, and test fixtures. Record every hit with the source file that proves it.

### ECS field families

| Family | Fields to look for |
| --- | --- |
| Actor identity | `user.*`, `client.user.*`, `source.ip`, `source.address` |
| Host identity | `host.*`, `device.*`, `source.ip` (when endpoint) |
| Service identity | `service.name`, `service.id`, `service.type`, `cloud.service.name` |
| Cloud resource | `cloud.provider`, `cloud.account.id`, `cloud.region`, `resource.id`, `resource.name`, `resource.type` |
| ECS target fields | `user.target.*`, `host.target.*`, `service.target.*`, `entity.target.*` |
| Destination identity (de-facto target) | `destination.user.*`, `destination.host.*`, `destination.hostname` — often used **instead of** `*.target.*` |
| Network endpoints (context vs target) | `source.*`, `destination.ip`, `destination.domain`, `destination.port` — verify whether peer or audit target |
| Related / enrichment | `related.user`, `related.hosts`, `related.ip`, `gen_ai.*` |
| Event action | `event.action`, `event.type`, `event.category`, `event.outcome`; vendor operation/action/event_type fields |

### Vendor namespace (`{integration}.*`)

| Family | Fields to look for |
| --- | --- |
| All vendor fields | `{integration}.*` in fields.yml — full tree per data stream |
| Actor / principal | vendor paths for user, caller, principal, issuer, admin, identity, session |
| Target / object | vendor paths containing `target`, `resource`, `entity`, `object`, `affected`, `destination` |
| Action / operation | vendor paths for action, operation, event_type, activity, api_method, eventName, methodName |
| Unmapped identity | vendor fields that *should* map to ECS but do not (pipeline keeps them vendor-only) |

For each field found (ECS or vendor), answer before classifying:
- **Actor or target?** — Who initiated the action vs what was acted upon. Do not list cloud scope or invoked-service fields under Actor unless they identify the caller.
- **Mapped today?** — ECS field populated in fixtures (yes/no). Vendor-only counts as no ECS mapping.
- **Mapping correct?** — If mapped to ECS: does the pipeline source field semantically match the ECS field's intended meaning? (yes/partial/no/n/a)
- **ECS target bucket** — If target: which bucket would it map to (`user.target.*`, `host.target.*`, `service.target.*`, `entity.target.*`, or context-only)?
- **De-facto target?** — If under `destination.user.*` / `destination.host.*`: is this the audit target (yes/no/context-only)? Should it migrate to `*.target.*`?
- **Event action?** — Does this field name the operation performed? Could it map to `event.action`?

---

## Step 2b — Event action check (mandatory)

For **each data stream**, answer:

| Stream | `event.action` in fixtures? | Pipeline maps to `event.action`? | Primary action candidate | Confidence | Evidence |
| --- | --- | --- | --- | --- | --- |

- Search all `sample_event.json` and `*-expected.json` for `"event.action"` or `"action"` under `event`.
- Grep ingest pipelines for `event.action` (set, rename, copy_from).
- When `event.action` is **absent**, propose the best vendor field(s) to populate it — cite fixture values (e.g. `operation_name: ListKey`).
- When `event.action` is **present**, trace source and assess mapping quality.
- Metrics / inventory streams: note "no per-event action" if applicable.

---

## Step 3 — Append this section format

## Expected Audit Log Entities

Brief intro covering:
- Which streams are true audit logs vs audit-adjacent (findings, metrics, network telemetry, inventory sync)
- Whether the integration has audit logs at all
- Whether existing ECS `*.target.*` fields are populated (check target-fields-audit if available)
- Whether `event.action` is populated per stream, or which vendor fields are action candidates

### Event action (semantic)

What operation or activity does each stream record?

| Action (normalized label) | Classification | Confidence | Evidence | Per-stream notes |
| --- | --- | --- | --- | --- |

- Use vendor fixture values where possible (e.g. `ListKey`, `ChatCompletions_Create`, `login`)
- Classification describes action *type* if useful: authentication, administration, api_call, data_access, configuration_change, detection, etc.
- If the stream has no meaningful per-event action (metrics, inventory sync), say so in prose

### Event action (ECS candidates)

| ECS / vendor field | Mapped to `event.action` today? | Mapping correct? | Recommended `event.action` value (from fixtures) | Enhancement candidate? | Evidence |
| --- | --- | --- | --- | --- | --- |

- When `event.action` is **missing** from fixtures, this table is the primary output — list vendor candidates and suggested mapping
- Prefer single vendor field per stream as primary candidate; note alternates if ambiguous
- Include pipeline line reference when pipeline maps (or fails to map) the candidate

### Actor (semantic)

For each distinct actor pattern:

| Entity | Classification | Entity type (if general) | Confidence | Evidence | Per-stream notes |
| --- | --- | --- | --- | --- | --- |

- **Classification** must be one of: `user`, `host`, `service`, `general`
- If no actor exists for a stream, say so in prose — do not use "none" or "cloud" as a classification value
- Distinguish security principals from homonyms: chat message role "user", DHCP client (→ host), service account (→ user or service depending on context)

### Actor (ECS candidates)

| ECS / vendor field | Role | Mapped today? | Mapping correct? | Confidence | Evidence |
| --- | --- | --- | --- | --- | --- |

List fields that identify or enrich the actor. Include `{integration}.*` vendor fields — especially those **not** mapped to ECS. When an ECS field is cited, trace it back to the pipeline source and assess whether the mapping is intentional and correct.

### Target (semantic)

Targets are often layered — document all applicable layers, not just the most granular:

| Layer | Description | Entity | Classification | Entity type (if general) | Confidence | Evidence | Per-stream notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 — Platform / cloud service | The cloud API or SaaS product invoked | e.g. Amazon Bedrock, Azure OpenAI | service | — | | | |
| 2 — Resource / object | The specific resource acted upon | e.g. foundation model, user account, VM | varies | | | | |
| 3 — Content / artifact | Payload, message, file, or request instance | e.g. prompt, email, invocation ID | general | ai_content, api_request, … | | | |

- Not every integration has all three layers — omit rows that do not apply
- Layer 1 is commonly missed; always check whether `cloud.service.name` or equivalent identifies the invoked platform service

### Target (ECS candidates)

| ECS / vendor field | Layer | Classification | Mapped today? | Mapping correct? | ECS target bucket | Enhancement candidate? | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |

Rules for this table:
- If the pipeline sets `cloud.service.name`, always evaluate it as a Layer 1 target service candidate
- If the pipeline sets `destination.user.*` or `destination.host.*`, evaluate as a **de-facto target** candidate — cite whether it represents the acted-upon user/host vs network/session context
- Distinguish **context fields** (`cloud.service.name`, `cloud.account.id`, flow `destination.ip`) from **explicit target fields** (`service.target.entity.id`, de-facto `destination.user.*`)
- Mark **Enhancement candidate?** yes when a vendor, `destination.*`, or context field semantically represents a target but is not in `*.target.*` today
- Include all relevant `{integration}.*` paths — mapped or not
- When **Mapping correct?** is `partial` or `no`, explain in Gaps and mapping notes below

### Gaps and mapping notes

Short bullet list covering:
- Vendor `{integration}.*` fields that represent actor/target but lack ECS mapping (best source of truth for enhancement)
- `destination.user.*` / `destination.host.*` used as de-facto targets — note intended entity and whether `*.target.*` migration applies
- ECS fields populated but semantically wrong or ambiguous (cite pipeline step + why)
- Fields where actor and target identity are conflated in the same ECS field
- Alignment or tension with target-fields-audit classification for this package (if CSV row exists)
- **`event.action` gaps** — vendor operation fields present but not mapped; recommended primary candidate per stream

Optional: ### Per-stream notes — short subsections for streams with distinct semantics (include action semantics where relevant).

---

## Classification rules

1. **Semantic vs ECS are separate steps.** First decide what the entity is; then identify which ECS/vendor field represents it.
2. **Vendor namespace first for truth.** `{integration}.*` fields often contain the canonical vendor actor/target identity. ECS fields are the *normalized view* — verify they reflect that identity correctly.
3. **Do not take ECS for granted.** Presence of an ECS field ≠ correct mapping. Always trace pipeline source → ECS destination and compare against ECS field-set definitions in the reference index.
4. **Check de-facto targets under `destination.*`.** Many integrations store target user/host identity in `destination.user.*` or `destination.host.*` rather than `user.target.*` / `host.target.*`. Inventory these explicitly; do not report "no target user field" when `destination.user.email` is populated.
5. **Actor vs target.** Caller/principal/session → actor. Object/resource/content acted upon → target. Cloud tenancy (`cloud.account.id`, `cloud.region`) is scope context, not an actor. The invoked cloud service (`cloud.service.name`) is typically a **target**, not an actor. Flow `destination.ip` may be network peer or target endpoint — verify per event type.
6. **Allowed classifications:** `user`, `host`, `service`, `general` only. Use prose for "no actor/target" cases.
7. **Use `general` sparingly** — prefer user/host/service when they fit with high probability; always specify entity type when general.
8. **Target layering for cloud/SaaS/API integrations.** Expect Layer 1 (platform service) + Layer 2 (resource) at minimum. Example: Bedrock invocation → Layer 1: `cloud.service.name: bedrock`; Layer 2: `gen_ai.request.model.id`.
9. **Ground claims in fixtures.** Cite sample_event.json, *-expected.json, and pipeline YAML. Do not speculate beyond what evidence supports.
10. **Metrics streams.** Dimensions (model ID, guardrail ARN) are aggregation targets, not per-request audit targets. Note absence of caller identity.
11. **Inventory / entity-analytics packages.** These sync asset state, not audit events. State explicitly that actor/target audit semantics do not apply; describe inventory subject fields instead under ECS candidates if useful.
12. **Event action is mandatory.** Always check `event.action` in fixtures and pipelines per stream. Absence is a gap — propose vendor-field candidates rather than leaving action undocumented.
13. **Action vs actor vs target.** `event.action` is the verb (what happened). Actor is who did it. Target is what it was done to. Do not substitute `event.type` or `event.category` for `event.action` without noting the distinction.

---

## Cloud / SaaS integration addendum

Apply when the package sets `cloud.provider`, `cloud.service.name`, `azure.*`, `aws.*`, or `gcp.*`:

- **Invoked service** (what API was called) → usually Layer 1 target → check `cloud.service.name`, `event.action`, `service.name`
- **Resource within service** (model, bucket, function, policy) → Layer 2 → check `resource.*`, vendor IDs, ARNs
- **Caller principal** (who called the API) → actor → check `user.id`, `identity.arn`, `client.user.*`, assumed-role ARNs
- Do not collapse these into a single target row

---

## Anti-patterns (do not do)

- Do not put `cloud.service.name` under Actor unless it identifies the caller
- Do not use "cloud", "account", or "none" as a classification value
- Do not conflate chat/LLM message role "user" with IAM/security principal "user"
- Do not treat Elastic Agent / collector credentials as the event actor
- Do not list only the most granular target and skip the platform service layer
- Do not ignore statically-set pipeline fields (e.g. `set: cloud.service.name: bedrock`) in favor of dynamic fields only
- Do not cite an ECS field as evidence without checking the pipeline step that produced it
- Do not ignore `{integration}.*` vendor fields just because ECS fields exist — the vendor namespace is often more complete or more accurate
- Do not assume `{integration}.*` fields are mapped to ECS — most packages retain significant vendor-only identity data
- Do not report missing target user/host fields without first checking `destination.user.*` and `destination.host.*`
- Do not treat all `destination.*` fields as network peers — in audit/email/auth events they often hold the acted-upon entity
- Do not assume `event.action` is populated — verify fixtures; if missing, document action candidates
- Do not omit action analysis for streams that have vendor `operation`, `action`, or `event_type` fields
- Do not read other integrations' domain docs or packages to "find a similar example" — analyze `{integration}` evidence only
- Do not claim fixture proof for **assets-only** packages — dashboard filter literals are not sample events
- Do not invent `data_stream.dataset` values from manifest when package has no `policy_templates`

---

Return the file path when done.
```

## Example invocation

Integration: `azure_openai`  
Output: `dev/domain/p1/azure_openai.md`

Expected highlights in output:
- **Event action:** `event.action` absent in all fixtures; candidates `azure.open_ai.operation_name` (`ListKey`, `ChatCompletions_Create`) and `properties.operation_id` — enhancement candidate
- Actor: Entra object ID on Audit; API client IP on GatewayLogs → `source.ip`
- Target Layer 1: Cognitive Services / APIM → `azure.resource.provider`; no `cloud.service.name`
- Target Layer 2: model deployment → `properties.model_deployment_name`

Integration: `aws_bedrock`  
Output: `dev/domain/p1/aws_bedrock.md`

Expected highlights:
- **Event action:** `event.action` ← `aws_bedrock.invocation.operation` (`InvokeModel`, `Converse`) on invocation stream
- Actor: IAM user / assumed-role → `user.id` ← `identity.arn`
- Target Layer 1: `cloud.service.name: bedrock`

## Notes for orchestrator

- **Append only** — never overwrite the Product Domain section from the first pass.
- Sub-agents should read **all** data streams, not just streams named "audit".
- **Assets-only** packages (e.g. `corelight`, `aws_vpcflow_otel`): follow [package-capability.md](package-capability.md); Tier B evidence only; never cite dashboard JSON as `sample_event.json`.
- One sub-agent per integration keeps context focused and token use low.
- Sub-agents do not see the full conversation — include all paths, the integration name, and [Scope guardrails](#scope-guardrails) in the prompt.
- Do not suggest peer domain docs as references — e.g. do not tell the `aws_vpcflow_otel` agent to read `suricata.md`.

## Related artifacts

| Artifact | Use |
| --- | --- |
| [ECS field reference](https://www.elastic.co/docs/reference/ecs/ecs-field-reference) | Official field-set definitions and semantics (ECS 9.4.0) |
| `packages/{integration}/data_stream/*/fields/fields.yml` | Vendor `{integration}.*` field tree |
| `packages/{integration}/data_stream/*/fields/ecs.yml` | ECS fields declared for this data stream |
| `dev/target-fields-audit/VENDOR_TARGET_ANALYSIS_PLAN.md` | Actor vs target triage workflow and ECS bucket selection |
| `dev/target-fields-audit/out/target_enhancement_packages.csv` | Prior actor/target heuristic per package |
| `dev/target-fields-audit/out/target_fields_audit.csv` | Already-mapped ECS `*.target.*` fields |
| `dev/target-fields-audit/out/vendor_target_special_cases.csv` | Vendor `*target*` field paths |
| `dev/target-fields-audit/out/destination_identity_hits.csv` | Packages using `destination.user` / `destination.host` in pipelines |
| `dev/target-fields-audit/out/destination_identity_review.md` | Review checklist for destination-as-target vs network context |
