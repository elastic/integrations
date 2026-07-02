# Domain analysis prompts

Reusable sub-agent prompts for building per-integration domain documents under `dev/domain/`. Each integration gets a markdown file describing what the vendor product is, what data the Elastic package collects, and what actor/target entities appear in its logs.

## Workflow overview

Analysis runs in **four sequential passes**. Each pass appends to the same markdown file.

**Before Pass 2–4:** classify the package per [package-capability.md](package-capability.md) — **agent-backed** vs **assets-only** (dashboards/content, no `data_stream/`). Assets-only packages must not use fixture-grounded example workflows.

```
Integration list
       │
       ▼
┌──────────────────────┐
│ Pass 1: Domain       │  one sub-agent per integration
│ knowledge            │  → creates dev/domain/p1/{integration}.md
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Pass 2: Actor /      │  one sub-agent per integration
│ target / action      │  → appends detailed audit entity analysis
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Pass 3: Event graph  │  one sub-agent per integration
│ example              │  → appends simple Actor → action → Target examples
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Pass 4: ES|QL entity │  one sub-agent per integration
│ extraction           │  → appends EVAL/CASE actor + target mappings
└──────────┬───────────┘
           │
           ▼
   dev/domain/p1/{integration}.md
```

## Prompts

| File | Pass | Action |
| --- | ---: | --- |
| [`domain-knowledge.md`](domain-knowledge.md) | 1 | **Create** the domain doc — product domain + data streams |
| [`actor-target-classification.md`](actor-target-classification.md) | 2 | **Append** audit entity analysis — actor / action / target + ECS mapping |
| [`event-graph-example.md`](event-graph-example.md) | 3 | **Append** 1–3 simple Actor → event.action → Target examples |
| [`esql-entity-mapping.md`](esql-entity-mapping.md) | 4 | **Append** ES\|QL `EVAL`/`CASE` actor + target field extraction |
| [`package-capability.md`](package-capability.md) | — | **Reference** — detect agent-backed vs assets-only; evidence tiers A/B/C |

## How to run

### 1. Choose integrations

Provide a list of package names (must exist under `packages/`). Example batch: `wiz`, `aws_bedrock`, `fortinet_fortigate`.

### 2. Set variables

Substitute these in the prompt template before dispatching each sub-agent:

| Variable | Value |
| --- | --- |
| `{integration}` | Package name, e.g. `wiz` |
| `{output_path}` | `dev/domain/p1/{integration}.md` |
| `{repo_root}` | Absolute path to this repo |

### 3. Dispatch sub-agents

- **One sub-agent per integration** — keeps context focused and limits token use.
- **Run Pass 1 for all integrations first**, then Pass 2, then Pass 3, then Pass 4.
- **Batch in parallel** (e.g. 8–10 at a time) when orchestrating from a parent agent.
- Sub-agents do **not** see the parent conversation — the prompt must be self-contained with all paths and instructions.
- Include the [scope guardrails](#scope-guardrails) in every prompt — sub-agents must not read other integrations' domain docs or packages unless explicitly allowed by the target package README.

### 4. Review output

Each completed file under `dev/domain/p1/` should contain:

```markdown
# {integration}

## Product Domain
…

## Package capability
agent-backed | assets-only | assets-with-sibling

## Data Collected (brief)
…

## Expected Audit Log Entities
…
### Event action (semantic)
…
### Event action (ECS candidates)
…
### Actor (semantic)
…
### Actor (ECS candidates)
…
### Target (semantic)
…
### Target (ECS candidates)
…
### Gaps and mapping notes
…

## Example Event Graph
…
### Example 1: …
…

## ES|QL Entity Extraction
…
### Dataset inventory
…
### Combined ES|QL — actor fields
…
### Combined ES|QL — target fields
…
```

Pass 1 produces only the first two sections. Pass 2 appends audit entity analysis. Pass 3 appends readable graph examples. Pass 4 appends ES|QL extraction mappings.

Pass 2 analyzes three pillars:

| Pillar | Question | Key ECS field |
| --- | --- | --- |
| **Event action** | What happened? | `event.action` |
| **Actor** | Who initiated it? | `user.*`, `source.*`, vendor principal fields |
| **Target** | What was acted upon? | `*.target.*`, `destination.user.*`, `cloud.service.name`, vendor resource fields |

If `event.action` is missing from fixtures (common — e.g. `azure_openai`), sub-agents must propose vendor-field **action candidates** rather than skipping action analysis.

### Pass 3 — event graph example

| Source | Purpose |
| --- | --- |
| `dev/domain/p1/{integration}.md` | Domain + Pass 2 context (optional) |
| `packages/{integration}/data_stream/*/sample_event.json` | Primary example source |
| `packages/{integration}/data_stream/*/_dev/test/pipeline/*-expected.json` | Additional representative events |

Pass 3 produces **1–3 simple examples** with this entity shape:

| Node | Fields |
| --- | --- |
| Actor / Target | `id`, `name` (optional), `type`, `sub_type` (optional), `geo` (optional), `ip` (optional) |
| Event action | `action`; if not in `event.action`, cite `source_field` + `source_value` |

**Quality gate (mandatory):** Before finishing each example, apply the **common-sense graph test** — read the one-liner aloud. If it sounds wrong or tautological (e.g. “user logs in to themselves”), fix the target before moving on. See [`event-graph-example.md`](event-graph-example.md) Step 3 and Rule 4.

See [`event-graph-example.md`](event-graph-example.md) for the full template.

### Pass 4 — ES|QL entity extraction

| Source | Purpose |
| --- | --- |
| `dev/domain/p1/{integration}.md` | Pass 2 field inventory + Pass 3 target routing |
| `packages/{integration}/manifest.yml` | `data_stream.dataset` values per stream |
| `packages/{integration}/data_stream/*/sample_event.json` | Query-time field paths |
| `packages/{integration}/data_stream/*/_dev/test/pipeline/*-expected.json` | Golden documents |
| [ES\|QL EVAL](https://www.elastic.co/docs/reference/query-languages/esql/commands/eval) · [CASE](https://www.elastic.co/docs/reference/query-languages/esql/functions-operators/conditional-functions-and-expressions/case) | Syntax reference |

Pass 4 produces **dataset-routed `CASE` mappings** into standard actor/target ECS columns:

| Side | user | host | service | general |
| --- | --- | --- | --- | --- |
| **Actor** | `user.id`, `user.name`, `user.domain`, `user.email` | `host.id`, `host.ip`, `host.name` | `service.id`, `service.name`, `service.type`, `service.version` | `entity.id`, `entity.name`, `entity.type`, `entity.sub_type` |
| **Target** | `user.target.*` | `host.target.*` | `service.target.*` | `entity.target.*` |

Primary router: `data_stream.dataset == "{integration}.{stream}"`. Apply Pass 3 semantics when auth events have self-referential vendor `entity` fields.

**Pass 4 rules (v2):**

- **Unscoped queries** — full pipeline fragments use `FROM logs-*` with **no** `WHERE data_stream.dataset`; every `CASE` fallback branch embeds `data_stream.dataset == "…"` (or `event.dataset` for assets-only).
- **Preserve existing** — column-level `CASE(<col> IS NOT NULL, <col>, …)`; define `actor_exists` / `target_exists` / `action_exists` as query helpers only (not first `CASE` branches on mapped columns).
- **Boolean casts** — wrap boolean-typed fields in `TO_BOOLEAN()` in conditions (e.g. `TO_BOOLEAN(citrix.cef_format) == true`); do not compare raw fields to `true`/`false` when mapping may be `keyword`.
- **Target namespace** — only `user.target.*`, `host.target.*`, `service.target.*`, `entity.target.*` (never `target.user.*` or `target.entity.type`).

See [`esql-entity-mapping.md`](esql-entity-mapping.md) for the full template.

## Scope guardrails

Each sub-agent is scoped to **one integration only**: `{integration}`. Parent orchestrators must include these rules in every dispatched prompt.

### Allowed reads

| Source | Scope |
| --- | --- |
| `packages/{integration}/**` | Primary evidence — manifest, docs, data streams, pipelines, fixtures, dashboards |
| `{output_path}` | This integration's domain doc only (`dev/domain/p1/{integration}.md`) |
| `dev/target-fields-audit/out/*.csv` | Repo-wide audit scans — use the row for `{integration}` only |
| ECS field reference | External Elastic docs for field semantics |
| Web search | This **vendor product** only, when package docs are thin |

### Forbidden reads

- **Other integration domain docs** — do not read `dev/domain/p1/*.md` except `{output_path}`. Never use a peer doc (e.g. `suricata.md`, `snort.md`) as a template or reference.
- **Other integration packages** under `packages/` — except `{integration}` itself and **explicit sibling comparisons** named in the target package's README (e.g. classic `packages/aws/data_stream/vpcflow/` when analyzing `aws_vpcflow_otel`). When a sibling package is allowed, cite evidence from that **package path only** — not from another integration's domain doc.
- **Copying analysis across integrations** — do not reuse prose, table rows, or classifications from another integration's output, even when domains seem similar (network flows, IDS, OTel dashboard packages).

### Why

Similar integrations share entity patterns (5-tuple actors, no `user.*`, missing `event.action`) but differ in streams, vendor fields, and action semantics. Cross-reading domain docs causes template bleed and subtle factual errors.

## What sub-agents read

### Pass 1 — domain knowledge

| Source | Purpose |
| --- | --- |
| `packages/{integration}/manifest.yml` | Data streams, collection inputs |
| `packages/{integration}/docs/README.md` | Product description |
| Web search (optional) | Fill gaps when package docs are thin |

### Pass 2 — actor / target classification

| Source | Purpose |
| --- | --- |
| `dev/domain/p1/{integration}.md` | Domain context from Pass 1 |
| `packages/{integration}/data_stream/*/sample_event.json` | Indexed document shape |
| `packages/{integration}/data_stream/*/_dev/test/pipeline/*-expected.json` | Pipeline golden fixtures |
| `packages/{integration}/data_stream/*/elasticsearch/ingest_pipeline/*.yml` | Field mappings |
| `packages/{integration}/data_stream/*/fields/fields.yml` | Vendor `{integration}.*` field tree |
| `packages/{integration}/data_stream/*/fields/ecs.yml` | Declared ECS fields |
| [ECS field reference](https://www.elastic.co/docs/reference/ecs/ecs-field-reference) | Official field-set semantics |
| `dev/target-fields-audit/out/*.csv` | Prior audit scans (optional) |

## Key principles (Pass 2)

Pass 2 encodes lessons from integration review. Sub-agents must:

1. **Inventory vendor and ECS fields separately** — `{integration}.*` often holds identity data that never maps to ECS.
2. **Verify mapping intent** — an ECS field in a document does not prove correct actor/target semantics; trace pipeline source → ECS destination.
3. **Check event action per stream** — verify `event.action` in fixtures; if absent, propose vendor operation fields as candidates (e.g. `azure.open_ai.operation_name`).
4. **Use layered targets** — platform service (`cloud.service.name`) → resource (`resource.*`, model ID) → content (prompt, email body).
5. **Check de-facto targets** — many packages store target user/host under `destination.user.*` / `destination.host.*` instead of `user.target.*` / `host.target.*`.
6. **Separate semantic classification from ECS mapping** — classify entities as user | host | service | general first, then map to fields.

See [`actor-target-classification.md`](actor-target-classification.md) for the full rule set, ECS index, and anti-patterns.

## Output tiers

Documents are organized by priority tier under `dev/domain/`:

| Tier | Path | Status |
| --- | --- | --- |
| P1 | `dev/domain/p1/` | First batch — 47 integrations analyzed |

Add new tiers (`p2/`, etc.) as needed; point `{output_path}` at the appropriate folder.

## Relationship to target-fields-audit

Domain docs complement the deterministic scans in `dev/target-fields-audit/`:

| Domain docs (this workflow) | Target-fields-audit |
| --- | --- |
| Qualitative — product context, semantic actor/target | Quantitative — grep/pipeline scans across all packages |
| Per-integration narrative + field evidence | CSV inventories (`target_fields_audit.csv`, `destination_identity_hits.csv`, …) |
| Enhancement candidates with rationale | Stakeholder matrix and tier classification |

Pass 2 sub-agents should cross-reference target-fields-audit CSVs when available and note alignment or gaps.

## Re-running a pass

| Scenario | Action |
| --- | --- |
| New integration | Run Pass 1, then Pass 2 |
| Pass 1 doc exists, need actor/target | Run Pass 2 only (appends section) |
| Improved Pass 2 prompt | Delete `## Expected Audit Log Entities` section from the doc, re-run Pass 2 |
| Pass 2 adds event action section | Re-run Pass 2 only (v3 prompt adds `### Event action` subsections) |
| Pass 3 graph only | Delete `## Example Event Graph` section, re-run Pass 3 |
| Pass 3 quality sweep | Re-run Pass 3 with **review/fix** mode — keep Pass 1/2; apply common-sense graph test to each example (see `event-graph-example.md` Step 3) |
| Pass 4 ES\|QL only | Delete `## ES\|QL Entity Extraction` section, re-run Pass 4 |
| Full refresh | Delete the doc, re-run all passes |

## Example orchestrator command

From a parent agent, for one integration:

```
Task (generalPurpose):
  Use prompt from dev/domain/prompts/domain-knowledge.md
  integration=aws_bedrock
  output_path=dev/domain/p1/aws_bedrock.md
  repo_root=/Users/peledkfir/Documents/elastic/integrations
```

Then, after Pass 1 completes:

```
Task (generalPurpose):
  Use prompt from dev/domain/prompts/actor-target-classification.md
  integration=aws_bedrock
  output_path=dev/domain/p1/aws_bedrock.md
  repo_root=/Users/peledkfir/Documents/elastic/integrations
```

Then, after Pass 2 completes:

```
Task (generalPurpose):
  Use prompt from dev/domain/prompts/event-graph-example.md
  integration=citrix_waf
  output_path=dev/domain/p1/citrix_waf.md
  repo_root=/Users/peledkfir/Documents/elastic/integrations
```

Then, after Pass 3 completes:

```
Task (generalPurpose):
  Use prompt from dev/domain/prompts/esql-entity-mapping.md
  integration=slack
  output_path=dev/domain/p1/slack.md
  repo_root=/Users/peledkfir/Documents/elastic/integrations
```
