# Sub-agent prompt: ES|QL entity extraction mapping

Use this prompt when dispatching a sub-agent to append **ES|QL `EVAL` / `CASE` mappings** that normalize actor and target identity fields across an integration's data streams.

Pass 2 inventories which fields exist and what they mean. Pass 3 shows coherent Actor → action → Target examples. **Pass 4 turns that into query-time extraction** so a single ES|QL pipeline can populate standard ECS entity columns from heterogeneous integration documents.

## Variables

| Variable | Description | Example |
| --- | --- | --- |
| `{integration}` | Package name under `packages/` | `slack` |
| `{output_path}` | Path to the existing domain markdown file | `dev/domain/p1/slack.md` |
| `{repo_root}` | Absolute path to the integrations repo | `/Users/.../integrations` |

## Scope guardrails

Each sub-agent analyzes **`{integration}` only**.

**Allowed reads:** `packages/{integration}/**`, `{output_path}` (only this file under `dev/domain/p1/`), sibling packages only when named in the target package README.

**Forbidden:** other `dev/domain/p1/*.md` files, other `packages/*/` directories (unless README allows), copying ESQL from peer integrations.

Ground every source field in `{integration}` fixtures, pipelines, or Pass 2/3 evidence for this integration.

## Package capability (mandatory check)

Read [package-capability.md](package-capability.md) before Step 1.

| Package type | Pass 4 behavior |
| --- | --- |
| **Agent-backed** | Full section: `data_stream.dataset` from manifest + Tier A fixture fields |
| **Assets-only** | Router on `event.dataset` / index pattern per **dashboard ES|QL** (Tier B); intro states **no package fixtures**; confidence capped at medium/low; optional reduced section |
| **Assets-with-sibling** | May cite sibling package fixture field paths when README allows; label **sibling evidence** |

**Assets-only:** do not claim `data_stream.dataset` values from this integration's manifest. Do not present `CASE` mappings as package-verified when only dashboard field references exist.

## ES|QL reference

| Resource | URL |
| --- | --- |
| **EVAL command** | [elastic.co/docs/reference/query-languages/esql/commands/eval](https://www.elastic.co/docs/reference/query-languages/esql/commands/eval) |
| **CASE function** | [elastic.co/docs/reference/query-languages/esql/functions-operators/conditional-functions-and-expressions/case](https://www.elastic.co/docs/reference/query-languages/esql/functions-operators/conditional-functions-and-expressions/case) |
| **ECS field reference** | [elastic.co/docs/reference/ecs/ecs-field-reference](https://www.elastic.co/docs/reference/ecs/ecs-field-reference) |

Syntax reminders:

- `EVAL` appends or replaces columns: `| EVAL col = expression`
- `CASE(condition1, value1, condition2, value2, …, elseValue)` — **pairs** of boolean **condition** + return value; first true condition wins ([CASE docs](https://www.elastic.co/docs/reference/query-languages/esql/functions-operators/conditional-functions-and-expressions/case))
- **Odd** argument count → last argument is **default** (`elseValue`) when no condition matches
- **Even** argument count → no default; result is `null` when nothing matches
- **Simple if/else (3 args):** `CASE(user.name IS NOT NULL, user.name, user.full_name)` — preserve `user.name`, else `user.full_name`
- **Wrong (4 args):** `CASE(user.name IS NOT NULL, user.name, user.full_name, null)` — parses as two pairs: `(user.full_name)` is a **condition**, `null` is its value, **not** “else default null”
- **Preserve + one fallback (5 args):** `CASE(user.id IS NOT NULL, user.id, dataset == “x”, vendor.id, null)` — condition, value, condition, value, else
- Combine conditions with `AND` / `OR`: `data_stream.dataset == “slack.audit” AND event.action == “user_login”`
- Use `IS NOT NULL` / `!= null` when guarding empty vendor fields
- Quote string literals: `”slack.audit”`, `”user_login”`
- **Type safety:** `host.id`, `user.id`, `entity.id`, and similar identity columns are `keyword`. Assigning an `ip`-typed field (e.g. `source.ip`, `destination.ip`) requires `TO_STRING()`: `TO_STRING(source.ip)`. Assigning a numeric field requires `TO_STRING()` as well. `mac`, `domain`, and most vendor string fields are already `keyword` and need no conversion.
- **Boolean conditions:** Fields documented or intended as `boolean` may be indexed as `keyword` (runtime mapping, ingest quirks). **Always wrap boolean fields in `TO_BOOLEAN()`** in `CASE` conditions — e.g. `TO_BOOLEAN(citrix.cef_format) == true`, `TO_BOOLEAN(servicenow.event.applied.value) == true`, `(field IS NULL OR TO_BOOLEAN(field) == false)` — never compare the raw field to `true`/`false` literals. This stays correct if the mapping is fixed later.
- **Field names starting with a digit:** Any field whose name (or any dot-separated segment) starts with a digit is not a legal bare identifier in ES|QL. Wrap the **entire** dotted path in backticks: `` `cisco_meraki.8021x_eap_success.vap` ``. Check vendor field trees for such names before writing CASE expressions.

## Array and multi-value field constraints (mandatory)

ES|QL **flattens arrays of objects** at index time. Each sub-field becomes an independent multi-value field; the positional relationship between sibling fields within the same array element is **lost and the order of values is not guaranteed**.

### What is NOT supported in ES|QL

| Pattern | Why it fails | What to do instead |
| --- | --- | --- |
| `field[0]` / `field[1]` | Array index syntax is not valid ES|QL | Use `MV_FIRST(field)` only when ordering doesn't matter (e.g. a field that is always single-valued in practice); otherwise document as **ingest-only** |
| `field[].subfield` | Array-of-objects sub-field notation is not valid | Use `field.subfield` — ES|QL already sees it as a multi-value field after flattening |
| `MV_FILTER(fieldA, fieldB == “value”)` | `MV_FILTER` takes a single field + a **string/regex literal**, not a cross-field boolean condition | Cannot correlate sibling fields from the same array element at query time → **ingest-only** |
| `MV_FIRST(MV_FILTER(fieldA, fieldB == “x”))` | Same as above — the inner `MV_FILTER` call is invalid | **ingest-only** |

### Decision rule

For each vendor field that comes from an array of objects, make one of two calls:

1. **Use the full multi-value field** — when ALL values are semantically equivalent for the output column (e.g. every IP in a multi-value `source.ip` field is a valid actor IP). Use the field directly; `MV_FIRST()` is acceptable only when the field is practically always single-valued.

2. **Document as ingest-only** — when only a SPECIFIC element is relevant (e.g. the participant whose `role == “offender”`) and using all values would be misleading or incorrect. Write a note in **Gaps and limitations**: `{field} — cannot extract specific element at query time; array-of-objects requires ingest-time pipeline handling.`

Do **not** emit `MV_FILTER` with a cross-field condition or `field[n]` indexing. Both are invalid and will cause the query to fail.

## Output ECS columns (mandatory set)

Produce **`EVAL` expressions that populate these destination columns** when applicable. Omit columns with no defensible source for this integration — do not emit empty `CASE()` branches for unsupported fields.

### Actor columns (by semantic classification)

| Classification | Destination columns |
| --- | --- |
| **user** | `user.id`, `user.name`, `user.domain`, `user.email` |
| **host** | `host.id`, `host.ip`, `host.name` |
| **service** | `service.id`, `service.name`, `service.type`, `service.version` |
| **general** (none of the above) | `entity.id`, `entity.name`, `entity.type`, `entity.sub_type` |

### Target columns (by semantic classification)

Target identity lives under the **entity’s `.target.*` namespace** — the target field set is a suffix on the entity type, not a `target.` prefix.

| Classification | Destination columns (correct) |
| --- | --- |
| **user** | `user.target.id`, `user.target.name`, `user.target.domain`, `user.target.email` |
| **host** | `host.target.id`, `host.target.ip`, `host.target.name` |
| **service** | `service.target.id`, `service.target.name`, `service.target.type`, `service.target.version` |
| **general** | `entity.target.id`, `entity.target.name`, `entity.target.type`, `entity.target.sub_type` |

**Forbidden target column names (never emit):**

| Wrong | Correct |
| --- | --- |
| `target.user.*`, `target.host.*`, `target.service.*`, `target.entity.*` | `user.target.*`, `host.target.*`, `service.target.*`, `entity.target.*` |
| `target.entity.type` (helper misnamed as ECS) | `entity.target.type` if classifying target; or omit |
| `actor.entity.type` as actor output | `entity.type` / `entity.sub_type` for actor-side general only |

**Naming note:** Many integrations index `user.full_name` instead of `user.name`. The **output column is always `user.name`** (and `user.target.name` for targets); the `CASE` source may be `user.full_name`, a vendor name field, or a literal. Document the source in the mapping table.

**Domain note:** When `user.domain` / `user.target.domain` is not indexed, derive from email when possible (document the expression or mark **gap — not extractable**).

## Routing key

Primary router: **`data_stream.dataset`**

- Elastic integrations use `{package}.{stream}` (e.g. `slack.audit`, `wiz.audit`, `aws_bedrock.invocation`).
- Prefer **exact dataset equality** per stream: `data_stream.dataset == "slack.audit"`.
- Use `STARTS_WITH(data_stream.dataset, "{integration}.")` only when one mapping applies to all streams of this package and fixtures confirm shared field layout.
- List every dataset covered in `manifest.yml` / Pass 1 **Data Collected**; mark streams with no actor/target extraction (metrics, inventory sync).

Secondary routers (when one dataset has mixed entity types):

- Vendor discriminators: e.g. `slack.audit.entity.entity_type`, `event.action`, `event.category`
- Pass 3 event-graph semantics (e.g. login → service target, not self-referential `entity`)
- Pass 2 per-stream notes

## Mapping principles

1. **Do not override existing values (mandatory).** Pass 4 is **fill-gaps-only** enrichment. If the document already has actor, target, or action identity, **keep it**. Only apply heuristic / vendor / integration-specific extraction when detection flags are false.
2. **Detection flags first.** Emit a single upfront `| EVAL` that sets booleans `actor_exists`, `target_exists`, `action_exists`. Mapped columns use valid `CASE` arity (see Syntax reminders): e.g. `CASE(col IS NOT NULL, col, vendor_field)` (3 args) or `CASE(col IS NOT NULL, col, dataset == "…", vendor_field, null)` (5 args) — not `CASE(flag, col, vendor_field, null)` (4 args — vendor field becomes a condition).
3. **Vendor fallback when empty.** When ECS fields are empty but vendor fields hold identity (e.g. `slack.audit.entity.id` for target user), use the vendor path only in the **fallback** branch — never replace a non-null existing value.
4. **De-facto targets.** When Pass 2 documents `destination.user.*` / `destination.host.*` as target identity, map to `user.target.*` / `host.target.*` in the **fallback** branch only.
5. **Do not conflate actor and target.** Actor columns come from principal/caller fields; target columns from entity/resource/object fields. When vendor `entity` mirrors `actor` on auth events (Slack login), **do not** map entity to `user.target.*` — use Pass 3 target semantics (often `service.target.*` or a literal) in fallback only.
6. **Classification-first when mixed.** For datasets with multiple target types (user vs file vs service), nest `CASE` with discriminators in the **fallback** branch — do not add misnamed columns like `target.entity.type`.
7. **Fixture-grounded sources only.** Every non-literal fallback source field must appear in fixtures or Pass 2 evidence.
8. **Literals for semantic targets.** Use string literals only in fallback branches when Pass 3 marks **semantic — not indexed**.
9. **No per-event graph → no extraction block.** Metrics, inventory, entity-analytics sync streams: document under **Streams excluded** instead of forcing `CASE`.
10. **No tautological CASE (mandatory).** A fallback branch must use a **different** field than the output column. Forbidden patterns:
    - `CASE(actor_exists, user.id, user.id, null)` — when `user.id` is empty, reading `user.id` again does nothing.
    - `CASE(actor_exists, user.id, data_stream.dataset == "…", user.id, null)` — same column in preserve and fallback.
    - `CASE(flag, col, condition, col, null)` for any `col` — identity no-op.
    **When ingest always populates a column** and the vendor source is renamed away at index time (no query-time vendor path), **omit that column from the actor/target `EVAL` block** and note **ingest-only — no ES|QL** in the mapping table. Only emit `CASE` when a real alternate source exists (vendor field, different ECS field like `user.full_name` → `user.name`, or literal).
    **Column-level preserve for renames:** When output is `user.name` but identity lives in `user.full_name`, use **3-arg** `CASE(user.name IS NOT NULL, user.name, user.full_name)` or **5-arg** with a boolean middle condition — never 4-arg with a bare field as the 3rd argument (ES|QL treats it as a condition, not a value). Do not use `CASE(actor_exists, user.name, …)` if `actor_exists` can be true from `user.full_name` while `user.name` is still empty.

## Prompt template

```
Update {repo_root}/{output_path}:

1. KEEP all existing sections unchanged.
2. REMOVE any existing `## ES|QL Entity Extraction` section (if present).
3. APPEND a new `## ES|QL Entity Extraction` section as specified below.

Task: For integration "{integration}", produce ES|QL `EVAL` / `CASE` mappings that populate standard actor and target ECS columns from indexed fields, routed primarily by `data_stream.dataset`.

---

## Step 1 — Read sources

Scope: **{integration} only**.

1. {repo_root}/{output_path} — Pass 2 (`Expected Audit Log Entities`) and Pass 3 (`Example Event Graph`)
2. packages/{integration}/manifest.yml — data stream names → expected `data_stream.dataset` values
3. packages/{integration}/data_stream/*/sample_event.json and *-expected.json — field paths that exist at query time
4. packages/{integration}/data_stream/*/elasticsearch/ingest_pipeline/*.yml — when vendor → ECS rename is unclear
5. packages/{integration}/data_stream/*/fields/fields.yml — vendor field tree

Build a dataset inventory before writing ES|QL.

**Assets-only:** if no `data_stream/` in package, inventory uses `event.dataset` (or index pattern) from dashboard ES|QL — mark **Tier B — not verified by package fixture**.

---

## Step 2 — Append this section format

## ES|QL Entity Extraction

One intro paragraph: package type (agent-backed vs assets-only), which dataset router applies (`data_stream.dataset` vs `event.dataset`), streams covered, and streams excluded.

**Assets-only intro must include:** "Field paths inferred from bundled dashboard ES|QL only; this package defines no ingest pipelines or test fixtures in-repo."

### Dataset inventory

| data_stream.dataset | Stream role | Actor classification(s) | Target classification(s) | Extraction |
| --- | --- | --- | --- | --- |
| `{integration}.…` | audit / network / … | user, host, … | user, service, … | full / partial / none |

### Field mapping plan

Per **actor** and **target**, a row for each destination column you will populate:

#### Actor mappings

| Output column | Source field(s) | Condition (dataset + optional) | Confidence | Notes |
| --- | --- | --- | --- | --- |
| `user.id` | e.g. `user.id` | `data_stream.dataset == "…"` | high | pass-through / vendor fallback |
| `user.name` | e.g. `user.full_name` | … | … | … |
| … | … | … | … | … |

#### Target mappings

| Output column | Source field(s) | Condition (dataset + optional) | Confidence | Notes |
| --- | --- | --- | --- | --- |
| `user.target.id` | … | … | … | … |
| `service.target.name` | … | … | … | semantic literal on login |
| … | … | … | … | … |

Rules for this table:
- **Condition** column uses ES|QL boolean expressions (not prose)
- **Confidence**: high (fixture + pipeline), medium (pipeline only), low (heuristic / Pass 3 semantic)
- Mark **preserve existing**, **vendor fallback**, **semantic literal**, **de-facto destination.***

### Detection flags (mandatory — run first)

One fenced `esql` block **before** actor/target/action mappings. These are **query-time helpers**, not ECS fields:

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

Tune `actor_exists` / `target_exists` if this integration only uses a subset (e.g. network-only: drop `user.*` from `actor_exists`). Document the chosen predicate in the mapping plan.

**Semantics:** When `actor_exists` is true, output actor columns must equal their **current** values (no overwrite). When false, apply integration heuristic. Same for `target_exists` / `action_exists`.

### Optional classification helpers (when needed)

Only when fallback branches need type discrimination. Use **correct ECS names**:

- Actor-side general: `entity.type`, `entity.sub_type` (not `actor.entity.type`)
- Target-side general: `entity.target.type`, `entity.target.sub_type` (not `target.entity.type`)

Set these in the **fallback** branch only, e.g. `entity.target.type = CASE(entity.target.type IS NOT NULL, entity.target.type, data_stream.dataset == "…" AND …, "domain", null)`.

Skip when stream-level routing in `CASE` is enough.

### Combined ES|QL — actor fields

Second fenced `esql` block. **Every assignment** uses column-level preserve-first `CASE`:

```esql
| EVAL
  user.id = CASE(
    user.id IS NOT NULL, user.id,
    data_stream.dataset == "{integration}.audit" AND slack.actor.user.id IS NOT NULL, slack.actor.user.id,
    null
  ),
  user.name = CASE(
    user.name IS NOT NULL, user.name,
    data_stream.dataset == "{integration}.audit" AND user.full_name IS NOT NULL, user.full_name,
    null
  ),
  host.ip = CASE(
    host.ip IS NOT NULL, host.ip,
    data_stream.dataset == "{integration}.log" AND source.ip IS NOT NULL, source.ip,
    null
  )
```

Pattern: `CASE(<col> IS NOT NULL, <col>, data_stream.dataset == "…" AND <source> IS NOT NULL, <source>, null)` (5 args) or `CASE(<col> IS NOT NULL, <col>, <fallback>)` (3 args, when only one possible source).

**Never** `CASE(actor_exists, col, ...)` — `actor_exists` can be true from a different field while `col` is still null, silently skipping the fallback.

Only include columns with a defensible fallback for at least one dataset. Order: user → host → service → entity actor fields.

### Combined ES|QL — event action

Third fenced `esql` block (when this integration has action candidates):

```esql
| EVAL
  event.action = CASE(
    event.action IS NOT NULL, event.action,
    data_stream.dataset == "{integration}.audit" AND slack.action IS NOT NULL, slack.action,
    data_stream.dataset == "{integration}.logs" AND azure.open_ai.operation_name IS NOT NULL, azure.open_ai.operation_name,
    null
  )
```

Omit entire block when no action fallback exists (document in Gaps).

### Combined ES|QL — target fields

Fourth fenced `esql` block. Target columns use **`user.target.*` / `host.target.*` / `service.target.*` / `entity.target.*` only**:

```esql
| EVAL
  user.target.id = CASE(
    user.target.id IS NOT NULL, user.target.id,
    data_stream.dataset == "{integration}.audit" AND slack.audit.entity.entity_type == "user" AND event.action != "user_login" AND slack.audit.entity.id IS NOT NULL, slack.audit.entity.id,
    null
  ),
  service.target.name = CASE(
    service.target.name IS NOT NULL, service.target.name,
    data_stream.dataset == "{integration}.audit" AND event.action == "user_login", "Slack",
    null
  ),
  host.target.ip = CASE(
    host.target.ip IS NOT NULL, host.target.ip,
    data_stream.dataset == "{integration}.log" AND destination.ip IS NOT NULL, destination.ip,
    null
  )
```

Pattern: `CASE(<col> IS NOT NULL, <col>, <dataset-and-conditions>, <source>, null)` (5 args) or `CASE(<col> IS NOT NULL, <col>, <literal>)` (3 args for semantic literals with no ambiguity).

**Never** `CASE(target_exists, col, fallback, null)` — that is a 4-arg CASE where `fallback` parses as a boolean condition and `null` is its return value, not the default.

Never write `target.user.id` — always `user.target.id`.

### Full pipeline fragment (optional)

A copy-pasteable minimal query — **unscoped** `FROM logs-*` (no `WHERE data_stream.dataset` filter). Dataset routing lives **inside every CASE fallback branch**:

```esql
FROM logs-*
| EVAL
  actor_exists = …,
  target_exists = …,
  action_exists = event.action IS NOT NULL
| EVAL
  user.name = CASE(user.name IS NOT NULL, user.name, data_stream.dataset == "{integration}.audit" AND user.full_name IS NOT NULL, user.full_name, null),
  user.target.id = CASE(user.target.id IS NOT NULL, user.target.id, data_stream.dataset == "{integration}.audit" AND slack.audit.entity.id IS NOT NULL AND …, slack.audit.entity.id, null),
  event.action = CASE(event.action IS NOT NULL, event.action, data_stream.dataset == "{integration}.audit" AND slack.action IS NOT NULL, slack.action, null)
| KEEP @timestamp, data_stream.dataset, event.action, user.id, user.name, user.target.id, service.target.name
```

**Do not** use `| WHERE data_stream.dataset IN (…)` in the fragment — customers run cross-package queries; each fallback must embed its dataset guard.

### Streams excluded

Bullet list of datasets where **no** actor/target `EVAL` is produced (metrics, inventory, engine stats), with one-line reason.

### Gaps and limitations

- Destination columns intentionally omitted (no indexed source)
- Fields that need ingest-time enrichment before ES|QL can map them
- Ambiguous cases where `CASE` would guess wrong — prefer omission + note over false positives
- Alignment with Pass 2 **Enhancement candidate?** rows

---

## Step 3 — Validate mappings (mandatory)

Before returning, check each populated output column:

| Test | Action |
| --- | --- |
| Source field exists in fixtures for the cited dataset | Remove or downgrade if not |
| Actor source is principal/caller, not target object | Swap or split conditions |
| Target maps self on auth login (tautology) | Apply Pass 3 semantics — service/platform target |
| Same vendor field used for actor and target on one event | Add `event.action` or entity_type guard |
| Literal string used | Mark **semantic literal** in mapping table |
| ES|QL syntax | `CASE(cond, val, …)`, string equality with `==`, string literals double-quoted |
| Boolean conditions | Wrap boolean fields in `TO_BOOLEAN(field)` before `== true` / `== false`; never compare raw keyword booleans |
| Target namespace | No `target.user.*` — only `user.target.*` (and host/service/entity equivalents) |
| Preserve-first | Every mapped column uses `CASE(col IS NOT NULL, col, …)` as the first two args (column-level preserve) |
| No tautology | Fallback ≠ output column; omit ingest-only columns with no alternate source |
| Ingest-only | If pipeline always sets the field, do not emit `CASE(col, col, …)` |

---

## Rules

1. **Preserve existing values** — `CASE(user.id IS NOT NULL, user.id, …)` (column-level preserve), never blind assignment and never `CASE(actor_exists, user.id, …)` (flag-level — silently skips fallback when flag is true from a different field while this column is still null).
2. **Detection flags block** — `actor_exists`, `target_exists`, `action_exists` defined before mapping `EVAL`s.
3. **Correct target namespaces** — `user.target.*`, `host.target.*`, `service.target.*`, `entity.target.*` only; **never** `target.user.*` or `target.entity.type`.
4. **Dataset-first routing** — fallback branches start with `data_stream.dataset` (or `event.dataset` for assets-only).
5. **Mandatory column sets** — use the actor/target tables above; do not invent alternate ECS names.
6. **Separate EVAL blocks** — detection flags, then actor, then action (if any), then target (minimum four subsections when action applies).
7. **Mapping plan before code** — tables must precede ES|QL blocks; note **preserve existing** vs **fallback** per row.
8. **No cross-integration CASE branches** — this file covers `{integration}` datasets only.
9. **Prefer omission over guessing** — if confidence is low, leave column out and document in Gaps.
10. **Assets-only** — follow [package-capability.md](package-capability.md); Tier B dashboard evidence only.
11. **No tautological CASE** — omit columns from `EVAL` when ingest-only; fallback must reference a different field path.

---

Return the file path when done.
```

## Example invocation

Integration: `slack`  
Output: `dev/domain/p1/slack.md`

Expected highlights:

- Dataset: `slack.audit` only
- Detection flags → preserve-first `CASE` on all columns
- Actor fallback: `user.id` ← `user.id` or vendor; `user.name` ← `user.full_name` when `NOT actor_exists`
- Target fallback: `service.target.name = "Slack"` when login and `NOT target_exists`; `user.target.id` ← `slack.audit.entity.id` when `entity_type == "user"` and not login
- Action: `event.action` ← `slack.action` when `NOT action_exists`
- Never `target.user.*`; never overwrite populated `user.*` / `user.target.*`

Integration: `linux`  
Expected: **Streams excluded** — metrics-only; no actor/target EVAL

Integration: `fortinet_fortigate`  
Expected: actor `user.name` / `source.ip`; target `destination.user.name` → `user.target.name` (de-facto); network flows → `host.target.ip`

## Notes for orchestrator

- Run **after Pass 2** (required) and **Pass 3** (strongly recommended — target routing on auth events).
- **Replace** `## ES|QL Entity Extraction` on re-run; do not duplicate.
- One sub-agent per integration.
- Include [Scope guardrails](#scope-guardrails) in every prompt.
- Pass 4 output is **query-time normalization** — it does not modify ingest pipelines or packages.
- For orchestrator batches: same parallel pattern as Pass 2–3 (8–10 at a time).

## Relationship to other passes

| Pass | Prompt | Output |
| --- | --- | --- |
| 1 | `domain-knowledge.md` | Product domain + data streams |
| 2 | `actor-target-classification.md` | Field inventory + ECS candidates |
| 3 | `event-graph-example.md` | Readable Actor → action → Target examples |
| 4 | `esql-entity-mapping.md` | ES|QL `EVAL`/`CASE` actor + target extraction |

Pass 4 must **not contradict** Pass 2 mapping quality flags or Pass 3 target semantics. When Pass 2 marks **Mapping correct?** = `no`, do not wire that field into ES|QL without a guard or note in Gaps.
