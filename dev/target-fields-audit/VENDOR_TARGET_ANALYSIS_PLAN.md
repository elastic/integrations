# Analysis plan — vendor `*target*` fields → ECS target / `entity.target.*`

## Goal

Turn `vendor_target_special_cases.csv` into an actionable backlog: which integrations expose
vendor-specific **target** semantics (`okta.target`, `canva.audit.target.*`, `azure.provisioning.properties.target_identity.*`, …)
and how to normalise them at ingest or in ES|QL (`CASE` / `COALESCE`) into `user.target.*`, `host.target.*`,
`service.target.*`, or **`entity.target.*`** when classification is unclear.

## Inputs

| Artifact | Use |
| --- | --- |
| [`out/vendor_target_special_cases.csv`](out/vendor_target_special_cases.csv) | One row per deduplicated field path + where it was found (fields vs pipeline vs fixture). |
| [`out/vendor_target_special_cases_report.md`](out/vendor_target_special_cases_report.md) | Package-level counts and namespace mix. |
| [`out/target_fields_audit.csv`](out/target_fields_audit.csv) | Already-mapped ECS `*.target.*` (avoid duplicate work). |
| [`out/target_enhancement_packages.csv`](out/target_enhancement_packages.csv) | Broader destination/actor heuristics per integration. |

## Triage workflow (recommended)

### Step 1 — Filter vendor signal

In the CSV, keep rows where `namespace_class` is `vendor_root` or `vendor_namespaced`.
These are the closest analogues to `okta.target`.

### Step 2 — Group by `package` + `data_stream`

Produce a short table per data stream: distinct `field_path`, `source`, and whether the path
already appears in `target_fields_audit.csv` for that package (Tier A ECS target).

### Step 3 — Semantic review (human)

For each field path, answer:

1. **Actor vs target** — Is this the object acted upon, or the initiating principal?
2. **Cardinality** — Single object vs collection (e.g. `okta.target` list)?
3. **ECS mapping** — `user.target.*`, `host.target.*`, `service.target.*`, or fallback `entity.target.*`?

### Step 4 — Runtime ES|QL prototype

For the top N integrations by hit count, draft a `CASE` chain (see Elastic `CASE` docs) ordered:
existing ECS `*.target.*` → vendor `*.target.*` identity fields → generic `entity.target.*`.

### Step 5 — Validate on fixtures

Use rows with `source=expected_json` to run simulate / sample queries against golden documents.

## Reporting outputs (for stakeholders)

1. **Executive one-pager:** X integrations with vendor `*target*` paths; Y already overlap ECS target; Z net-new.
2. **Per-integration appendix:** field_path list + recommended ECS bucket + confidence.
3. **Runtime matrix:** integration → ES|QL fragment version (for reuse in Kibana).

## Caveats

- Nested `fields.yml` stack parsing can miss unusual YAML; re-run after major field refactors.
- Keys in `expected.json` may include escaped vendor blobs; treat as hints.
- Paths like `oracle.memory.pga.aggregate_target` are **not** security “target entity” semantics — filter with an exclusion list as you learn them.
