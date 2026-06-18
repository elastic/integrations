# ECS target semantics — enhancement opportunity report

- **git HEAD:** `d43ff234d21161ef4cbbc25d56415e4aa72680d9`
- **generated (UTC):** 2026-05-20T08:56:50Z
- **packages scanned:** 273

- **filter:** Only integrations whose root `packages/<name>/manifest.yml` includes the `security` category.

- **audit CSV used:** `dev/target-fields-audit/out/security/target_fields_audit.csv` (Tier A ECS `*.target.*` packages: 28)

## What this report is (and is not)

**Is:** A static, heuristic pass over this repository only — ingest pipeline YAML,
pipeline `*expected.json` fixtures (truncated for very large files), and `docs/**/*.md`.
Signals are meant to suggest where vendor logs *might* describe a second party
(user/host/service/resource) that could be modeled as ECS **target** fields or
**`entity.target.*`** when classification is unclear.

**Is not:** Log volume, production field population, or vendor API guarantees.
Each row still needs product/security review before changing mappings.

## Method — signal definitions

| Signal | Meaning |
| --- | --- |
| `pipeline_dest_identity` | Pipeline references `destination.user`, `destination.host`, `destination.domain`, etc. |
| `pipeline_dest_network` | Pipeline references `destination.ip`, `destination.address`, ports/geo/bytes (common in flow logs). |
| `pipeline_actor` | `principal`, `victim`, `impersonat`, `protoPayload.authentication`, `source.user`, etc. (not `related.*`) |
| `pipeline_entity_other` | `entity.id` / `entity.name` / `entity.type` (not already `entity.target.*`). |
| `fixture_strong` | Pipeline expected JSON contains destination identity, ECS `*.target.*`, or JSON keys containing `target`. |
| `docs_lexicon` | Docs mention “target user/host”, “affected user”, “principal”, “victim”, etc. |

## Priority labels (per package)

| Label | Rule |
| --- | --- |
| `already_maps_ecs_target` | Listed with Tier A hits for `host|user|service|entity.target.*` in the audit CSV. |
| `strong_candidate` | Not already mapped **and** (`pipeline_dest_identity` **or** `pipeline_actor`). |
| `moderate_candidate` | Not stronger **and** (`fixture_strong` **or** `pipeline_entity_other`). |
| `moderate_candidate_network_dest` | Not stronger **and** only `pipeline_dest_network` among pipeline/fixture signals. |
| `exploratory_docs` | Not above **and** `docs_lexicon` only. |
| `none` | No heuristic signal. |

## Counts

| Priority | Packages | Share of scanned |
| --- | ---: | ---: |
| Already maps ECS target (Tier A audit) | 28 | 10.3% |
| **Strong enhancement candidate** | 59 | 21.6% |
| Moderate (fixtures / generic entity) | 48 | 17.6% |
| Moderate (network `destination.*` only) | 38 | 13.9% |
| Exploratory (documentation phrasing only) | 6 | 2.2% |
| No signal | 94 | 34.4% |

### Interpretation

- **Already using ECS target fields in pipelines (audit):** 28 / 273 packages.
- **Packages we would revisit first for new target mappings:** **59** strong candidates.
- **Broader backlog (includes weaker / noisier signals):** **151** packages (strong + moderate + moderate_network_only + exploratory), i.e. anything not `none` and not already mapped.
- If you only trust identity/actor-style pipeline evidence, focus on the **59** strong bucket first, then selectively pull from **48** moderate cases after reviewing fixtures.

**Note:** `strong_candidate` is an **upper bound**. Some regex matches (e.g. `destination.host` in pure flow telemetry) reflect common ECS patterns without always implying a distinct “target” entity for SIEM. Use [`target_enhancement_packages.csv`](target_enhancement_packages.csv) to triage by toggling signals off in a spreadsheet filter.

## Machine-readable output

- Per-package flags: [`target_enhancement_packages.csv`](target_enhancement_packages.csv)

## Follow-ups (not automated here)

- Vendor-specific field dictionaries (OCSF, ASIM, raw vendor `target*`) → ECS mapping tables.
- Runtime sampling / simulate ingest to confirm population rates.
- When entity type is unknown, map remaining attributes to **`entity.target.*`** per your placeholder rule.
