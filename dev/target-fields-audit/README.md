# ECS `*.target.*` integration audit

Deterministic inventory of references to `host.target.*`, `user.target.*`, `service.target.*`, and `entity.target.*` under [`packages/`](../../packages/).

## Documents

- [SCOPE.md](SCOPE.md) — tier definitions, prefixes, defaults (Checkpoint 1).
- [OUTPUT.md](OUTPUT.md) — CSV and summary schema (Checkpoint 2).
- [PILOT_VALIDATION.md](PILOT_VALIDATION.md) — pilot command and human sign-off checklist (Checkpoint 3).
- [CHECKPOINT4.md](CHECKPOINT4.md) — full-scan artifacts and acceptance checklist (Checkpoint 4).
- [PLAN_B.md](PLAN_B.md) — contingencies if substring matching is insufficient.

## Requirements

Python 3.10+ (stdlib only).

## Usage

From the repository root:

```bash
python3 dev/target-fields-audit/scan.py
```

Pilot (subset of packages):

```bash
python3 dev/target-fields-audit/scan.py \
  --only-packages vectra_detect,cyberarkpas,nginx,redis,apache \
  --output-dir dev/target-fields-audit/out/pilot
```

Stricter Tier A (skip whole-line `#` comments only):

```bash
python3 dev/target-fields-audit/scan.py --ignore-yaml-comments
```

Optional compact “top N by Tier A rows” section in the Markdown summary:

```bash
python3 dev/target-fields-audit/scan.py --top-n 20
```

## Security-tagged integrations only (`categories: security`)

To restrict all scans to packages whose root [`manifest.yml`](../../packages/okta/manifest.yml) lists the **`security`** category (273 packages in this repo), use `--security-only` and a dedicated output directory:

```bash
mkdir -p dev/target-fields-audit/out/security
python3 dev/target-fields-audit/scan.py --security-only --output-dir dev/target-fields-audit/out/security
python3 dev/target-fields-audit/enhancement_scan.py \
  --security-only \
  --audit-csv dev/target-fields-audit/out/security/target_fields_audit.csv \
  --output-dir dev/target-fields-audit/out/security
python3 dev/target-fields-audit/vendor_target_scan.py --security-only --output-dir dev/target-fields-audit/out/security
```

Helper: [`manifest_util.py`](manifest_util.py) (`security_package_names()`).

## Enhancement opportunities (broader heuristics)

Second pass: packages that **do not** yet map ECS `*.target.*` in pipelines (per audit CSV) but show **destination / actor / fixture / docs** signals that might justify `host|user|service|entity.target.*` or generic `entity.target.*`:

```bash
python3 dev/target-fields-audit/enhancement_scan.py
```

Writes [`out/target_enhancement_report.md`](out/target_enhancement_report.md) and [`out/target_enhancement_packages.csv`](out/target_enhancement_packages.csv). Re-run after refreshing `target_fields_audit.csv` with `scan.py`.

## Vendor `*target*` fields (e.g. `okta.target`)

Per-integration dotted paths and pipeline assignments that contain `target` but are **not** necessarily ECS `host|user|service|entity.target.*`:

```bash
python3 dev/target-fields-audit/vendor_target_scan.py
```

Produces [`out/vendor_target_special_cases.csv`](out/vendor_target_special_cases.csv), [`out/vendor_target_special_cases_report.md`](out/vendor_target_special_cases_report.md), and the triage playbook [`VENDOR_TARGET_ANALYSIS_PLAN.md`](VENDOR_TARGET_ANALYSIS_PLAN.md).

## `destination.user` / `destination.host` review list

Per-integration checklist for manual review (ingest pipeline references only):

```bash
python3 dev/target-fields-audit/destination_identity_scan.py
python3 dev/target-fields-audit/destination_identity_scan.py --security-only --output-dir dev/target-fields-audit/out/security
```

Writes `destination_identity_hits.csv` (line-level) and `destination_identity_review.md` (numbered package checklist + detail).

## Stakeholder matrix (all 445 packages)

```bash
python3 dev/target-fields-audit/stakeholder_matrix.py
```

See [`STAKEHOLDER_MATRIX.md`](STAKEHOLDER_MATRIX.md) — outputs [`out/packages_stakeholder_matrix.csv`](out/packages_stakeholder_matrix.csv).

## Outputs

Written to `out/` by default:

- `target_fields_audit.csv`
- `target_fields_audit_summary.md`

## Plan B

If substring search is too noisy or misses dynamic Painless literals, see the Plan B table in the execution plan: YAML-aware processor walk, script literal extraction, or ECS field list cross-check. This directory can host a follow-up `scan_ast.py` without changing the default CSV schema.
