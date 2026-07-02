# Checkpoint 2 — Output schema

- [`out/security/`](out/security/) — optional **security-only** run (`--security-only` on each scanner); same filenames as above.

## `target_fields_audit.csv`

One row per `(file, line_number, matched_prefix)` when a line matches one or more prefixes.

| Column | Description |
|--------|-------------|
| `tier` | `A`, `B`, or `C`. |
| `package` | Integration package name. |
| `data_stream` | Data stream folder name, or empty. |
| `file` | Path relative to repository root. |
| `line` | 1-based line number. |
| `matched_prefix` | One of: `host.target.`, `user.target.`, `service.target.`, `entity.target.` |
| `snippet` | Truncated line text (CSV-escaped; default max 240 chars). |

Encoding: UTF-8.

## `target_fields_audit_summary.md`

Machine-generated from the CSV:

- Git `HEAD` SHA, scan timestamp, and **total integration packages scanned** (directories under `packages/` for this run).
- **Confidence legend:** `high` = any Tier A (pipeline); `medium` = Tier B only; `low` = Tier C only (see summary body).
- Unique **package** counts by `tier` and by `matched_prefix` (Tier A/B/C tables).
- Tier A unique `(package, data_stream)` pair count.
- **Full list** of every package with at least one hit: `package`, `confidence`, `tiers`, row counts per tier, `prefixes_seen`.
- Optional: if `scan.py --top-n N` with `N > 0`, a short “top N by Tier A rows” section is appended.

## Enhancement scan (optional second pass)

After `target_fields_audit.csv` exists, run `enhancement_scan.py` (see [README](README.md)) to produce:

- `target_enhancement_packages.csv` — one row per package with boolean signals and a `priority` label.
- `target_enhancement_report.md` — methodology, counts, and interpretation (heuristic backlog, not ground truth).

## Vendor `*target*` scan (`vendor_target_scan.py`)

- `vendor_target_special_cases.csv` — deduplicated dotted `field_path` values containing a `target` token, with `source` (`fields_yml_*`, `ingest_pipeline`, `expected_json`), `namespace_class`, and heuristic `suggest_bucket`.
- `vendor_target_special_cases_report.md` — aggregates (e.g. packages with vendor-prefixed paths).
- [`VENDOR_TARGET_ANALYSIS_PLAN.md`](VENDOR_TARGET_ANALYSIS_PLAN.md) — how to triage CSV rows into an ECS / `entity.target.*` backlog.

## Destination identity review (`destination_identity_scan.py`)

- `destination_identity_hits.csv` — pipeline lines referencing `destination.user` or `destination.host` / `destination.hostname`.
- `destination_identity_review.md` — numbered package checklist (for one-by-one review) plus per-package detail.

