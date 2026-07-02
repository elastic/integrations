# Checkpoint 4 — Full scan sign-off

## Artifacts

| File | Description |
|------|-------------|
| [`out/target_fields_audit.csv`](out/target_fields_audit.csv) | One row per `(file, line, matched_prefix)` with evidence snippet. |
| [`out/target_fields_audit_summary.md`](out/target_fields_audit_summary.md) | Aggregates, **packages scanned** count, confidence legend, unique packages by tier/prefix, Tier A `(package, data_stream)` count, **full list** of integrations with hits. |

Re-run after any change under `packages/`:

```bash
python3 dev/target-fields-audit/scan.py
```

The summary header records **`git HEAD`** at generation time for reproducibility.

## Acceptance checklist (owner: you)

- [ ] **Coverage:** `out/target_fields_audit_summary.md` answers package counts for Tier A/B/C and each prefix.
- [ ] **Traceability:** Any summary number can be traced to rows in the CSV (same commit SHA as in summary).
- [ ] **Reproducibility:** Re-running `scan.py` on the same commit reproduces the same row set (deterministic scan order and rules).

## Latest full-scan totals (see summary for authoritative numbers)

From the generated summary at implementation time:

- **29** unique packages with at least one **Tier A** (pipeline) hit.
- **37** unique packages with any hit (A, B, or C).
