# Checkpoint 3 — Pilot run (for human sign-off)

## Command

```bash
python3 dev/target-fields-audit/scan.py \
  --only-packages vectra_detect,cyberarkpas,nginx,redis,apache,mysql_enterprise,okta \
  --output-dir dev/target-fields-audit/out/pilot
```

## Pilot packages

| Package | Rationale |
|---------|-----------|
| vectra_detect | Known `user.target.*` pipeline usage |
| cyberarkpas | Known `user.target.*` pipeline usage |
| mysql_enterprise | Known pipeline + fields from earlier repo search |
| okta | Known pipeline usage |
| nginx, redis, apache | Likely low/no hit sanity check |

## Automated self-check (implementation)

- **Tier A** rows in pilot CSV must reference real processor lines (e.g. `set:`, `field:`, `rename`, `value:`) for known positives; pilot output is under [`out/pilot/`](out/pilot/).
- **Inline comment false positives:** Lines where a prefix appeared only after ` #` in YAML are excluded from matching (see [`SCOPE.md`](SCOPE.md)); snippets still show the full line for audit.

## Acceptance (owner: you)

- [ ] Spot-check 10–20 rows in `out/pilot/target_fields_audit.csv` for correct **tier** (path-based) and **prefix**.
- [ ] Confirm a known integration (e.g. `vectra_detect` or `cyberarkpas`) still appears for `user.target.` in **Tier A** after the comment heuristic.

If precision is below expectation, run with `--ignore-yaml-comments` or proceed to [PLAN_B.md](PLAN_B.md).
