# Stakeholder matrix — `packages_stakeholder_matrix.csv`

## Generate

```bash
python3 dev/target-fields-audit/stakeholder_matrix.py
```

Output: [`out/packages_stakeholder_matrix.csv`](out/packages_stakeholder_matrix.csv) — **445 rows** (one per integration under `packages/`).

## Columns

| Column | Values | Source |
|--------|--------|--------|
| **package** | integration directory name | `packages/<name>/` |
| **security category** | Y / N | Root `manifest.yml` lists catalog category `security` |
| **observability category** | Y / N | Root `manifest.yml` lists catalog category `observability` |
| **graph visualization support** | `supported` / `identified potential` / `missing` | Heuristic from audit artifacts (see below) |
| **new strategy support (destination field)** | Y / N | Y if ingest pipeline references `destination.user` or `destination.host` / `destination.hostname` ([`destination_identity_hits.csv`](out/destination_identity_hits.csv)) |
| **support verified** | Y / N | Defaults to **N** (automated scan only). Set **Y** manually after product review. |
| **other catalog categories** | text (may be empty) | All other categories from the same manifest, joined with `; ` (e.g. `network; threat_intel`). Excludes `security` and `observability`. Last column for easy filtering in spreadsheets. |

## Graph visualization support (automated rules)

Priority order:

1. **`supported`** — Tier **A** hit in [`target_fields_audit.csv`](out/target_fields_audit.csv): pipeline maps ECS `host.target.*`, `user.target.*`, `service.target.*`, or `entity.target.*`.
2. **`identified potential`** — Not Tier A, but at least one of:
   - **new strategy** destination field (Y above), or
   - ECS `*.target.*` only in Tier **B** (fields) or **C** (Kibana JSON), or
   - Vendor-namespaced `*target*` path in [`vendor_target_special_cases.csv`](out/vendor_target_special_cases.csv) (`vendor_root` / `vendor_namespaced`).
3. **`missing`** — None of the above.

## Inputs refreshed when re-running

Re-run upstream scans first if the repo changed:

```bash
python3 dev/target-fields-audit/scan.py
python3 dev/target-fields-audit/destination_identity_scan.py
python3 dev/target-fields-audit/vendor_target_scan.py
python3 dev/target-fields-audit/stakeholder_matrix.py
```
