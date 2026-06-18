# Plan B — If substring scan is insufficient

Use when Checkpoint 3/4 validation shows **too many false positives** or **missed dynamic mappings**.

| Symptom | Remediation |
|--------|----------------|
| Noise in Tier A/B/C | YAML-aware walk: only scan processor string values (`field`, `target_field`, `copy_from`, `rename`, `value`, etc.); ignore comments structurally. |
| Missed `ctx.*` / Painless | Optional second pass: extract string literals from `script` `source` blocks; merge with tier A rows flagged `confidence=low`. |
| Need ECS alignment | Cross-reference matched tokens against a pinned **ECS** `field` list JSON; add column `ecs_known=true/false`. |
| Ongoing drift | Add a scheduled GitHub Action (manual or cron) that runs `scan.py` and uploads `out/` as a workflow artifact. |

The default tool remains `scan.py` until one of the above is implemented.
