# Checkpoint 1 — Approved scope (defaults from execution plan)

This document freezes scope for the ECS `*.target.*` audit unless explicitly revised.

## Tiers

| Tier | Path rule | Meaning |
|------|-----------|---------|
| **A** | Under `packages/`, path contains `/elasticsearch/ingest_pipeline/`, file ends with `.yml` or `.yaml` | Ingest pipeline logic (strong signal). |
| **B** | Under `packages/`, path contains `/fields/`, file ends with `.yml` | Field definitions (weaker; schema only). |
| **C** | Under `packages/`, path contains `/kibana/`, file ends with `.json` | Kibana saved objects (separate appendix; not ingest). |

## Field prefixes (substring match)

- `host.target.`
- `user.target.`
- `service.target.`
- `entity.target.`

## Excluded patterns (enhancement scan)

- **`related.*`** (e.g. `related.user`) is not treated as a target signal: related entities may be actor or target without disambiguation in the catalog.

## Integration grain

- **package**: first path segment under `packages/` (e.g. `okta`).
- **data_stream**: segment after `data_stream/` when present; otherwise empty.
- **file**: repository-relative path.

## Comments

- **Whole-line** `#` comments: skipped when using `--ignore-yaml-comments`.
- **End-of-line** comments: by default, text after a ` #` sequence (space + hash) is ignored for prefix matching only (heuristic; not a YAML lexer). Snippets in the CSV still show the full original line.

## Tier C handling

Tier C hits are reported in the same CSV with `tier=C` and summarized separately so pipeline counts stay comparable across integrations.
