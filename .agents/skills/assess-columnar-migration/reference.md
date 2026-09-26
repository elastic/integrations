# Columnar reference (assess-columnar-migration)

Read this when you need semantics beyond the assessment workflow in `SKILL.md`.

## Why integrations opt in

Columnar can be enabled via index settings or, for some clusters, a `logs-*-*`
component template. **Fleet integrations in this repo should still opt in
explicitly per data stream** because:

- Index sort must match the integration’s query patterns (dashboards, rules).
- A shared `logs-*-*` template cannot set the right sort for every integration.

## Modes

| Mode | Use for | Defaults |
| --- | --- | --- |
| `logsdb_columnar` | Log data streams | `@timestamp` mapping; sort on `host.name` + `@timestamp` when those mappings exist |
| `columnar` | Non-log indices | No default sort — you must set one |

Setting: `settings.mode: logsdb_columnar` or `settings.mode: columnar`.
Cannot be changed after index creation.

### Metrics / TSDB

- Streams with `elasticsearch.index_mode: time_series` (or top-level
  `index_mode: time_series`) are **TSDB** — out of scope for columnar.
- Metrics **without** `time_series` are assessed as `metrics_undecided`:
  bare `columnar` is technically possible, but TSDB may still be the right
  product choice. Do not auto-recommend columnar for metrics.

## Storage and query model

- Non-text fields stored once as doc values; **not inverted-indexed by default**.
- Query performance on non-indexed fields depends on **index sort + doc-value
  skippers**. Filters on unsorted high-cardinality fields are slow.
- Text fields remain inverted-indexed by default.
- Future migration success criterion: shipped dashboards and detection rules
  still produce correct results on columnar-backed data.

## Dynamic mapping

- Strings → `keyword` (not keyword+text multi-field).
- Numbers → long/double.
- `dynamic: false` → unmapped fields are **dropped** (no `_source` fallback).
  Check both `fields/*.yml` and stream `manifest.yml` index template mappings.
- `enabled: false` on objects → subtree **dropped**.
- Stack ECS template still adds text subfields for many ECS fields (e.g.
  `*.name`). Supported; storage trade-off; **info**, not a migration blocker.

## Mappings

- Always `subobjects: false`; mappings auto-flattened. Package
  `subobjects: false` is fine — do not report it.
- Single-level `nested` and `flattened` are valid — do not report them.
- **Nested-in-nested is rejected** (blocker).
- Mapping-level runtime fields rejected; request-time runtime fields still work.

## Hard rejects (blockers)

- `store: true` — common on metrics `type: text` descriptions; remediation is
  usually drop `store` or switch to `keyword`
- `doc_values: false` on mapped fields:
  - **`event.original`**: classic ECS integrity packaging (`index: false` +
    `doc_values: false`, retrieve from `_source`). Under columnar `_source` is
    synthetic/columnar — treat as a dedicated remediation, not the same as
    redacting secrets.
  - **Secrets / custom**: e.g. password fields — remap or exclude the stream
- `copy_to`
- Nested-in-nested (script reports parent → child dotted paths)
- Turning off `_source`
- Incompatible types (e.g. `search_as_you_type`)

## Valid mapping types (do not report)

- Single-level `type: nested`
- `type: flattened`
- `type: group` / `type: object` (auto-flattened)

## Info (do not block migration)

- Package `type: text` / `match_only_text` — storage / inverted-index cost only
- ECS text subfields from the stack template — same

## Index sorting guidance

| Pattern | Sort idea |
| --- | --- |
| Host-centric logs | `host.name` + `@timestamp` |
| Network / firewall | `observer.name` or similar device id + `@timestamp` |
| Cloud audit | `cloud.account.id` / tenant / org + `@timestamp` |
| IdP / SaaS audit | `user.name` / actor id + `@timestamp` |
| OTel content packages | Out of scope; stack OTel template owns sort |

The assess script prints **Kibana field seeds** from dashboard JSON; use them as
hints, then apply domain judgment.

## Package spec version

Fleet installs a package only when its `format_version` **major.minor** is within `xpack.fleet.internal.registry.spec.max` (`REGISTRY_SPEC_MAX_VERSION` in Kibana). The patch is ignored: `3.4.0` and `3.4.2` are the same gate.

| `format_version` | Stacks that install it |
| --- | --- |
| 2.3.x – 2.11.x | Any stateful stack (not serverless) |
| 3.0.x | 8.11+ and 9.x |
| 3.1.x – 3.3.x | 8.16+ |
| 3.4.x | 8.19 and 9.1+ (not 9.0; 9.0 max is 3.3) |
| 3.5.x | 9.2+ |
| 3.6.x | 9.4+ |

9.5's max is still **3.6**.

`elasticsearch.index_mode` allows only `time_series`. Index sort (`index.sort.field` / `order`) is already in the spec. Nothing can declare `logsdb_columnar` or `columnar`. That is a new feature that needs stack support, so package-spec versioning makes it a **minor** bump, not a patch on 3.4 or 3.6.

Order:

1. Add the columnar-ready concept to package-spec (mode, required index sort, mapping rules that match this skill's blockers).
2. Raise `REGISTRY_SPEC_MAX_VERSION` on the Kibana line that has columnar (9.5+).
3. Bump the integration's `format_version` to that spec and set the stack constraint to 9.5+.

Step 3 is what drops older stacks. A package left on 3.4.x stays installable on 8.19 and cannot express columnar. Many integrations stay on 3.4 for that reason. `conditions.kibana.version: ^9.5.0` is still required, and it does not make a new `index_mode` valid on an older spec.

## What eventual migration would touch (TODO/TBC)

Not performed by this skill; list in “Proposed changes” only:

1. New package-spec minor for columnar-ready streams, shipped in Kibana 9.5 (`spec.max`)
2. Bump `format_version`. State the current spec minimum first (3.4 → 8.19, 3.5 → 9.2, 3.6 → 9.4); the bump raises it to 9.5+
3. Fix blockers or exclude data streams (others can proceed)
4. Index sort per data stream
5. Set `logsdb_columnar` or `columnar`
6. Update tests under columnar mode
7. End-to-end tests + dashboard/rule checks
8. Changelog noting opt-in and behavioral differences

Ingest comparisons later should check array ordering, missing fields under
`dynamic: false`, and synthetic / columnar `_source` shape.
