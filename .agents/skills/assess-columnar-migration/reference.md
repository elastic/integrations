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
| `logsdb_columnar` | Log data streams | Sort on `host.name` asc + `@timestamp` desc unless a sort is configured; adds the `host.name` mapping if missing, and sorts on `@timestamp` only if the existing `host.name` mapping cannot be sorted on |
| `columnar` | Non-log indices | No default sort — you must set one |

Setting: `settings.mode: logsdb_columnar` or `settings.mode: columnar`.
Cannot be changed after index creation.

### Metrics and other stream types

The rollout covers logging integrations only. Metrics streams are out of
scope, whether they are TSDB (`elasticsearch.index_mode: time_series`) or not;
bare `columnar` is technically possible for them, but is not part of this
rollout. Stream types other than `logs` and `metrics` (for example
`synthetics`) are out of scope too.

## Storage and query model

- Non-text fields stored once as doc values; **not inverted-indexed by default**.
- Query performance on non-indexed fields depends on **index sort + doc-value
  skippers**. Filters on unsorted high-cardinality fields are slow.
- Text fields remain inverted-indexed by default.
- Future migration success criterion: shipped dashboards, detection rules,
  alerting rule templates, and SLO templates return the same results on
  columnar-backed data as on LogsDB.

## Dynamic mapping

- Strings → `keyword` (not keyword+text multi-field).
- Numbers → long/double.
- `dynamic: false` → unmapped fields are **dropped** (no `_source` fallback).
  Check both `fields/*.yml` and stream `manifest.yml` index template mappings.
  This is the tech-preview behaviour. Whether columnar stores unmapped fields
  by GA is still open, so these streams are `pending_platform`, not package work.
- `enabled: false` on objects → subtree **dropped**.
- Stack ECS template still adds text subfields for many ECS fields (e.g.
  `*.name`). Supported; storage trade-off; **info**, not a migration blocker.

## Mappings

- Always `subobjects: false`; mappings auto-flattened. Package
  `subobjects: false` is fine — do not report it.
- Single-level `nested` and `flattened` are valid — do not report them.
- **Nested-in-nested is rejected** (blocker).
- Mapping-level runtime fields rejected; request-time runtime fields still work.

## Columnar `_source`

Columnar modes do not store the original JSON. Both synthetic columnar `_source` and `columnar_stored` return the same reconstructed document. LogsDB synthetic `_source` still returns objects as nested JSON. Columnar `_source` returns dotted leaf keys: `{"host": {"name": "host-1"}}` comes back as `{"host.name": "host-1"}`. An array of objects that is not `nested` loses element pairing (`links: [{trace_id, span_id}]` becomes `links.trace_id` and `links.span_id`). Single-level `nested` keeps the array of objects. This check does not scan for that pairing loss.

ES|QL that only names fields reads columns and is unaffected. It breaks when the query asks for `METADATA _source` and then walks that JSON.

| Consumer | LogsDB `_source` | Columnar `_source` | Rewrite that works on both |
| --- | --- | --- | --- |
| Field reference `host.name` | Works | Works | Already cross-mode |
| `JSON_EXTRACT(_source, "host.name")` | Matches nested objects | Misses the literal key `"host.name"` | Use the field, not `_source` |
| `JSON_EXTRACT(_source, "['host.name']")` | Misses nested objects | Matches the literal key | Use the field, not `_source` |
| `FIELD_EXTRACT(flattened_root, "sub.key")` | Reads flattened doc values | Reads flattened doc values | Use this for `type: flattened` |
| `params._source.host.name` / `params._source['host']['name']` | Walks nested maps | Misses; the key is the literal `"host.name"` | `field('host.name').get(null)` or `$('host.name', null)` |
| `doc['host.name'].value` | Doc values | Doc values | Already the mapped name |

`type: flattened` stays valid as a mapping. It is not a blocker. The consumer problem is a query that uses `JSON_EXTRACT` on `_source` because ES|QL cannot treat flattened subfields as columns. `FIELD_EXTRACT(gcp.audit.request, "spec.request")` replaces `JSON_EXTRACT(_source, "$.gcp.audit.request.spec.request")`.

There is no `JSON_EXTRACT` path that matches both shapes. `COALESCE` of the dot path and the bracket path returns a value either way, and the path that misses emits a warning on every row. A lenient path that follows both nested objects and literal dotted keys is [elastic/elasticsearch#160300](https://github.com/elastic/elasticsearch/issues/160300).

`SET unmapped_fields="load"` is not the rewrite for these queries. `LOAD` reads `_source`, which is the document columnar changes, and it cannot reference subfields of a `flattened` parent. `NULLIFY` only avoids an error when a name is mapped in none of the indices in the `FROM`. A name mapped on one index and absent on another already returns `null` under the default.

| Query | Fields | Rewrite |
| --- | --- | --- |
| SIP enumeration, SIP REGISTER brute force, NFS burst | `network_traffic.sip.*` / `sip.*` and `network_traffic.nfs.*` / `nfs.*` are mapped leaves (`keyword`, or `long` for `sip.code`) on `logs-network_traffic.*`. `packetbeat-*` has the `sip.*` / `nfs.*` names. | Field reference: `COALESCE(network_traffic.sip.method, sip.method)`. No `unmapped_fields`. |
| GKE certificate signing | `gcp.audit.request` is `flattened`. `spec.request` is the CSR string. | `FIELD_EXTRACT(gcp.audit.request, "spec.request")` |
| AKS kube-audit hunting query (`detection-rules` only) | `azure.platformlogs.properties` is `flattened`. | `FIELD_EXTRACT(azure.platformlogs.properties, "log.user.username")` and the same for the other `log.*` leaves. The published AKS reverse-shell rule already does this. |

### Where the queries live

Do not classify the integration as Security or observability. Join on the dataset in `FROM`:

| `FROM` pattern | Package stream |
| --- | --- |
| `logs-gcp.audit-*` | `gcp` / `audit` |
| `logs-network_traffic.sip-*` | `network_traffic` / `sip` |
| `logs-azure.platformlogs-*` | `azure` / `platformlogs` |
| `packetbeat-*` | Not an integrations dataset. Keep the rule on the integration pattern in the same `FROM`. |

`security_detection_engine` has no `data_stream/` directory. It is the published prebuilt-rule snapshot. Hunting queries live only in [`elastic/detection-rules`](https://github.com/elastic/detection-rules) under `rules/` and `hunting/`. The assess script scans a local checkout when present and says so when it is missing. Search that repo before finishing a triage that prints the missing-checkout note.

Ingest pipelines see the document before index time. Do not flag them.

## Hard rejects (blockers)

- `store: true` — common on metrics `type: text` descriptions; remediation is
  usually drop `store` or switch to `keyword`
- `doc_values: false` on mapped fields:
  - **`event.original`**: classic ECS integrity packaging (`index: false` +
    `doc_values: false`, retrieve from `_source`). Under columnar `_source` is
    synthetic/columnar — treat as a dedicated remediation, not the same as
    redacting secrets. Most packages get it from `external: ecs`: ECS defines
    the field with `doc_values: false` and elastic-package copies that into the
    built mapping, so the field file doesn't show it. The script flags these.
    The stack's `ecs@mappings` uses `index: false` only, so packages that don't
    declare `event.original` are unaffected. Remediation options are dropping
    the ECS import for the field, or a columnar-only override
    ([obs-integration-team#1252](https://github.com/elastic/obs-integration-team/issues/1252)).
  - **ECS `*.x509.public_key_exponent`** (and `gen_ai.agent.description` in
    newer ECS): same mechanism as `event.original` via `external: ecs`.
  - **Secrets / custom**: e.g. password fields — remap or exclude the stream
- `copy_to`
- Runtime fields declared in `fields/*.yml` (`runtime: true` or a script string)
- Nested-in-nested (script reports parent → child dotted paths). Checked on
  dotted paths across all of a stream's field files, so a dotted sibling
  (`- name: whats` nested next to `- name: whats.intel_intra_ids` nested) counts
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

Applies when migrating a specific integration, not during assessment.

| Pattern | Sort idea |
| --- | --- |
| Host-centric logs (system, web servers) | `host.name` + `@timestamp` (the `logsdb_columnar` default) |
| Reverse proxy / load balancer fronting many upstreams | Consider the upstream or virtual host field if dashboards slice by it; otherwise `host.name` |
| Network / firewall | `observer.name` or similar device id + `@timestamp` |
| Cloud audit | `cloud.account.id` / tenant / org + `@timestamp` |
| IdP / SaaS audit | `user.name` / actor id + `@timestamp` |
| OTel content packages | Out of scope; stack OTel template owns sort |

`scripts/index_sort_hints.py` prints per-stream dashboard fields; use them as
hints, then apply domain judgment. It reads dashboards, visualizations, Lens,
saved searches, and maps (not ML modules), and lists dashboard-level controls
and filters separately from panels. Each panel counts toward the streams whose
dataset it names (in a filter, index pattern, or field prefix), else the stream
its dashboard names if that is exactly one; otherwise it counts only fields the
stream declares. Fields that only appear in KQL strings or saved-search columns
are not captured.

### Detection-rule fields

`index_sort_hints.py` also lists, per stream, the fields that prebuilt rules in
`security_detection_engine` declare in `required_fields` (latest version per
rule). The assess script uses the same attribution for its rule counts. A rule
is attached by its index patterns. A package-wide pattern
(`logs-aws*`) is narrowed to the datasets the query names, then to the
policy templates in `related_integrations`. A rule on `logs-*` counts only
when `related_integrations` names the package.

Security queries often filter on mid/high-cardinality fields (user names, file
hashes, IPs) across long time ranges. Without an inverted index those filters
scan doc values unless the field leads the index sort, and block-level
structures such as bloom filters are not planned for GA. So:

- Low-cardinality fields most rules filter on are sort candidates.
- High-cardinality identifiers are candidates for an explicit inverted index
  (`index: true`).
- Indexing all fields by default for Security-heavy streams is a product-level
  option, not a per-package decision.
- EQL, KQL, and Lucene rules run as Query DSL; performance tests must cover
  them, not only ES|QL. The same goes for Query DSL dashboards and the
  package's alerting rule and SLO templates.

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

9.5 shipped with max **3.6**, so the columnar spec minor needs Kibana 9.6+.

`elasticsearch.index_mode` allows only `time_series`. Index sort (`index.sort.field` / `order`) is already in the spec. Nothing can declare `logsdb_columnar` or `columnar`. That is a new feature that needs stack support, so package-spec versioning makes it a **minor** bump, not a patch on 3.4 or 3.6.

Order:

1. Add the columnar-ready concept to package-spec (mode, required index sort, mapping rules that match this skill's blockers).
2. Raise `REGISTRY_SPEC_MAX_VERSION` on the Kibana line that ships the columnar opt-in (9.6+).
3. Bump the integration's `format_version` to that spec and set the stack constraint to 9.6+.

Step 3 is what drops older stacks. A package left on 3.4.x stays installable on 8.19 and cannot express columnar. Many integrations stay on 3.4 for that reason. `conditions.kibana.version: ^9.6.0` is still required, and it does not make a new `index_mode` valid on an older spec.

## What eventual migration would touch (TODO/TBC)

Not performed by this skill; list in “Proposed changes” only:

1. New package-spec minor for columnar-ready streams, accepted by Kibana 9.6+ (`spec.max`)
2. Bump `format_version`. State the current spec minimum first (3.4 → 8.19, 3.5 → 9.2, 3.6 → 9.4); the bump raises it to 9.6+
3. Fix blockers or exclude data streams (others can proceed)
4. Index sort per data stream
5. Set `logsdb_columnar`
6. Update tests under columnar mode (procedure lives in the follow-up migration skill)
7. End-to-end tests + dashboard/rule checks
8. Changelog noting opt-in and behavioral differences

Indexed-document checks belong in that follow-up skill. Pipeline tests stay valid: they compare ingest-simulate output, before index mode. LogsDB golden `_source` is not the columnar document; normalize per [Columnar `_source`](#columnar-source). System and asset tests catch mapping rejects. Query rewrites for `_source` consumers belong in `detection-rules` or `security_detection_engine`, unless that package owns the query.
