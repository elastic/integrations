# Validating a migrated package

Four stages: static, install, correctness, performance. Stages 1–3 are reproducible
today; stage 4 is manual.

## Contents

- 1. Static validation
- 2. Install against a real stack (Kibana with the Fleet support; getting a columnar
  index: routes A, B, C)
- 3. Correctness (pipeline tests; system tests; comparing the two modes; what is a bug)
- 4. Performance (workload; running it; what to watch)

---

## 1. Static validation

The static half is steps 1–7 of [`migration.md`](migration.md): baseline `lint`, the
`format_version` bump and second `lint`, the fixes, then `lint`, `build`,
`test pipeline` and `test static`, and a re-run of the audit. Two points matter for
validation:

- **Run `build`, not just `lint`.** `lint` validates the package **source**; `build`
  resolves `external: ecs` first and validates the **built zip**. In the source an
  `external: ecs` reference to `event.original` carries no `doc_values` at all; in the
  built package it carries `doc_values: false`. The ECS blocker
  (`doc_values_false_ecs`) is invisible to `lint` and fails `build` the moment the
  stream declares readiness.
- **The spec is unreleased.** Everything this skill writes is package-spec 3.7.0
  (`3.7.0-next`). A stock `elastic-package` rejects it; build one against a local
  package-spec checkout ([`migration.md`](migration.md#local-tooling)).

---

## 2. Install against a real stack

```
elastic-package stack up -d --version 9.6.0-SNAPSHOT
cd packages/<pkg>
elastic-package install
```

Then confirm what Elasticsearch actually built:

```
GET _index_template/logs-<pkg>.<ds>
GET .ds-logs-<pkg>.<ds>-*/_settings?filter_path=**.index.mode,**.index.sort
```

Check that:

- `index.mode` is `logsdb_columnar` — if the opt-in did not reach Elasticsearch the
  data stream silently stays on logsdb and every later measurement is meaningless.
  With the tech-preview plumbing (`columnar.supported: true`, no `index_mode`) `logsdb`
  is the *correct* answer until the stream is opted in (below);
- `index.sort.field` / `index.sort.order` match the intended sort. If you relied on the
  default, verify it resolved to `host.name, @timestamp` and not to the
  `@timestamp`-only fallback.

A template PUT that fails here is a Class A blocker the static audit missed — capture
the Elasticsearch error and report it.

### Kibana with the Fleet support

No Kibana snapshot has the Fleet columnar support yet (it is on the
`feat/columnar-index-mode` branch). Stock Kibana installs the package but ignores
`columnar.supported`, the field-level `columnar:` overrides and any non-TSDB
`index_mode`: the stream stays on logsdb and the toggle does not exist. Until the
Fleet change ships:

1. `elastic-package stack up` as above, then stop the docker Kibana
   (`docker stop elastic-package-stack-kibana-1`).
2. Run Kibana from the branch (`yarn start`) against the stack's Elasticsearch, with
   the stack's CA and the elastic-package service account token.
3. Install with the locally built `elastic-package`. Kibana's registry `spec.max` is
   still 3.6, so 3.7.0 packages only reach it through `elastic-package install`
   (upload), not through the registry.

Or use route C below, which works on any stock 9.5+ stack.

### Getting a columnar index locally

`elasticsearch.columnar.supported: true` does **not** change the index mode. It tells
Fleet the stream is ready, so Fleet offers the per-stream toggle; nothing is columnar
until a user turns it on. `elastic-package` has no flag that flips that toggle, so a
system test against a package that only declares `supported: true` runs on **logsdb**
and proves nothing about columnar. Pick one route:

**A. Temporarily declare the mode** (custom Kibana). Add the index mode to the stream
manifest, keep the edit **uncommitted**, test, revert:

```yaml
# data_stream/<ds>/manifest.yml — TEMPORARY, do not commit
elasticsearch:
  index_mode: logsdb_columnar      # local testing only
  columnar:
    supported: true                # this is the line that ships
```

```
elastic-package install
elastic-package test system
git checkout -- data_stream/<ds>/manifest.yml   # revert before committing
```

Shipping `index_mode: logsdb_columnar` would force columnar on every install of the
version, lock the toggle on and switch existing streams at the next rollover — a
different decision from declaring the stream ready.

**B. Opt in through the Fleet API** (custom Kibana). Install the package unmodified,
then set the same feature the toggle sets, on the package policy:

```
PUT kbn:/api/fleet/package_policies/<package_policy_id>
{
  ... the full package policy body ...,
  "package": {
    "name": "<pkg>", "version": "<version>",
    "experimental_data_stream_features": [
      { "data_stream": "logs-<pkg>.<ds>", "features": { "columnar": true } }
    ]
  }
}
```

It goes through exactly the Fleet toggle path, including the field-level `columnar:`
overrides. A stream whose package does not declare `columnar.supported` returns 400
("not columnar-ready"). The opt-in requests a **lazy** rollover: the new backing index
appears on the next indexed document, so `GET _data_stream/logs-<pkg>.<ds>` can show
the old generation long after the opt-in succeeded. Verify with a write, or force it
with `POST logs-<pkg>.<ds>/_rollover`.

**C. A `@custom` component template** (any stock 9.5+ stack). For packages without
`doc_values: false` fields — no ECS `event.original` import, no package-owned one —
set the mode in the stream's custom component template, which Fleet templates already
compose:

```
PUT _component_template/logs-<pkg>.<ds>@custom
{ "template": { "settings": { "index.mode": "logsdb_columnar" } } }
POST logs-<pkg>.<ds>-default/_rollover
```

Fleet does not know about this mode, so it applies no field overrides: a
`doc_values: false` field makes the PUT fail, which is itself a useful check. Delete
the component template (and roll over) when done.

Whatever the route, re-run the `GET _settings` check and confirm `index.mode` is
`logsdb_columnar` on the **newest** backing index before believing any result.

---

## 3. Correctness

Run the package's own tests **with and without** columnar and diff the results. The
"with columnar" half needs one of the routes above; if you skip that step both halves
run on logsdb and the diff is empty for the wrong reason.

### Pipeline tests: the output must be identical

`elastic-package test pipeline` posts the documents to `_ingest/pipeline/_simulate`
and compares the result with `data_stream/<ds>/_dev/test/pipeline/*-expected.json`.
**Nothing is ever indexed**, so the index mode cannot change the output.

- **When the index mode is the only difference**, the results must be **identical**.
  Any diff is a real bug, or pre-existing test nondeterminism (a timestamp, a
  generated id) — never an expected columnar effect. `-g` should never be needed.
- **When the migration also applied an auto-fix that touches the pipeline** (a
  `copy_to` moved into a `set`/`append` processor, a normalizer replaced by a
  `lowercase`/`gsub` processor), the output legitimately changes. Regenerate with
  `-g`, read every hunk, keep the regeneration in its own commit, and say so in the PR.
- A package-level pipeline, such as a `latest` transform's destination pipeline, is
  not covered by `test pipeline`: check it with `_ingest/pipeline/_simulate`
  ([`blockers.md`](blockers.md) C10).

### System tests: where the shape changes show up

System tests are the only stage that indexes anything, so they are the only stage the
index mode can affect. Confirm `index.mode` on the backing index (section 2) before
reading the diff.

Expected differences **in indexed documents**:

| Difference | Example | Why |
| --- | --- | --- |
| `_source` keys are **dotted**, not nested objects | `{"event.id": "abc"}` instead of `{"event": {"id": "abc"}}` | columnar flattens the mapping, so the rebuilt `_source` has no hierarchy. `geo_point` still returns `{lat, lon}` |
| **Single-element arrays collapse to scalars** | `event.category: ["web"]` reads back as `"web"` | logsdb keeps the array via `index.mapping.synthetic_source_keep: arrays`, a setting columnar does not support |
| Arrays of objects lose their per-object grouping | `[{a:1,b:2},{a:3,b:4}]` → `{a:[1,3], b:[2,4]}` | object arrays are not retained faithfully |
| Multi-value arrays keep ingest order | | columnar preserves the order; plain logsdb synthetic source sorts and dedupes |
| A field under `dynamic: false` disappears | | Class B data loss — must already have been reviewed |
| A keyword with `normalizer: lowercase` comes back lowercased | | Class C4 |

The first four rows are the **complete** expected-diff set for a package with no
Class B finding. Measured on `anthropic`: the same mock data indexed in both modes, 8
documents matched on `event.id`, **zero value differences**, shape only.

**elastic-package reports the scalar collapse as a failure.** Its system-test field
validation fails every columnar package with `field "<x>" is not normalized as
expected: expected array, found <scalar>` (seen on `tags`, `event.category`,
`event.type`, `related.ip`). That is the tooling not knowing columnar yet, not a
package bug: confirm the values match and note it in the PR.

**Who is affected by the shape changes.** Anything doing *nested* access on the source
breaks: `_source.event.id`, Painless `params._source.event.id`, ES|QL
`JSON_EXTRACT(_source, "event.id")`, a `latest` transform's destination pipeline,
Kibana code walking the object. Anything indexing into an array (`event.category[0]`)
has to tolerate a scalar. **Field-level access is unaffected** — `doc[...]`, KQL,
aggregations, ES|QL columns, dashboards and rules that query fields.

### Comparing the two modes

```
# 1. logsdb baseline
elastic-package test system --defer-cleanup 4m
#    during the deferral window, against the test stack:
#    GET logs-<pkg>.<ds>-*/_search?size=100      -> save as logsdb.json

# 2. same again in columnar (route A, B or C)
elastic-package test system --defer-cleanup 4m
#    GET logs-<pkg>.<ds>-*/_search?size=100      -> save as columnar.json
```

`--defer-cleanup` keeps the data stream alive long enough to snapshot it. For streams
that keep producing data, snapshot on the `INFO Validating test case...` line: the data
stream is deleted before the results table prints. Match documents on a **flattened**
`event.id` (`doc.get("event.id") or doc["event"]["id"]`), then classify every
difference into the table above. A difference that fits none of them is a bug.

### Anything else is a bug

Report it with the package, data stream, the input document and the two indexed
documents. Specifically not expected: values changing, numeric precision loss,
`null`/empty-string confusion, dropped fields that *are* explicitly mapped, or
`ignore_malformed` behaviour differences.

**Query-level correctness is still manual.** The rollout asks whether the same queries
return the same answers in both modes. Replay the stream's dashboard queries and the
rules on its **Detection rules** line against both copies and compare the hits.

---

## 4. Performance

Manual for now. There is no harness in this skill; the audit extracts the workload.

### Build the workload

- **Dashboards:** `audit.py <package>` prints the fields the package's Kibana assets
  reference under **"Dashboard fields"**; the queries themselves are in
  `kibana/dashboard/*.json`, `kibana/lens/*.json`, `kibana/search/*.json` and
  `kibana/ml_module/*.json`.
- **Detection rules:** each stream's **Detection rules** line says how many shipped
  rules query it directly, by language (JSON: `detection_rules.names`). Take those rule
  queries from `packages/security_detection_engine/kibana/security_rule/`.
- **Lookup candidates:** each stream's **Lookup candidates** line names the
  exact-value filter fields to measure first.

**The workload must include Query DSL, not only ES|QL.** Dashboards are Query DSL
(filter pills, KQL query bars, the aggregations behind every panel), and EQL detection
rules are built on Query DSL and run on a schedule. ES|QL is the case *least* sensitive
to this migration; benchmarking only ES|QL measures the easy half and misses the
needle-in-a-haystack filters that decide whether the sort was chosen well.

### Run it

Index a realistic volume (weeks of data, not the handful of documents in `_dev/test/`)
into two data streams — one `logsdb`, one `logsdb_columnar` — and replay the workload
against both. Compare latency, storage size and CPU. Benchmark both `_source` modes if
Basic licenses matter: without the synthetic-source license columnar uses columnar
stored source.

### What to watch

- **Needle in a haystack is the worst case**: a single user name, IP or file hash
  filtered over a long time range, on a field outside the sort key. Without an inverted
  index this becomes a doc-value scan. Measure it explicitly.
- **Aggregations and ES|QL should be neutral to better** — they read doc values in both
  modes.
- **Storage** should drop; that is the point of the exercise.
- If a lookup field is unacceptably slow and cannot be worked into the sort key, that
  measurement is the evidence for a per-field `columnar: {index: true}`
  ([`blockers.md`](blockers.md) C5).

Elasticsearch-side improvements are in flight and will change these numbers (see the
**Current status** section of `SKILL.md`), so re-run on the next build before
concluding.
