# Validating a migrated package

Four stages: static, install, correctness, performance. Stages 1–3 are reproducible
today; stage 4 is manual.

---

## 1. Static validation

```
cd packages/<pkg>
elastic-package lint      # twice, before and after the format_version bump — see below
elastic-package build
elastic-package check
```

`build` also regenerates `docs/README.md` from `_dev/build/docs/README.md` — never edit
the generated file. It renders the README **before** it validates, so a `build` that
then fails validation has still updated `docs/README.md`: `--skip-validation` is not
needed for the docs. What a failed validation denies you is the **zip**, so
`elastic-package build --skip-validation` is for when you actually need one — an
`elastic-package install` against a stack, stage 2 below.

While the 3.7.0 spec is unreleased, validation can fail on things the migration cannot
fix: `PSR00001` for the spec version itself, or the
`https://github.com/elastic/integrations/pull/XXXXX` changelog placeholder. Skipping
validation for those is acceptable **only** when you have read the whole error list,
every entry is one of those two, and you re-run `lint`/`build` without the flag before
opening the PR. It is **never** a way past a columnar finding — see `validation.yml`
below.

**Run `build`, not just `lint`.** `lint` validates the package **source**. `build`
resolves `external: ecs` references first and validates the **built zip**. The two see
different documents, and the difference matters: in the source an `external: ecs`
reference to `event.original` carries no `doc_values` at all, while in the built
package it carries `doc_values: false`. The ECS blocker (`doc_values_false_ecs`,
~49 packages) is therefore invisible to `lint` and will fail `build` for every
affected package the moment it opts in — independent of which `format_version` it
declares.

### The spec version problem

Everything this skill writes is package-spec **3.7.0**, which is currently unreleased
(`3.7.0-next`): `format_version: "3.7.0"` itself, the stream-level
`elasticsearch.columnar.supported: true`, the field-level `columnar: {doc_values: true}`
override, and `elasticsearch.index_mode: logsdb_columnar` if you use it. A stock
`elastic-package` binary bundles an older spec and will reject all of them:

```
found 2 validation errors
  1. field format_version: Must validate one and only one schema (oneOf)
  2. field elasticsearch.index_mode: elasticsearch.index_mode must be one of the following: ...
```

The three 3.7.0 constructs also have to agree with each other, which the audit checks:
`columnar` anywhere with `format_version` below 3.7.0 is `columnar_requires_spec_3_7`
(bump `format_version`); `columnar.supported: true` on a stream that still has a Class A
finding is `columnar_supported_with_blockers`; and a field-level `columnar:` block on a
multi-field or on an `object_type` dynamic-template field is
`columnar_override_misplaced` — Fleet does not apply overrides in either place and the
spec rejects them there.

Separately, `conditions.kibana.version` has to be at least the first Kibana minor that
ships the Fleet support for these constructs, which is **9.6**: write `"^9.6.0"`.
Elasticsearch 9.5 already has the index mode, but `columnar.supported` and the
field-level `columnar` overrides are read by **Fleet**, and an older Kibana ignores
both silently.

**That constraint has a cost.** `"^9.6.0"` plus `format_version: "3.7.0"` raises the
package's **minimum stack version to 9.6**, so users on an older stack stop receiving
any further update to the package — a bug fix for them then needs a backport
branch/release line. Declare readiness only for the packages deliberately picked as
tech-preview targets.

That is a **tooling** failure, not a package failure. To validate locally, build
`elastic-package` against a local package-spec checkout:

```
cd /path/to/elastic-package
go mod edit -replace github.com/elastic/package-spec/v3=/path/to/package-spec/code/go
go mod tidy
go build -o ./elastic-package .
./elastic-package lint -C /path/to/integrations/packages/<pkg>
```

Revert with `go mod edit -dropreplace github.com/elastic/package-spec/v3`.

### `validation.yml`

Bumping `format_version` to 3.7.0 turns on validators the package never had to satisfy
before, so unrelated pre-existing problems can surface. **Lint twice, and bracket the
bump with the two runs:**

1. `elastic-package lint` on the **pristine** package, before any edit — the control.
   Whatever it reports is pre-existing under the package's current `format_version`.
2. bump `format_version` to `"3.7.0"` and nothing else, then `elastic-package lint`
   again. Every finding that is new relative to run 1 is **attributable to the spec
   jump**. Resolve them here, before any columnar edit goes in; afterwards the three
   causes are indistinguishable.

A multi-minor jump surfaces the most: taking `anthropic` from 3.4.x to 3.7.0 turned on
`SVR00008` and `SVR00009`, the ingest pipeline `on_failure` requirements, which have
nothing to do with columnar.

#### The three classes a 3.0.x → 3.7.0 jump surfaces

| Code | Finding | Treatment |
| --- | --- | --- |
| `SVR00006` | ingest processors missing a `tag` | **Many** hits — 62 on `apache`. The fix is output-neutral but purely mechanical. An **exclusion with a comment is accepted repo practice**: `akamai`, `mimecast` and `aws` each ship one. Either way, say which you chose. |
| `SVR00008` / `SVR00009` | `on_failure` handler shape (`event.kind`, `error.message`) | **Fix.** It only adds an *error* path, which the pipeline tests never take, so `*-expected.json` does not move and no `-g` is needed. |
| `JSE00001` | the `message` / `event.original` removal pattern: a `rename` of `message` → `event.original` must carry `if: ctx.event?.original == null` and be paired with a `remove` of `message` (`ignore_missing: true`, `if: ctx.event?.original != null`). The rule arrived in spec 3.1.0, so any 3.0.x package gets it. | **Not automatically cheap.** The fix **inserts a processor on the main path** — it deletes `message` from every document. It is cheap only once the placement is reasoned about: typically between the `rename` and the `grok`/`dissect` that recreates `message`, so the net output is unchanged. Prove it with `elastic-package test pipeline` **without `-g`**; a diff means the placement is wrong, and `-g` is not the answer. |

**Prefer fixing when the fix is cheap** — the `SVR00008`/`SVR00009` row is the
archetype. Exclude in `validation.yml` only what is genuinely out of scope for the PR,
with a comment explaining each one. The file lives at the package root:

```yaml
errors:
  exclude_checks:
    - SVR00006  # pre-existing: ingest pipeline processors missing required tag
    - SVR00008  # pre-existing: on_failure handler missing event.kind
```

Whatever you fix here is a **user-visible pipeline change** and needs its own
`enhancement`/`bugfix` changelog entry alongside the columnar ones — e.g. "Add
processor tags and on_failure handlers to ingest pipelines."

**Excluded checks are still printed, in full.** `lint` logs every suppressed finding
first under `Skipped errors:` (`cmd/lint.go`), and that list carries its own
`found N validation errors:` header — so a run with 62 silenced `SVR00006` hits reads
like a failure. The number that matters is in the **final**
`linting package failed: found N validation errors:` line; on a clean run there is no
such line at all.

**Never add an exclusion for a columnar validator error.** The `CodeColumnar*` codes in
`code/go/pkg/specerrors/constants.go` are:

| Code | Constant | Finding |
| --- | --- | --- |
| `SVR00011` | `CodeColumnarNestedField` | `nested` type has limited support in columnar mode |
| `SVR00012` | `CodeColumnarDynamicFalse` | `dynamic: false` causes data loss (no `_source`) |
| `SVR00013` | `CodeColumnarEnabledFalse` | `enabled: false` on an object causes data loss |

Those are the findings this whole exercise is about; silencing them ships broken data
streams.

The **hard** columnar errors — `doc_values: false`, `store: true`, `copy_to`, a
non-`lowercase` `normalizer`, mapping-level runtime fields, a type with no doc values —
have **no `SVR` code at all**. They are raised by Elasticsearch when the index
template is applied, not by a package-spec validator, so they cannot be excluded via
`validation.yml` under any circumstances. There is nothing to silence: fix them or
leave the data stream on logsdb.

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
  **But read the next subsection first**: with the tech-preview plumbing
  (`columnar.supported: true`, no `index_mode`) `logsdb` is the *correct* answer here
  and nothing has failed — the package just has not been opted in yet;
- `index.sort.field` / `index.sort.order` match the intended sort. If you relied on
  the default, verify it resolved to `host.name, @timestamp` and not to the
  `@timestamp`-only fallback (which is what happens when an existing `host.name`
  mapping is incompatible with sorting).

A template PUT that fails here is a Class A blocker the static audit missed — capture
the Elasticsearch error and report it.

### Getting a columnar index locally

`elasticsearch.columnar.supported: true` does **not** change the index mode. All it
does is tell Fleet the stream is ready, so Fleet offers the per-stream columnar opt-in
toggle; logsdb stays the default and nothing is columnar until a user turns the toggle
on. `elastic-package` has no flag that flips that toggle, so `elastic-package install`
and `elastic-package test system` against a package that only declares
`supported: true` install on **logsdb** and never exercise columnar at all — the run is
green and proves nothing about columnar.

Two ways to actually get a columnar index for the duration of the testing. Pick one:

**A. Temporarily declare the mode (simplest).** Add the index mode to the stream
manifest, keep the edit **uncommitted**, test, revert:

```
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

This is the route the diffing procedure in section 3 below uses, and it is the only
one that also exercises the install path Fleet takes when a package ships a columnar
`index_mode`.

**B. Opt in through the Fleet API after install.** Install the package unmodified,
then set the experimental data stream feature that the toggle sets, and let the data
stream roll over:

```
POST kbn:/api/fleet/epm/packages/<pkg>/<version>
{
  "experimental_data_stream_features": [
    { "data_stream": "logs-<pkg>.<ds>", "features": { "columnar": true } }
  ]
}
```

Closer to what a real user does — it goes through exactly the Fleet toggle path,
including the code that applies the field-level `columnar:` overrides — but it needs a
Kibana with the Fleet support (see `conditions.kibana.version` above) and it leaves the
already-created backing index on the old mode, so force a rollover
(`POST logs-<pkg>.<ds>/_rollover`) and check `index.mode` on the **new** backing index.

> **Footnote — the opt-in requests a *lazy* rollover.** Fleet does not create the new
> backing index when the toggle is turned on; it marks the data stream to roll over on
> the **next indexed document**. So `GET _data_stream/logs-<pkg>.<ds>` can still show
> the old generation, and the old `index.mode`, long after the opt-in succeeded —
> which looks exactly like the opt-in having failed. **Verify with a write**, not by
> reading the generation number: index one document (or let the agent ship one), then
> re-read `GET logs-<pkg>.<ds>/_settings` and look at the newest backing index. An
> explicit `POST .../_rollover` forces the same thing immediately.

Either way, re-run the `GET _settings` check above and confirm `index.mode` is
`logsdb_columnar` before believing any correctness or performance result.

---

## 3. Correctness

Run the package's own tests **with and without** columnar and diff the results.

The "with columnar" half needs one of the two routes from
[Getting a columnar index locally](#getting-a-columnar-index-locally) — the shipped
`columnar.supported: true` is not enough on its own, and if you skip that step both
halves run on logsdb and the diff is empty for the wrong reason. Using route A, with
the temporary `index_mode: logsdb_columnar` edit uncommitted in the working tree:

```
git stash                                 # remove the temporary index_mode: logsdb_columnar
elastic-package test pipeline  2>&1 | tee /tmp/pipeline-logsdb.txt
elastic-package test system    2>&1 | tee /tmp/system-logsdb.txt
git stash pop                             # put it back
elastic-package test pipeline  2>&1 | tee /tmp/pipeline-columnar.txt
elastic-package test system    2>&1 | tee /tmp/system-columnar.txt
diff /tmp/pipeline-logsdb.txt /tmp/pipeline-columnar.txt
```

Then drop the temporary edit for good (`git checkout -- data_stream/<ds>/manifest.yml`)
and make sure it is not in the commit: shipping `index_mode: logsdb_columnar` makes
columnar the **default** for every new install of the version, which is a different
decision from declaring the stream ready.

### Pipeline tests: the output must be identical

`elastic-package test pipeline` posts the documents to
`_ingest/pipeline/_simulate` (`internal/testrunner/runners/pipeline/tester.go` →
`internal/elasticsearch/ingest/pipeline.go`) and compares the simulated result with
`data_stream/<ds>/_dev/test/pipeline/*-expected.json`. **Nothing is ever indexed.**
There is no index, no index template and no index mode involved, so
`index_mode: logsdb_columnar` cannot change the output by construction.

Consequences:

- **When the index mode is the only difference between the two runs**, they must
  produce **identical**
  pipeline results. Any diff is a real bug in the change, or pre-existing test
  nondeterminism (a timestamp, a generated id) — never an expected columnar effect.
  `-g` should never be needed, and if you feel the urge to regenerate expectations,
  stop: you are about to bake something else into the repo.
- **When the migration also applied an auto-fix that touches the pipeline**, the
  output legitimately changes and `-g` is the correct tool. Two of the mechanical
  fixes do this:
  - `copy_to` → a `set`/`append` processor: the copied field now appears in the
    simulated document, because the copy happens at ingest instead of at mapping
    time;
  - a non-`lowercase` `normalizer` → a `lowercase` (or `gsub`) processor: the value
    is normalised in the document rather than only in the index.

  Regenerate with `elastic-package test pipeline -g`, then **read every hunk** of the
  resulting diff. The only fields that may move are the ones the auto-fix touched;
  anything else in the diff is a bug in the fix. Say so explicitly in the PR
  description, and keep the regeneration in its own commit so a reviewer can see the
  expectation churn separately from the manifest change.

### System tests: where the shape changes show up

System tests are the only stage that indexes anything, so they are the only stage the
index mode can affect — and therefore the only stage that is worth running twice. That
also makes them the stage that silently tells you nothing if the columnar half was
never actually columnar: confirm `index.mode` on the backing index (section 2) before
reading the diff.

Synthetic source is only observable once documents are actually indexed, i.e. in
system tests, or by installing the package twice (one data stream on `logsdb`, one on
`logsdb_columnar`), ingesting the same documents and diffing `GET _search` output.

Expected differences **in indexed documents**:

| Difference | Example | Why |
| --- | --- | --- |
| `_source` keys are **dotted**, not nested objects | `{"event.id": "abc", "anthropic.audit.actor.type": "user_actor"}` instead of `{"event": {"id": "abc"}}` | Synthetic source is reconstructed from doc values, which are flat. `geo_point` is the exception and still returns `{lat, lon}` |
| **Single-element arrays collapse to scalars** | `event.category: ["web"]` reads back as `"web"` | logsdb keeps the array via `index.mapping.synthetic_source_keep: arrays`, a setting columnar does not support. Seen on `event.category`, `event.type`, `related.ip`, `related.hosts`, `anthropic.audit.scopes` |
| Arrays of objects lose their per-object grouping | `[{a:1,b:2},{a:3,b:4}]` → `{a:[1,3], b:[2,4]}` | Object arrays are not retained faithfully |
| Multi-value arrays keep ingest order instead of being sorted/de-duplicated | | Columnar preserves original order; plain logsdb synthetic source sorts and dedupes |
| A field under `dynamic: false` disappears | | Class B data loss — must already have been reviewed |
| A keyword with `normalizer: lowercase` comes back lowercased | | Class C4 — the original casing is not stored |

The first four rows are the **complete** expected-diff set for a package with no Class
B finding: dotted keys, collapsed single-element arrays, parallel object arrays,
preserved order. Measured on `anthropic` — the same mock data indexed in both modes, 8
documents matched on `event.id`, **zero value differences**, shape only.

**Who is affected by the first two.** Anything doing *nested* access on the source
breaks: `_source.event.id`, Painless `params._source.event.id`, ES|QL
`JSON_EXTRACT(_source, "event.id")` paths, Kibana code walking the object. Anything
indexing into an array (`event.category[0]`) or asserting a list type has to tolerate
a scalar. **Field-level access is unaffected** — `doc[...]`, KQL, aggregations, ES|QL
columns, dashboards and alerting rules that query fields all behave identically.

### Comparing the two modes

```
# 1. logsdb baseline
elastic-package test system --defer-cleanup 4m
#    during the deferral window, against the test stack:
#    GET logs-<pkg>.<ds>-*/_search?size=100      -> save as logsdb.json

# 2. same again with a TEMPORARY index_mode: logsdb_columnar in the stream manifest
#    (route A above, uncommitted)
elastic-package test system --defer-cleanup 4m
#    GET logs-<pkg>.<ds>-*/_search?size=100      -> save as columnar.json
```

`--defer-cleanup` keeps the data stream alive long enough to snapshot it; without it
the documents are deleted before you can read them. Match the documents across the two
snapshots on a **flattened** `event.id` (the columnar half has dotted keys, so compare
`doc.get("event.id") or doc["event"]["id"]`), then classify every difference into the
four classes above. A difference that fits none of them is a bug.

### Anything else is a bug

Report it with the package, data stream, the input document and the two indexed
documents. Specifically not expected: values changing, numeric precision loss,
`null`/empty-string confusion, dropped fields that *are* explicitly mapped, or
`ignore_malformed` behaviour differences.

System tests additionally exercise the dashboards' fields — a system test failure that
is not in the table above usually means a mapping the audit classified as READY is
actually lossy.

---

## 4. Performance

Manual for now. There is no harness in this skill; the audit only extracts the
workload.

### Build the workload

`scripts/audit.py <package>` prints a ranked list of the field names referenced by the
package's Kibana assets under **"Dashboard fields"**. That list, plus the package's
detection rules, alerts and SLOs, is the query workload to replay. Sources:

- `kibana/dashboard/*.json`, `kibana/lens/*.json`, `kibana/search/*.json`
- `kibana/ml_module/*.json`
- the detection rules that reference `logs-<pkg>.<ds>-*` (these live in
  `elastic/detection-rules`, not in this repo)

**The workload must include Query DSL, not only ES|QL.** Two kinds of query dominate
the real load on these indices and neither is ES|QL:

- **dashboards**, which are Query DSL — filter pills, KQL query bars and the
  aggregations behind every panel;
- **EQL detection rules**, which are **built on Query DSL** and run on a schedule
  against the same indices.

ES|QL is the case that is *least* sensitive to this migration: it reads doc values, so
the `_source` shape does not reach it — the exception being a query that explicitly
asks for `METADATA _source` (see [`blockers.md`](blockers.md) C6-C8). Benchmarking only
ES|QL therefore measures the easy half of the workload and misses the needle-in-a-
haystack Query DSL filters that decide whether the index sort was chosen well.

**Solution workloads have to be added by hand.** The detection rules that query an
integration's data streams are **not shipped in the integration package** — they live
in `elastic/detection-rules` and reach users through the `security_detection_engine`
package — so neither `scripts/audit.py` nor anything else in this repo can enumerate
them for you. (Four of them already use `FROM ... METADATA _source` against
`logs-network_traffic.sip-*`, `logs-network_traffic.nfs-*` and `logs-gcp.audit-*`.)
Search `elastic/detection-rules` for the data stream, take the EQL and KQL rules plus
the Security and Observability solution views that read the stream, and add them to
the replay set explicitly.

### Run it

Index a realistic volume (weeks of data, not the handful of documents in
`_dev/test/`) into two data streams — one `logsdb`, one `logsdb_columnar` — and replay
the workload against both. Compare latency, storage size and CPU.

### What to watch

- **Needle in a haystack is the worst case**: a single user name, IP or file hash
  filtered over a long time range, where the field is not in the sort key. Without an
  inverted index this becomes a doc-value scan. Measure this case explicitly; it is
  the one that decides whether the sort key was chosen well.
- **Aggregations and ES|QL should be neutral to better** — they read doc values in
  both modes and benefit from the improved compression. This is why they cannot be
  the whole workload: measure the Query DSL and EQL side, which is where the
  regression would be.
- **Storage** should drop noticeably; that is the point of the exercise.
- If a specific field is unacceptably slow and cannot be worked into the sort key,
  record it as benchmark evidence for a future per-field `index: true` decision. Do
  **not** add `index: true` pre-emptively — that decision is made from measurements,
  never from static analysis.

Elasticsearch-side improvements are in flight and will change these numbers: keyword
skippers in 9.7, bloom filters after GA.
