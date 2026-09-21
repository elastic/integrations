# Validating a migrated package

Four stages: static, install, correctness, performance. Stages 1–3 are reproducible
today; stage 4 is manual.

---

## 1. Static validation

```
cd packages/<pkg>
elastic-package lint
elastic-package build
elastic-package check
```

**Run `build`, not just `lint`.** `lint` validates the package **source**. `build`
resolves `external: ecs` references first and validates the **built zip**. The two see
different documents, and the difference matters: in the source an `external: ecs`
reference to `event.original` carries no `doc_values` at all, while in the built
package it carries `doc_values: false`. The ECS blocker (`doc_values_false_ecs`,
~49 packages) is therefore invisible to `lint` and will fail `build` for every
affected package the moment it opts in — independent of which `format_version` it
declares.

### The spec version problem

`elasticsearch.index_mode: logsdb_columnar` and `format_version: "3.7.0"` are
package-spec **3.7.0**, which is currently unreleased (`3.7.0-next`). A stock
`elastic-package` binary bundles an older spec and will reject both:

```
found 2 validation errors
  1. field format_version: Must validate one and only one schema (oneOf)
  2. field elasticsearch.index_mode: elasticsearch.index_mode must be one of the following: ...
```

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
before, so unrelated pre-existing problems can surface. Those may be excluded in
`validation.yml`, with a comment explaining each one.

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
  data stream silently stays on logsdb and every later measurement is meaningless;
- `index.sort.field` / `index.sort.order` match the intended sort. If you relied on
  the default, verify it resolved to `host.name, @timestamp` and not to the
  `@timestamp`-only fallback (which is what happens when an existing `host.name`
  mapping is incompatible with sorting).

A template PUT that fails here is a Class A blocker the static audit missed — capture
the Elasticsearch error and report it.

---

## 3. Correctness

Run the package's own tests **with and without** the opt-in and diff the results.

```
git stash                                 # remove index_mode: logsdb_columnar
elastic-package test pipeline  2>&1 | tee /tmp/pipeline-logsdb.txt
elastic-package test system    2>&1 | tee /tmp/system-logsdb.txt
git stash pop
elastic-package test pipeline  2>&1 | tee /tmp/pipeline-columnar.txt
elastic-package test system    2>&1 | tee /tmp/system-columnar.txt
diff /tmp/pipeline-logsdb.txt /tmp/pipeline-columnar.txt
```

### Pipeline tests: the output must be identical

`elastic-package test pipeline` posts the documents to
`_ingest/pipeline/_simulate` (`internal/testrunner/runners/pipeline/tester.go` →
`internal/elasticsearch/ingest/pipeline.go`) and compares the simulated result with
`data_stream/<ds>/_dev/test/pipeline/*-expected.json`. **Nothing is ever indexed.**
There is no index, no index template and no index mode involved, so
`index_mode: logsdb_columnar` cannot change the output by construction.

Consequences:

- **When `index_mode` is the only change**, the two runs must produce **identical**
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

Synthetic source is only observable once documents are actually indexed, i.e. in
system tests, or by installing the package twice (one data stream on `logsdb`, one on
`logsdb_columnar`), ingesting the same documents and diffing `GET _search` output.

Expected differences **in indexed documents**:

| Difference | Why |
| --- | --- |
| Objects appear flattened (`a.b.c` instead of nested objects) | Synthetic source is reconstructed from doc values |
| Arrays of objects lose their per-object grouping | Object arrays are not retained faithfully |
| Multi-value arrays keep ingest order instead of being sorted/de-duplicated | Columnar preserves original order; plain logsdb synthetic source sorts and dedupes |
| A field under `dynamic: false` disappears | Class B data loss — must already have been reviewed |
| A keyword with `normalizer: lowercase` comes back lowercased | Class C4 — the original casing is not stored |

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
  both modes and benefit from the improved compression.
- **Storage** should drop noticeably; that is the point of the exercise.
- If a specific field is unacceptably slow and cannot be worked into the sort key,
  record it as benchmark evidence for a future per-field `index: true` decision. Do
  **not** add `index: true` pre-emptively — that decision is made from measurements,
  never from static analysis.

Elasticsearch-side improvements are in flight and will change these numbers: keyword
skippers in 9.7, bloom filters after GA.
