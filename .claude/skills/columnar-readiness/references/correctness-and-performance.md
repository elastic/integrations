# Validating a migrated package

Four stages: static, install, correctness, performance. Stages 1–3 are reproducible
today; stage 4 is manual.

---

## 1. Static validation

```
cd packages/<pkg>
elastic-package lint
elastic-package check
```

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

**Never add an exclusion for a columnar validator error** (`SVR00013`,
`SVR00014`, … — the `CodeColumnar*` codes). Those are the findings this whole exercise
is about; silencing them ships broken data streams.

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

Pipeline tests run the ingest pipeline and compare against
`data_stream/<ds>/_dev/test/pipeline/*-expected.json`. Regenerate with:

```
elastic-package test pipeline -g
```

Regenerate **only after** you have reviewed the diff and confirmed every change is on
the expected list below. `-g` overwrites the expectations, so it will happily bake a
real regression into the repo.

### Expected diffs

| Diff | Why |
| --- | --- |
| Objects appear flattened (`a.b.c` instead of nested objects) | Synthetic source is reconstructed from doc values |
| Arrays of objects lose their per-object grouping | Object arrays are not retained faithfully |
| Multi-value arrays keep ingest order instead of being sorted/de-duplicated | Columnar preserves original order; plain logsdb synthetic source sorts and dedupes |
| A field under `dynamic: false` disappears | Class B data loss — must already have been reviewed |

### Anything else is a bug

Report it with the package, data stream, the input document and the two expected
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
