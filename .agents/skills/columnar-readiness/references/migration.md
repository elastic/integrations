# Migrating a package

Only when asked. Readiness is declared for the package (`elasticsearch.logsdb_columnar:
opt_in`); every logs data stream takes it unless its own manifest says
`logsdb_columnar: unsupported`, which is what the streams that are not `READY` (or
`READY_AFTER_AUTO_FIX` once the fix is applied) get. Do the steps **in this order**: the
two `lint` runs come first on purpose, so every finding is attributable to exactly one
cause.

## Contents

- When a stream counts as ready
- Checklist
- 1. Baseline `lint`
- 2. Bump `format_version`, `lint` again (the spec-jump findings)
- 3. Mechanical fixes
- 4. Manifests: `logsdb_columnar` and the sort
- 5. Root manifest: Kibana floor and major bump
- 6. Changelog
- 7. Build and check
- The cost of declaring readiness
- Local tooling

## When a stream counts as ready

A logs data stream takes the package's `opt_in` unless it is marked `unsupported`, so
leave it unmarked only when all of these hold:

1. **No blocker, and every review item looked at**: the audit's `_source` consumers and
   Detection rules lines are quoted in the PR, including the negative results.
2. **Index sort settled**, from the queries the stream's dashboards and rules run. The
   sort applies to logsdb installs too, at their next rollover, so say so.
3. **Indexed fields decided**: an explicit list of `index: true` fields, possibly
   empty, each with the query that needs it (rollout rule 2).
4. **Tests pass in both modes**: `test pipeline` and `test static` as usual, and system
   tests on a columnar index (routes A to C in
   [`correctness-and-performance.md`](correctness-and-performance.md)).
5. **Existing queries still work** on columnar: the dashboards, the stream's direct
   detection rules, and the package's alerting rule and SLO templates return the same
   results as on logsdb. Automated where a test exists, otherwise a manual check
   recorded in the PR.

Performance numbers are not part of this bar; they decide whether columnar becomes a
default later, not whether the opt-in may be offered. A package can declare its ready
streams and leave the others for a later PR.

## Checklist

Copy it into the working notes and tick it off:

```
Columnar migration: <pkg>
- [ ] 1. Baseline `elastic-package lint` on the untouched package; keep the output
- [ ] 2. `format_version: "3.7.0"` only, `lint` again, resolve every new finding
- [ ] 3. Mechanical fixes from the audit (Class A auto_fix findings)
- [ ] 4. Sort (if proposed) per stream; `logsdb_columnar: unsupported` on the streams
        that stay on LogsDB; `elasticsearch.logsdb_columnar: opt_in` in the root manifest
- [ ] 5. `conditions.kibana.version: "^9.6.0"` + major version bump
- [ ] 6. Changelog: breaking-change + enhancement (+ one for pipeline fixes)
- [ ] 7. `lint`, `build`, `test pipeline`, `test static`; re-run the audit: the
        Package readiness line shows `opt_in`
```

## 1. Baseline `lint`

```bash
cd packages/<pkg>
elastic-package lint          # pristine package, current format_version
```

Keep the output. It is the control: whatever it reports is pre-existing under the
`format_version` the package already declares and has nothing to do with columnar.

## 2. Bump `format_version`, `lint` again

Change `format_version` to `"3.7.0"` in the root `manifest.yml` — that one line,
nothing else — and lint again. A multi-minor jump turns on every validator added in
between, and they fire on code that was already there (`anthropic` went 3.4.x → 3.7.0
and surfaced `SVR00008`/`SVR00009`). **Every new finding is attributable to the spec
jump**; resolve them now, while the package has no columnar edits in it.

A 3.0.x → 3.7.0 jump surfaces three classes:

| Code | Finding | Treatment |
| --- | --- | --- |
| `SVR00006` | ingest processors missing a `tag` | many hits (62 on `apache`); output-neutral but tedious. An exclusion with a comment is accepted repo practice (`akamai`, `mimecast`, `aws`). Fix or exclude, and say which in the PR. |
| `SVR00008` / `SVR00009` | `on_failure` handler shape (`event.kind`, `error.message`) | **Fix them.** Only the error path changes, which pipeline tests never take, so `*-expected.json` does not move. It is still a user-visible change for failed documents: add a changelog entry (step 6). |
| `JSE00001` | a `rename` of `message` → `event.original` must be guarded by `if: ctx.event?.original == null` and paired with a `remove` of `message` (`ignore_missing: true`, `if: ctx.event?.original != null`) | **Reason about it first.** The fix inserts a processor on the main path. Place it between the `rename` and the `grok`/`dissect` that recreates `message`, then prove it with `elastic-package test pipeline` **without `-g`**: green means neutral. |

`validation.yml` lives at the package root, one comment per exclusion:

```yaml
errors:
  exclude_checks:
    - SVR00006  # pre-existing: ingest pipeline processors missing required tag
```

**Never exclude a columnar finding** — `SVR00014` (`dynamic: false`), `SVR00015`
(`enabled: false`), or a hard mapping error (nested-in-nested, `copy_to`, a non-`lowercase`
normalizer, a mapping-level runtime field, an invalid `index.sort`: those have no code and
cannot be excluded). **Excluded checks still print**, under
`Skipped errors:` with their own `found N validation errors:` header; the count that
matters is the **final** `linting package failed: found N validation errors:` line,
and a clean run has none.

## 3. Mechanical fixes

The audit prints a **Suggested change** (file, position, snippet) for most of these;
paste it rather than writing your own. Pipeline processors go inline where the change
needs them, tagged `columnar_*`, never in a separate "columnar" pipeline file (a
pipeline runs in every index mode, see SKILL.md).

- `copy_to` → the suggested `script` processor (tag `columnar_copy_<field>`), which
  appends to the targets like `copy_to` does; then delete `copy_to` from the field.
- A non-`lowercase` `normalizer` → the suggested normalized multi-field, or a pipeline
  processor when the original value is not needed.
- A mapping-level runtime field → port the suggested `script` skeleton, then map a
  concrete type.
- `dynamic: runtime` → `dynamic: true`.
- A `latest` transform over the stream → the suggested `dot_expander` as the first
  processor of its destination pipeline (in the package that owns the transform).
- Objects inside a `nested` field → the suggested dotted-key `script` processor (tag
  `columnar_nested_dotted_<field>`), if that is the option picked.

Not package fixes: `doc_values: false` (declared, or inherited from `external: ecs`) and
`store: true` wait on Elasticsearch or Fleet (package-spec#1250 review). Leave those
fields alone; the stream stays BLOCKED and gets `logsdb_columnar: unsupported` (step 4).

The `copy_to`, normalizer and nested dotted-key fixes change what the pipeline emits,
so pipeline test expectations have to be regenerated (step 7). Blocked streams (`nested_in_nested` and
the other `blocker` findings) are not mechanical: see [`blockers.md`](blockers.md) A1
for the nested options, or mark the stream `unsupported`.

## 4. Manifests: `logsdb_columnar` and the sort

**Data stream manifests.** An `unsupported` override and the index sort are children of
the manifest's **single** `elasticsearch:` key, so write them as one block. **Look at
the manifest first**:

- it **already has** an `elasticsearch:` key → **merge** these children into it. A
  second `elasticsearch:` is a duplicate key: YAML does not error, it keeps one of them;
- it has **no** `elasticsearch:` key (`nginx` `access` and `error`) → **add** it as a
  new top-level key, conventionally after `streams:`.

The audit's **Stream manifest** line says which one applies, and what goes in:

```yaml
elasticsearch:
  logsdb_columnar: unsupported   # only for a stream that stays on LogsDB
  index_template:                # only when an explicit sort was proposed
    settings:
      index:
        sort:
          field: ["<field>", "@timestamp"]
          order: ["asc", "desc"]
```

With the default sort (`host.name asc, @timestamp desc`) the `index_template` half is
omitted. An explicit sort lands in the `@package` component template, so it applies to
LogsDB and standard installs too, not only to columnar opt-ins; mention it in the
changelog. If the manifest already declares an explicit `index.sort`, leave it alone
unless the dataset says otherwise.

A stream with a remaining blocker gets `unsupported`: the validator checks every logs
data stream that ends up ready, and fails the build otherwise. A stream whose
`_source` consumer review (C6-C10) is not done is not ready either: a detection rule, a
transform or a runtime field reading `_source` does not fail, it quietly gets a
different shape.

**The root manifest.** Then declare the package, as the audit's **Package readiness**
line shows:

```yaml
elasticsearch:
  logsdb_columnar: opt_in
```

Write `opt_in` for the tech preview: Fleet offers one toggle for the integration, and
LogsDB stays the default. `default` (columnar for new installations) is for later.

**There is no `index_mode: logsdb_columnar`.** `index_mode` is for a fixed mode the user
cannot change (`time_series`), and setting it together with `logsdb_columnar` fails
validation.

## 5. Root manifest: Kibana floor and major bump

Set `conditions.kibana.version: "^9.6.0"` and bump the **major** version.

**Replace the whole range** — do not add a branch to it. A package on
`"^8.19.0 || ^9.1.0"` becomes `"^9.6.0"`: every `||` branch has to be 9.6+, because a
single older branch is what lets Fleet keep offering this version to a stack that
ignores the setting. If the package has to keep serving older stacks, do
not declare readiness on this release line.

The constraint is about **Fleet**, not Elasticsearch (9.5 already has the index mode):
Fleet parses `elasticsearch.logsdb_columnar` to offer the toggle, and an older Kibana
silently ignores it.

**Why a major bump.** elastic/integrations treats a Kibana floor raise as a breaking
change with a major version: `aws` 7.0.0, `aws_bedrock` 2.0.0, `aws_bedrock_agentcore`
1.0.0. It also reserves the previous major for backports. (Whether the changelog entry
should be `breaking-change`, which makes Fleet show "Action required" to 9.6+ users who
are not affected, is an open team decision; follow the precedent until it is settled.)

## 6. Changelog

A new entry at the top with **at least two** changes, the breaking one first, each with
a placeholder link the user must replace:

```yaml
- version: "<new major version>"
  changes:
    - description: Raise the minimum required Kibana version to 9.6.0 (drops support
        for Kibana 8.x and 9.x below 9.6.0), required for columnar index mode support.
      type: breaking-change
      link: https://github.com/elastic/integrations/pull/XXXXX
    - description: Declare LogsDB columnar support (logsdb_columnar opt_in), enabling
        the integration's LogsDB columnar opt-in in Fleet (tech preview).
      type: enhancement
      link: https://github.com/elastic/integrations/pull/XXXXX
```

Say *declare support for*: the package only sets `logsdb_columnar: opt_in`. Marking a
stream `unsupported` in a later version, once it was ready, is a breaking change of its
own: Fleet moves it back to LogsDB at the next rollover, so it needs a major bump and a
`breaking-change` entry. Add **one
more entry** for anything fixed in step 2 or 3 that changes what the pipeline does
(`on_failure` handlers, a `JSE00001` `remove`, a `copy_to` moved into the pipeline):

```yaml
    - description: Add processor tags and on_failure handlers to ingest pipelines.
      type: enhancement
      link: https://github.com/elastic/integrations/pull/XXXXX
```

## 7. Build and check

```bash
cd packages/<pkg>
elastic-package lint           # third run: now it also covers your edits
elastic-package build          # regenerates docs/README.md, validates the built zip
elastic-package test pipeline  # no -g unless an auto-fix touched the pipeline
elastic-package test static
```

- **This `lint` is the third run.** Anything new here was caused by the columnar edits:
  fix it, do not reach for `validation.yml`.
- **`build` is not optional.** It validates the built zip, the only place the resolved
  ECS attributes exist (an ECS-imported `doc_values: false` only shows there).
- **`docs/README.md` is generated by `build`** from `_dev/build/docs/README.md`; never
  edit the generated file. `build` renders the README before it validates.
- **`--skip-validation`** is acceptable **only** for a local `elastic-package install`,
  and only when every remaining error is one of the two things this migration cannot
  fix yet: `PSR00001` (a GA version on the unreleased 3.7.0 spec) or the
  `pull/XXXXX` changelog placeholder. Re-run without it before the PR. Never use it to
  get past a columnar finding.
- **`test pipeline` with no `-g`**, unless a `copy_to`, normalizer or nested dotted-key
  fix moved logic into the pipeline; then regenerate and read every hunk.
- **Re-run the audit.** The Package readiness line now shows `opt_in`, and each
  `unsupported` stream's Stream manifest line reads "already present".

Then validate on a stack: [`correctness-and-performance.md`](correctness-and-performance.md).

## The cost of declaring readiness

Declaring readiness **raises the package's minimum stack version to 9.6**. Fleet does
not offer the new version to anything older, so every user on 9.5 or below stops
receiving *any* further update to the package, security and unrelated bug fixes
included. Fixing a bug for them requires a **backport**: a separate release line off
the last pre-9.6 version. Two mechanisms enforce the floor: `conditions.kibana.version`,
and `format_version: "3.7.0"`, which Kibana's registry `spec.max` filters.

That is a permanent, per-package maintenance commitment. Declare readiness
**deliberately, for the packages chosen as tech-preview targets**, never across the
catalog because the audit says `READY`: `READY` means "no mapping blocker", not "worth
the 9.6 floor". Say this to the user before writing the change.

## Local tooling

package-spec 3.7.0 is unreleased, so a stock `elastic-package` rejects
`format_version: "3.7.0"` and `elasticsearch.logsdb_columnar`. The local package-spec
checkout also has to carry the `logsdb_columnar` shape from the
elastic/package-spec#1250 review: until that PR is reworked, its branch still has the
earlier `columnar.supported` design and rejects the setting too.

Build `elastic-package` against a local package-spec checkout:

```bash
cd /path/to/elastic-package
go mod edit -replace github.com/elastic/package-spec/v3=/path/to/package-spec
go mod tidy
go build -o ./elastic-package-columnar .
./elastic-package-columnar lint -C /path/to/integrations/packages/<pkg>
```

Revert with `go mod edit -dropreplace github.com/elastic/package-spec/v3`. Stack tests
also need a Kibana with the Fleet support:
[`correctness-and-performance.md`](correctness-and-performance.md#kibana-with-the-fleet-support).
