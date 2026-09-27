# Design: making an integration columnar-ready

Draft for a follow-up skill (working name `migrate-columnar`) that takes one
package from the assessment to **columnar-ready**. Not a skill yet; nothing
here runs.

## Columnar-ready

A package is explicitly marked columnar-ready. Users then opt in to
`logsdb_columnar` through Fleet; packages without the mark stay on LogsDB.

The mark requires **every** log data stream of the package to meet the bar
below. PRs that prepare only some streams are fine, but the package is not
marked until the last one lands.

The bar, per log data stream:

1. **Index sort settled.** The sort is derived from the queries that run on the
   data (dashboards, prebuilt rules) and applies in **both** LogsDB and
   `logsdb_columnar`. Setting it therefore changes LogsDB for existing users on
   their next rollover, not only columnar opt-ins.
2. **Indexed fields decided.** Which fields get `index: true`, again from the
   queries that filter on them. Columnar leaves non-text fields unindexed by
   default; LogsDB indexes them anyway, so `index: true` is a no-op there.
   Deciding "none" is a valid outcome; it has to be an explicit decision.
3. **Columnar tests pass.** The package's tests run in CI for both LogsDB and
   `logsdb_columnar` as regular activity, not a one-off.
4. **Existing queries still work** with `logsdb_columnar`: dashboards and
   prebuilt rules return results without errors. Automated tests where they
   exist; otherwise a documented manual check. Not a strict requirement to
   automate yet.

Benchmark results are **not** part of the bar.

Metrics streams are not part of the mark. A `pending_platform` log stream
blocks the mark until its dropped fields are mapped or the platform decision
lands (see Gate A).

## Goal and boundary

The assessment answers *can this package move, and what blocks it*. The
migration skill produces **one PR per package**. The PR sets the mark when it
brings the last log stream over the bar; otherwise it prepares the streams it
covers and leaves the package unmarked.

Out of scope: repo-wide rollout, new test tooling, benchmarks, Fleet or
package-spec work, and `_source` consumer rewrites in `elastic/detection-rules`
(the skill lists them; separate PRs fix them).

## Prerequisites (blocking)

The skill cannot run end to end until these exist:

1. **Package-spec minor** that can express the mark. The index sort
   (`elasticsearch.index_template.settings`) and `index: true` on fields are
   already expressible, so preparation PRs don't depend on it.
2. **Kibana**: `REGISTRY_SPEC_MAX_VERSION` includes that minor, and Fleet shows
   the columnar opt-in for marked packages.
3. **elastic-package**: CI can run the package's system tests with the columnar
   opt-in enabled, in addition to the default LogsDB run.

Until then, the skill stops after Phase 2 and outputs the decided plan.

## Phase 1 — Assess and confirm scope

1. Run `assess_package.py packages/<pkg>`. Stop if the package verdict is
   `out_of_scope`, or if every in-scope stream is `defer_or_exclude` and the
   owner has not agreed to remap. Note which log streams already meet the bar
   from earlier preparation PRs.
2. Run `index_sort_hints.py packages/<pkg>` for the sort and indexing inputs.
3. Identify the package owner (CODEOWNERS). The PR changes LogsDB behavior
   (sort) and drops older stacks, so they review it.

## Phase 2 — Decision gates

Ask; do not edit files until every gate is answered and the plan is confirmed.

### Gate A — Streams

Which log streams does this PR prepare? If that leaves any log stream short of
the bar, the PR is a preparation PR and does not set the mark.

- `migrate_candidate`: included by default.
- `defer_or_exclude`: remap in this PR or a later one; the package stays
  unmarked until then. For nested-in-nested, the options are inner level as
  `object` or `flattened`, or keeping only the outer level nested; check
  dashboards and rules for `nested` queries on those paths first.
- `pending_platform`: map the dropped fields explicitly (then the stream is
  clean), or wait for the unmapped-field decision.
- `metrics_undecided`: not part of the mark; leave as is.

### Gate B — Index sort (per stream)

- Follow the assessment skill's
  [index sort guidance](SKILL.md#choosing-the-index-sort-at-migration-time).
- The sort applies in LogsDB too. If it differs from the LogsDB default
  (`host.name`, `@timestamp`), say so: existing users get it on rollover.
- Mapping additions the sort needs (a sort field that is not declared).
- Record the queries the choice is based on; the PR carries the rationale.

### Gate C — Indexed fields (per stream)

- Candidates: high-cardinality fields that dashboards or rules filter on by
  exact value (users, IPs, hashes, process names), outside the sort.
- Not candidates: grouping keys, leading-wildcard matches, fields covered by
  the sort.
- Output: an explicit list of `index: true` fields per stream, possibly empty.
  No LogsDB impact.

### Gate D — Stack and versions

- New `format_version` (the spec minor) and `conditions.kibana.version`. State
  which stacks lose upgrades.
- Package version bump: minor by default; major if the owner treats dropping
  8.x as breaking.
- Backport branch for the last pre-columnar-ready version, so users on dropped
  stacks can still get fixes. Create it now or on first need.

### Gate E — Query verification

- Automated coverage that exists today for the stream's queries (dashboard or
  rule tests), if any.
- Otherwise the manual check in Phase 4 and who performs it.

### Gate F — Collateral

- `_source` consumers from the assessment: list them and link their
  `detection-rules` PRs. The package PR waits only if a consumer reads a field
  this PR remaps.
- Dashboards or saved searches that query remapped paths (Gate A).
- README: the columnar opt-in and its behavioral differences (`_source` shape,
  unmapped fields).

### Gate G — Plan confirmation

One table per log stream: covered by this PR, already ready, or still open;
sort, indexed fields, mapping changes. Plus versions, collateral, and whether
the PR sets the mark. Proceed only on explicit confirmation.

## Phase 3 — Apply

1. Bump `format_version` and `conditions.kibana.version`.
2. Per covered stream: set the index sort, and add `index: true` to the chosen
   fields in `fields/*.yml`. Input packages use the root `fields/` and root
   `elasticsearch:`.
3. Apply Gate A remaps and Gate B mapping additions.
4. Set the columnar-ready mark only if every log stream now meets the bar.
5. `changelog.yml` entry (type `enhancement`) and version bump.
6. `elastic-package format`, `elastic-package lint`, `elastic-package build`.

## Phase 4 — Verify

Tests run in both modes, as CI will from now on:

| Check | LogsDB | `logsdb_columnar` |
| --- | --- | --- |
| `elastic-package test static` / `asset` | Must pass | Must pass |
| `elastic-package test pipeline` | Unchanged; no regenerated expectations | Same (pipelines run before the index mode matters) |
| `elastic-package test system` | Must pass with the new sort | Must pass; mapping errors from blockers and undeclared fields surface here |
| `sample_event.json` | Unchanged apart from sort-independent content | Not regenerated from columnar: its `_source` is flattened (dotted keys). Compare after normalizing per [reference.md](reference.md#columnar-source) |

Query verification (the fourth part of the bar), on the stack used for system
tests with columnar enabled:

- Run existing automated dashboard or rule tests, if any.
- Otherwise: open each package dashboard and check every panel renders; run
  each prebuilt rule for the stream through rule preview (KQL, EQL, ES|QL).
  Record panels or rules that error or return nothing, and why (a remapped
  field, `_source` access, a missing index).

No benchmarks.

## Phase 5 — PR

One PR per package.

- Title: `[<pkg>] Mark columnar-ready`, or `[<pkg>] Prepare <streams> for
  columnar` for a preparation PR.
- Body: streams covered, streams still open (with reasons), and whether the PR
  sets the mark; sort per stream and
  the queries behind it, including the LogsDB impact; indexed fields per stream;
  mapping changes; dropped stacks; `_source` consumers and their follow-up PRs;
  how queries were verified (automated or manual) and the results.
- Reviewers: package CODEOWNERS; Security for streams with prebuilt rules.

## Open questions

- **Spec shape**: how the mark and indexed fields are expressed. This drives
  Phase 3 entirely.
- **When to bump `format_version`**: preparation PRs only need the index sort
  and `index: true`, which older specs can already express. Bump the spec (and
  drop stacks) only in the marking PR, or in the first preparation PR?
- **Package version semantics** for dropping 8.x (Gate D default).
