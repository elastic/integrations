---
description: Draft-only triage of the whole daily run: start from today's Buildkite builds, triage what failed into the issues that track it, and sweep the backlog for stale issues (safe to run unattended)
argument-hint: "[YYYY-MM-DD, default today UTC]"
---

Triage the elastic/integrations **daily jobs** for **${ARGUMENTS:-today}**. Start from the Buildkite builds, then move to the issues that track them, then sweep the backlog. Produce **drafts only**: nothing is posted, filed, commented, closed or retried. Private CI logs and local repros are never used; they go into "Needs human" as proposals.

## 0. Setup

- Load the skill `integrations-triage:integrations-build-triage`. Set `S=<base>/scripts` and `REF=<base>/references`, follow its hard rules, and ignore its interactive-only parts (private logs gate, local repro). Read `$REF/auto-issues.md`: it explains how the daily jobs file and update issues, and every decision below depends on it.
- Run `$S/doctor.sh --unattended`. On non-zero, write `build/triage/daily/<date>/SETUP-NEEDED.md` with its output and stop.
- Run `$S/sync.sh` from the repo root: it fetches `elastic/main` and fast-forwards `main`, or moves a detached triage worktree. When the checkout is on another branch, it uses (or creates) the triage worktree `../integrations-triage-run` instead and leaves the branch alone. Its last line is `root: <path>`: **run everything after this from that path** (relative paths such as `build/triage/…` resolve there; `$S` stays absolute). On non-zero, write its output to `build/triage/daily/<date>/SETUP-NEEDED.md` and stop: never switch branches, stash or reset yourself. If it lists uncommitted changes, those package files are local edits, not upstream: say so wherever an investigation relies on them.
- `gh` and `bk` CLIs only (no GitHub/Buildkite MCP). Work from the root `sync.sh` printed. `D=build/triage/daily/<date>`.
- **Links are complete everywhere** (digest, drafts, tables): every issue/PR as a markdown link to its full URL, e.g. [#22189](https://github.com/elastic/integrations/issues/22189) or [elastic/elastic-agent#17977](https://github.com/elastic/elastic-agent/pull/17977); every build as https://buildkite.com/elastic/<pipeline>/builds/<B>. Never a bare `#N`.
- Token budget: script outputs, `.fail` files and log windows only.

## 1. Builds: what ran and where it was reported (no reasoning)

```sh
$S/daily.sh <date> $D        # builds.tsv: label, pipeline, build, state, failed_pkgs, report_mode, issues; issues.tsv
```

If it says there were no scheduler runs, reply "no daily run on <date>" and stop. Then, for each **failed** build, by `report_mode`:

| report_mode | What it means | Triage unit |
|---|---|---|
| `too-many` | More than 30 failing tests: one "Too many" issue `#N` (ecosystem) | **Issue #N**, with the per-issue flow below |
| `per-package` | 30 or fewer: one `Failing test daily` issue per failing test | **The build**, with the per-build flow below; its issues are in `issues.tsv` |
| `none` | Failed, but nothing in JUnit: setup/infra error or timeout | One line per failed job from `collect.sh` (`no-test-block` rows); no investigator unless the same job failed this way 3+ nights (`history.sh`) |
| `no-report-step` | The report step didn't run | Note it; propose checking the build |
| `running` | The build hasn't finished yet (nothing is cached) | Re-run `daily.sh` once it finishes; don't triage it before then |
| serverless `single-job:timed_out` | All packages run in one job, which timed out | Note it; per-package triage doesn't apply |

## 2. Triage the failing builds

Investigator budget for the whole run: **max 5** `cause-investigator` agents, in one message. Priority: `too-many` builds first (ecosystem's queue), then `per-package` builds by number of new or changed issues. Group by cause **across builds**: the same package failing the same way on 8.19, LogsDB and basic is one group, and one investigator. Over budget: "🔍 not investigated (budget)".

**Per issue (`too-many`)**: follow `/integrations-triage:triage-nightly` steps 1–4 for that issue (workspace `build/triage/issue-<N>`). Use `scope.env`: if `STATUS` is not `ACTIVE`, apply the superseded handling from that command.

**Per build (`per-package`)**: workspace `W=build/triage/job-<label-slug>` (lowercase, non-alphanumerics → `-`). This is the memory for that job across nights and across the per-package issues it files.

```sh
P=<pipeline> $S/collect.sh <B> $W/build-<B>
$S/match.sh $W/build-<B>/failures.tsv $W/known.tsv > $W/build-<B>/match.tsv
$S/lookup.sh $W/build-<B>/match.tsv > $W/build-<B>/lookup.md
P=<pipeline> $S/history.sh <B> 30 $W/build-<B> > $W/build-<B>/history.txt
```

- Join `match.tsv` to `issues.tsv` on the package: each failing package now has its issue numbers and whether they were `created` (new tonight) or `updated`.
- `KNOWN` rows need no reasoning. `CHANGED`, `SIG:*` and `UNKNOWN` rows go into the cross-build groups above.
- For each investigated issue, write `build/triage/issue-<n>/COMMENT_DRAFT_<date>.md`: the investigator's cause, evidence and owner, in the public comment style (`$REF/outputs.md`). If the cause is already tracked elsewhere, the draft says so and links it (a candidate for closing as a duplicate). If an issue for the same test exists under an older stack prefix, list it for closing.
- Update `$W/known.tsv` like the per-issue flow does (tests and detail from `failures.tsv`, then cause_id, cause and tracked refs; prefix `[🟡] ` / `[🔍] ` unless ✅). Put the per-package issue numbers in `tracked`.

## 3. Sweep the backlog (no reasoning)

```sh
$S/sweep.sh build/triage/sweep/<date>
```

It classifies every open auto-filed issue (SUPERSEDED, RETIRED, NOT-FAILING, QUIET, ACTIVE, UNKNOWN) and writes `close-candidates.tsv` plus `CLOSE_COMMANDS.sh` for a human to review and run. Don't re-derive its verdicts. Copy the counts and the top prefixes into the digest. For each SUPERSEDED or QUIET **"Too many"** issue, also write `build/triage/issue-<n>/COMMENT_DRAFT_close_superseded.md` from the close template in `$REF/outputs.md`.

## 4. Digest

Write `$D/DIGEST.md`, the one file the human reads first:

1. **Daily run**: the `builds.tsv` table (label, build link, state, failed packages, report mode, issues).
2. **What changed since the last daily run**: new failing packages and issues created tonight, packages that dropped out, and tracked fixes merged or closed (from `lookup.md`).
3. **Status by cause** (across builds): cause | jobs/stacks | packages | confidence | owner | existing issue/PR + status | expected outcome.
4. **New findings**: one block per investigator verdict, as returned.
5. **Backlog**: the sweep counts, close candidates by verdict and prefix, and the path to `CLOSE_COMMANDS.sh`.
6. **Proposed actions (needs human)**, as a checklist with the draft path on each item: file issue, comment, close (sweep and duplicates), approve private logs, local repro.

## 5. Reply

Five lines at most: the builds (failed/total), issues touched tonight, findings (new/known), close candidates, and the digest path.
