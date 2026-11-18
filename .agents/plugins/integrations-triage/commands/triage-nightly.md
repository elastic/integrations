---
description: Draft-only triage of one daily-job issue ("Too many packages failing" or "[pkg] Failing test daily") for its latest failed build (safe to run unattended)
argument-hint: <issue-number>
---

Triage elastic/integrations issue **#$ARGUMENTS** for its latest failed nightly build. It can be a "Too many packages failing in daily job" issue (ecosystem) or a per-package "[<pkg>] Failing test daily: <test>" issue; `scope.sh` tells which (`kind:`). For the whole daily run, use `/integrations-triage:triage-daily` instead. Produce **drafts only**: nothing is posted, filed, commented or retried. Private CI logs and local repros are never used here; they go into "Needs human" as proposals.

## 0. Setup

- Load the skill `integrations-triage:integrations-build-triage`. Its base directory is printed when it loads. Set `S=<base>/scripts` and `REF=<base>/references`. Follow its hard rules. Ignore its interactive-only parts: the private logs gate and local repro.
- Run `$S/doctor.sh --unattended`. If it exits non-zero, write `$W/DRAFT_<date>_SETUP-NEEDED.md` with its output and stop. No partial triage.
- Run `$S/sync.sh` from the repo root: it fetches `elastic/main` and fast-forwards `main`, or moves a detached triage worktree. When the checkout is on another branch, it uses (or creates) the triage worktree `../integrations-triage-run` instead and leaves the branch alone. Its last line is `root: <path>`: **run everything after this from that path** (relative paths such as `build/triage/…` resolve there; `$S` stays absolute). On non-zero, write its output to `$W/DRAFT_<date>_SETUP-NEEDED.md` and stop: never switch branches, stash or reset yourself. If it lists uncommitted changes, those package files are local edits, not upstream: say so wherever an investigation relies on them.
- Use the `gh` and `bk` CLIs (the scripts need them). Don't use GitHub/Buildkite MCP tools in this command.
- Work from the root `sync.sh` printed. `W=build/triage/issue-$ARGUMENTS`; create it if missing.
- Token budget: work from script outputs, `.fail` files and log windows only. Never print whole logs or whole reports.

## 1. Deterministic pass (no reasoning)

```sh
$S/scope.sh $ARGUMENTS $W            # writes $W/scope.env: KIND, PIPELINE, REF_BUILD (=B), STATUS, LATEST, SUCCESSOR
. $W/scope.env
# per-package issues: restrict to the issue's package (ONLY/PKGS = the line in $W/packages.txt); too-many: leave them empty
P=$PIPELINE ONLY=<pkg> $S/collect.sh $REF_BUILD $W/build-$REF_BUILD
$S/match.sh $W/build-<B>/failures.tsv $W/known.tsv > $W/build-<B>/match.tsv
$S/lookup.sh $W/build-<B>/match.tsv > $W/build-<B>/lookup.md
P=$PIPELINE PKGS=<pkg> $S/history.sh <B> 30 $W/build-<B> > $W/build-<B>/history.txt
```
Serverless (`PIPELINE=elastic/integrations-serverless`) runs all packages in one job, so `collect.sh` gives one row for the whole job. Note it and stop; the investigation is interactive.

- Read the `## triggering job:` block of the scope output first (see `$REF/auto-issues.md`):
  - `job status: SUPERSEDED` or `RETIRED`: the daily job no longer writes to this issue. Don't run the rest of the pipeline. Write `$W/COMMENT_DRAFT_close_superseded.md` (close template in `$REF/outputs.md`): the final build and its date (the last row of `nights.tsv`, **not** `updatedAt`, which bots such as the stale bot also bump), the updatecli commit/PR that moved the job, and the successor issue or, when there is none, the per-package issues it now writes to. Then write `$W/DRAFT_<date>_SUPERSEDED.md` with a one-line `[ ] Close #<n>` action, and reply "superseded by <successor or prefix>, close draft written". If the user asks for a triage of the final build anyway, run the full pipeline and put the superseded banner (outputs.md) at the top of every draft.
  - "Too many": `latest run: PASSED-TODAY`, or `FAILED-TODAY` with the "≤ CI_MAX_TESTS_REPORTED" hint: there is no new "too many" night. Reply with that verdict and stop.
  - Per-package: if the reference build isn't the latest run, `scope.sh` prints the package's state there. If it passed, run `$S/sweep.sh` (or read today's `build/triage/sweep/<date>/sweep.tsv`) and report its verdict for this issue instead of triaging an old night.
- If `$W/DRAFT_*_build-<B>.md` already exists, this build was already triaged. Write nothing new and reply "no new failing night (build <B>)".
- If `known.tsv` didn't exist (first run on this issue), every row will be SIG/UNKNOWN. That's expected.

## 2. Decide what needs reasoning

- `KNOWN`: no investigation. Its status comes from `lookup.md`. Flag it when a tracked PR **merged** ("fix merged <date>, expect it to clear once it reaches the snapshot") or a tracked issue **closed** while the package still fails ("closed but still failing: reopen?").
- `DROPPED`: list as fixed or flaky with its tracked ref, then remove the row from `known.tsv`.
- `CHANGED`, `SIG:*`, `UNKNOWN`: group packages that share a cause id or family and a similar detail. One group = one investigator.

## 3. Investigate (parallel, max 5)

Dispatch one `cause-investigator` agent per group, all in a single message. Order: UNKNOWN, then CHANGED, then SIG, largest group first. Groups beyond 5 are listed as "🔍 not investigated (budget)". Give each agent: issue #, B, `W`, `S`, the group's `match.tsv` rows, the `.fail` paths, the first-streak build and last passing build from `history.txt`, and the group's lines from `lookup.md`. Don't paste logs into the prompt.

## 4. Write the drafts

1. **`$W/DRAFT_<YYYY-MM-DD>_build-<B>.md`**: the private draft report for the human reviewer:
   - Header: build link, stack, date, elastic-package version, job totals, issue count vs failed jobs.
   - **What changed since the last night**: new, dropped, changed, and tracked fixes merged or closed.
   - **Status by cause** table: cause | packages | confidence | owner | existing issue/PR + status | expected outcome.
   - **New findings**: one block per investigator verdict, as returned.
   - **Proposed actions (needs human)**, as a checklist. Each item has a draft file where relevant:
     - `[ ] File issue in <repo>: <title>`: write `$W/ISSUE_DRAFT_<cause-id>.md` (template in `$REF/outputs.md`). Only when no existing issue covers it; otherwise propose a comment with the new evidence on that issue.
     - `[ ] Post status comment on #$ARGUMENTS`: draft below. For a per-package issue, the comment is the investigator's verdict (cause, evidence, owner), not a status table.
     - `[ ] Approve private logs: <B>/<pkg>, <log>, <what it would confirm>`
     - `[ ] Local repro: <pkg>, <what>`
     - `[ ] Reopen/close/dedupe: <ref>, <why>`
2. **`$W/build-<B>-summary.md`**: the public post-ready comment (summary template in `$REF/outputs.md`). Write it only if the cause set or statuses changed since the previous summary; otherwise write `$W/COMMENT_DRAFT_status_<date>.md` with the status template.
3. **`$W/known.tsv`**: add a row per investigated package (tests and detail copied from `failures.tsv`, plus cause_id, cause and tracked refs). Prefix the cause with `[🟡] ` or `[🔍] ` unless it was ✅.
4. **`$W/TRACKING.md`**: refresh the reference build, the package table statuses and next steps.

## 5. Reply

Five lines at most: build, packages (known/new/changed/dropped), number of proposed actions, and the draft path. No other output.
