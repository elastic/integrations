---
name: integrations-build-triage
description: Investigate why packages failed in an elastic/integrations Buildkite run (daily "Check integrations local stacks" / serverless / basic subscription jobs, or a PR build), triage the auto-filed issues they produce ("Too many packages failing in daily job" and per-package "Failing test daily"), sweep the backlog for stale or superseded issues, deep-dive one root cause, check whether tracked fixes have rolled out, and draft status comments and owner issues. Use when given a Buildkite build URL/number, or an auto-filed issue like "[Stack X-SNAPSHOT] Too many packages failing in daily job" / "Failing test daily", or when asked "why did these packages fail", "triage this build", "investigate this cause", "is there an issue for this", "when will the fix roll out", "status update for the issue".
---

# Integrations build triage

Group failing packages by **root cause**, name **who fixes each cause**, back each with **one line of evidence**, and keep it tracked until the fix rolls out.

## Two outputs, two audiences

| Output | Audience | Form |
|---|---|---|
| **Summary comment** `build-<B>-summary.md` | **Public**: the auto-filed issue (owners, other teams) | Post-ready markdown. The user posts it. This is *the* deliverable of a triage. Owner issue drafts follow the same public rules. |
| **Investigation report** `build-<B>-report.md` | **Private**: the user running the investigation | Published as a **private Artifact** (claude.ai page). Full detail: evidence, timelines, private-log findings, dead ends, confidence. Never pasted into GitHub. |

Report as an artifact:
- Before the first publish, load `artifact-design`. This skill explicitly asks for the report to be published as **Markdown** (`file_path` = the `.md`), so the single source stays greppable and cheap to edit section by section.
- Record the artifact URL at the top of TRACKING.md.
- After every change (new build, deep dive, correction), republish **to the same URL**. In the same conversation, use the same `file_path`. In a later conversation, `Artifact action:"read"` the URL first, then publish with `url`. Never create a second report artifact for the same build.
- The report may hold private-log findings because the artifact is private, but never secrets or tokens. Don't suggest sharing its link publicly.

Unattended/draft-only runs use the commands and the `cause-investigator` agent: `/integrations-triage:triage-daily [date]` covers the whole daily run (builds → the issues they reported to → backlog sweep), and `/integrations-triage:triage-nightly <issue>` covers one issue, "Too many" or per-package. This skill is the playbook for interactive sessions, and it works for both issue kinds.

**Which issue, which unit.** A failing daily build reports to one "Too many packages failing" issue (more than 30 failing tests; ecosystem's queue), or to one `[<pkg>] Failing test daily: <test>` issue per failing test (package owners). `$S/daily.sh` maps each build to its issues, and `scope.sh` prints `kind:` for an issue. Per-package issues: pass `-k <pkg>` to `collect.sh` and `history.sh`. Serverless builds (`P=elastic/integrations-serverless`) run every package in one job. See auto-issues.md.

**Backlog hygiene.** `$S/sweep.sh` classifies every open auto-filed issue (SUPERSEDED, RETIRED, NOT-FAILING, QUIET, ACTIVE) and writes `CLOSE_COMMANDS.sh` for the human to run. When asked "what's stale", run it instead of reasoning issue by issue.

References (load only when needed): how the daily jobs file/update issues (read when an issue looks stale or superseded) [references/auto-issues.md](references/auto-issues.md) · commands [references/commands.md](references/commands.md) · known causes [references/failure-signatures.md](references/failure-signatures.md) · output templates [references/outputs.md](references/outputs.md). Improvement backlog: ROADMAP.md at the plugin root (not needed to run a triage).

## Workspace

All files live in `build/triage/` (gitignored): `issue-<n>/` per issue, `job-<label-slug>/` per daily job (the per-build memory for per-package nights), `daily/<date>/` (daily.sh output and DIGEST.md), `sweep/<date>/`, and `cache/` (job states and report-step results per build; safe to delete). Fixed names, so any session can resume:

| File | Purpose |
|---|---|
| `TRACKING.md` | **Single source of truth.** Report artifact URL, reference build, one row per package (cause, issue, status), delta vs earlier nights, next steps. Read this first in every session. |
| `build-<B>-report.md` | Private report source (published as the artifact). One `## N.` section per cause. Grows with deep dives. |
| `build-<B>-summary.md` | Public summary comment. Status blocks are added **under the matching item**, not in new files. |
| `known.tsv` | Memory for `match.sh`: package → tests, detail, cause_id, cause, tracked refs. Update it whenever a cause is confirmed or changes. |
| `DRAFT_<date>_build-<B>.md` | Unattended run output: delta, status by cause, proposed actions. |
| `ISSUE_DRAFT_<topic>.md` / `COMMENT_DRAFT_<topic>.md` | Drafts for the user to post. |
| `build-<B>/` | Script output (logs, failures.tsv, match.tsv, lookup.md, history). `runs/` holds unattended run logs. |

## Hard rules

- **Never post, comment, pin, file or retry** anything (GitHub, Buildkite). Draft it; the user posts it. "Post/pin a status" means: add a draft block under that item in the summary.
- Setup: run `$S/doctor.sh` once per session; it checks the required `gh`, `bk`, `jq`, `yq` and the optional gcloud, elastic-package, docker and MCP, and prints fixes.
- `bk` CLI for Buildkite (org `elastic`, pipeline `integrations`) and `gh` CLI for GitHub. These are required, because the scripts pipe and cache their output. The GitHub/Buildkite MCP servers (Docker MCP gateway) are an optional interactive fallback with **separate tokens**: a working `gh` doesn't mean MCP works, and vice versa. MCP output lands in context, so prefer the CLIs. No WebFetch.
- **Private logs (`gs://ecosystem-ci-internal`)**: ask **every time**; earlier approvals don't carry over (see "Private logs gate" below). Until the user says yes, they are a next step in TRACKING.md. When allowed: read-only, only the approved build/package prefix, stream (`gcloud storage cat … | grep`), never `cp`. Public text never mentions the bucket, quotes private log lines, or includes UUIDs; say "the agent logs show …" plus how to reproduce locally.
- Reference only the **latest failed build**. Hypotheses from earlier builds/comments are "prior" until re-checked on that build.
- Mark every cause ✅ confirmed (log/diff/repro) · 🟡 inferred (matches a signature) · 🔍 not investigated. Never present 🟡 as ✅.
- Before blaming anyone, check that elastic-package and the package didn't change across the night the failure started.
- Owner is explicit: **package owners** (CODEOWNERS team), **ecosystem** (elastic-package / CI), or an **upstream repo**. "Fix in this repo" alone is ambiguous.
- Owner issues: context, since when (first failing build), evidence, proof of cause. Add a fix **only if verified locally**; otherwise let owners decide. When adding evidence to someone else's issue, add evidence only, no suggestions.
- Links are complete: Buildkite log lines as `https://buildkite.com/elastic/integrations/builds/<B>#<job-id>/<start>-<end>`, other repos as full URLs.

## Token budget

- Run the scripts; read `failures.tsv` and `logs/<pkg>.fail` (≈400 B each), never a whole job log. Use `grep -n` then `sed -n 'a,bp'`.
- Read one report section, not the file: `sed -n '/^## 7\./,/^## 8\./p' build-<B>-report.md`.
- One cause per session for deep dives. Start from TRACKING.md and that report section.
- `gh … --jq` to select fields and cut bodies (`.body[0:1500]`). Summarise agent logs per file with `sort | uniq -c | sort -rn | head`.
- Local test runs: run in the background with output to a file. Arm Monitor only with a narrow filter (`PASS|FAIL|Error`), not every `found N hits` line.

## Mode A: Triage a build (new issue or new failing night)

Scripts are in this skill's base directory under `scripts/` (`$S`). Run them from the repo root with `W=build/triage/issue-<n>`.

1. **Scope**: `$S/scope.sh <n> $W` gives the stack, the reference build (last URL in "Latest 5 failed builds"), the package list, per-night counts, new/fixed vs the previous night and the first build, and the state of every issue linked in comments. The bot rewrites the body each night (no comments). History is in the edit log. It also prints the **triggering job** status: if `SUPERSEDED`, put a banner at the top of every draft naming the successor issue and propose closing this one; `PASSED-TODAY`/below-threshold means no new "too many" night (see auto-issues.md). Create or refresh TRACKING.md from this output.
2. **Collect**: `$S/collect.sh <B> $W/build-<B>` gives one row per failed package: tests, log-line link, detail, plus job totals, non-package failures and the elastic-package version. Counts must match the issue list.
3. **Match and look up**: `$S/match.sh $W/build-<B>/failures.tsv $W/known.tsv > $W/build-<B>/match.tsv`. Each package gets KNOWN (unchanged known cause), CHANGED (tests or detail differ, possibly masking), SIG:<family> (generic pattern from `references/signatures.tsv`), UNKNOWN, or DROPPED. Then `$S/lookup.sh …/match.tsv` gives every tracked issue/PR with its state, assignees and linked PRs (merged/draft/review), and open issues/PRs for packages without a tracked ref. **Always check this before proposing an issue.** Only reason about non-KNOWN rows.
   **Group**: check failure-signatures.md for details. Then group by **trigger**, not symptom: look for a shared trait with `yq` over `packages/*/manifest.yml` or `_dev/deploy`, e.g. 14 packages had a space in `policy_templates[].name`, and the only 2 Azurite packages lacked a flag.
4. **History**: `$S/history.sh <B> 30 $W/build-<B>` gives each package's timeline and the first build of its failing streak. Bisect that night against upstream commits and releases. ⚠️ It sees job state only. A package failing "every night" may have switched test type: test order is asset → pipeline → policy → script → system, so an earlier failure hides the later ones. Run `collect.sh` on the first-streak build and compare the `tests` column.
5. **Control**: the same night's "local stacks and basic subscription" build (released stack). If a package passes there, the cause is stack-side or 9.x-only.
6. **Write** the report (summary-by-cause table, then one section per cause) and **publish it as the private artifact**. Write the public summary comment (outputs.md) and update TRACKING.md. Known causes already tracked go in as 📌 with the issue state. End the turn with the artifact link plus the path of the post-ready summary.

## Mode B: Deep-dive one cause ("investigate this cause")

- Cheapest evidence first:
  1. The job log: the hit progression `grep -o 'found [0-9]* hits' logs/<pkg>.log | uniq -c` (passing 3→6→9 vs failing 3→5→7 proved statsd's cause), plus elastic-package events (`Policy revision assigned`, service `Killing` = SIGHUP).
  2. The same package's log on the last **passing** build.
  3. JUnit artifacts for pipeline and policy diffs.
  4. The package's `_dev/deploy` (mocks, healthchecks).
  5. The upstream source at the exact ref.
  6. Private logs, only through the gate below.
  7. A local repro.
- Check for existing issues, including the auto-filed per-package "Failing test daily" issues on other stacks (8.19 / LogsDB). One root cause often explains 5–10 of them, so list them in the owner issue.
- **Repro locally** to confirm and to verify a fix (commands.md). Prove the fix with a single change and keep the run log.
- Then update the report section (say what changed vs the earlier hypothesis) and republish the artifact. Update TRACKING.md, adjust the item in the public summary if the cause or next step changed, and draft the owner issue (outputs.md). Look up labels with `gh label list --search`.

### Private logs gate

Use it only when the public evidence (job log, JUnit, stack dump, package code) can't settle the cause.

1. **Preflight, without touching the bucket:** `$S/gcs-preflight.sh`. If gcloud is missing, logged out or expired, tell the user the exact fix the script prints (install with `brew install --cask google-cloud-sdk` on macOS or https://cloud.google.com/sdk/docs/install on Linux, then `! gcloud auth login`). Stop there, don't ask for permission yet, and record it as a blocker in TRACKING.md.
2. **Ask** with AskUserQuestion, one question that stands on its own: build, package(s), which logs (agent / service / mock), the hypothesis they would confirm, and that findings stay in the private report only. Options: "Allow for <B>/<pkg>" · "Not now (keep as next step)". A "yes" covers only that build and those packages, in this session.
3. **Verify access:** `$S/gcs-preflight.sh <B> <pkg>` lists the prefix. On 403, the account lacks bucket access, so tell the user who to ask. On "no objects", the logs have expired or the package is wrong. Either way, stop and record it.
4. **Read:** stream and summarise per file (commands.md). If auto mode denies the read, stop and explain; don't work around it.

## Mode C: Status and rollout ("is it fixed", "when will it roll out")

For each tracked issue: state, linked PRs (merged?), and **where the fix must land to reach the nightly**:

- Package fix: merged to main means the next nightly.
- elastic-package: a release, then the version bump in this repo's `go.mod`.
- Upstream component (otel-contrib, beats): merged, then released, then bumped in elastic-agent `go.mod` on each branch, then the next snapshot (about 1 day).
- Kibana/ES: merged to main or the branch, then the next snapshot.

See commands.md. Write the answer as a status block under the item in the summary, and update TRACKING.md.

## Mode D: Status comment for the issue

Use the status template in outputs.md, built from TRACKING.md: ✅ tracked and waiting on owners · 🔄 fix in progress · ⏳ cause known, nothing filed · 🔍 not investigated. Keep it brief and link every issue.

## Pitfalls

- `bk … -o json`: `-o` is the format. Use `-p elastic/integrations`. `bk build list` date flags fail, so use `--since <h>h` and filter on `message`. If you get a `401 access-token`, ask the user to run `! bk configure --force`.
- Job logs have `ESC _` / `\r` prefixes (collect.sh strips them). The stripped line numbers match Buildkite anchors.
- zsh: `set -- $var` doesn't split, `[ a == b ]` fails, globs need quoting. Run scripts with bash. macOS has no `timeout` (Linux does). In some subshells `gh` isn't on PATH; use its full path (`command -v gh` in a normal shell, e.g. `/opt/homebrew/bin/gh` on macOS, `/usr/bin/gh` on Ubuntu).
- `elastic-package stack up` takes `--version`, not `-v`.
- The first explanation of a group is often wrong: on 52238, "OTel routing" turned out to be 4 causes, and on 53431, "UDP loss" was 3 causes. A "hit" can itself be an error event (oracle).
