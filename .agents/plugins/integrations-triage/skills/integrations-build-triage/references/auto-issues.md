# How the daily jobs file and update issues

Source: `dev/testsreporter` in elastic/integrations (entry `mage ReportFailedTests`, `magefile_daily_jobs.go`). `scope.sh` relies on the facts below. If the reporter changes, re-check them.

## Which jobs run

The cron schedules live in `catalog-info.yaml` under `integrations-schedule-daily` and run on `main`, Mon–Fri (UTC). Each scheduler run sets one env flag, and the matching steps in `.buildkite/pipeline.schedule-daily.yml` then trigger an `elastic/integrations` build whose **message is the step label**:

| Cron | Scheduler message | Steps (label → STACK_VERSION) |
|---|---|---|
| 00:30 | Run the daily jobs | v7.17 → 7.17.x · serverless Observability / Security (`integrations-serverless` pipeline) · publish |
| 01:30 | Run the daily jobs for 8.x | v8.19 and v8.19 - LogsDB → 8.19.N-SNAPSHOT |
| 03:30 | Run the daily jobs for 9.x | v9.Y → 9.Y.0-SNAPSHOT (the ES `main` snapshot) |
| 04:30 | Run the daily jobs for basic subscription | basic, and basic and LogsDB → unset (elastic-package default, a released stack) |

There is **no job per supported version**. 9.x has a single step that follows the ES `main` snapshot. When updatecli bumps it, both the label and STACK_VERSION change (e.g. v9.6 → v9.7, #22175). 8.19 follows the 8.19 patch snapshot, so the label stays the same and only STACK_VERSION changes (8.19.25 → 8.19.26).

## When an issue is written

- The `:github: Report failed tests` step (`report_issues.sh`, `soft_fail`) runs only in `integrations` / `integrations-serverless` builds triggered by `integrations-schedule-daily`. PR builds and manual builds never file issues.
- Input: the JUnit XML in `build/test-results/*.xml`. **One failure is one failing test case, not one package.** Failures that leave no JUnit failure (build or setup errors) file nothing. For example, build 53433 failed on beyondtrust_epm and the report step found no failures.
- **Threshold:** `CI_MAX_TESTS_REPORTED` is 30 (set in `pipeline.yml`; the code default is 20).
  - **More than 30 failing test cases:** one build issue, `<prefix>Too many packages failing in daily job`. Owner `@elastic/ecosystem`, labels `flaky-test`, `automation`, `Team:Ecosystem`. The body lists the packages with at least one failing test. **No per-package issues are filed or updated that night.**
  - **30 or fewer:** one issue per failing test case, `<prefix>[<pkg>] Failing test daily: <test>`. Owners come from CODEOWNERS (in the body). Labels `flaky-test`, `automation`. `Integration:*` and `Team:*` labels are added later by the issue-triage automation (`trigger-issue-triage.yml`), not by the reporter.
- Prefix, in this order: `[LogsDB] ` `[Serverless <project>] ` `[Stack <STACK_VERSION>] ` `[Subscription basic] `.

## How an issue is updated

- **Identity is the exact title.** The reporter searches `gh issue list --search "<title> in:title"` and needs an exact title match on an issue with labels.
- **Open match:** the body is rewritten with `gh issue edit --body`. There are **no comments**. `First build failed:` is kept, tonight's build is appended to `Latest 5 failed builds:` (only the newest 5 are kept), and the package list is replaced. History is only in the edit log (`userContentEdits`, which `scope.sh` reads).
- **No open match:** a new issue is created. If a closed issue with the same title exists, the body says `Latest issue closed for the same test: <url>`.
- **Nothing ever closes an issue.** A green night doesn't touch anything, so humans close them.

## Reading a quiet issue (`updatedAt` not today)

1. **Superseded:** STACK_VERSION or the label changed, so the reporter now writes under a new title. The old issue is orphaned for good. Examples: #20180 (9.6 → 9.7, #22175), and #14020 / #14021 (`8.19.0-SNAPSHOT`; final builds on 2025-08-11 when #14886 bumped to 8.19.1). It also explains most of the ~460 open per-package issues with old `8.19.x` prefixes.
2. **Green:** the latest run of that label passed.
3. **Below threshold:** the run failed with 30 or fewer failing tests, so per-package issues were updated instead. For a "Too many" issue this is "not too many tonight", not "fixed".
4. **Not run:** weekend, or no build in the last 36h.
5. **Report step failed:** it is `soft_fail`, so check the `:github: Report failed tests` job log.

`scope.sh` prints `job status: SUPERSEDED` with the successor issue, and `latest run: PASSED-TODAY | FAILED-TODAY | NOT-RUN…`.

## Tools that use these facts

- `scripts/lib.sh`: `title_job` maps a title to its job (and today's version of it); `reported_issues` reads a build's report-step log to get exactly which issues it created or updated, or whether it was a "Too many" night.
- `scripts/daily.sh`: builds-first, it lists the scheduler runs of a day, their builds, and the issues each build reported to.
- `scripts/sweep.sh`: the backlog verdict for every open auto-filed issue. Per-package issues are per *test*, so "not failing" is decided from report-step logs, not job states. A night is clean for an issue when the build passed, or the reporter filed per-test issues and didn't touch it. "Too many" nights and failures outside JUnit are unknown.
- Serverless: the daily serverless builds (`elastic/integrations-serverless`) run every package in **one** job (`Check integrations in serverless`). A timeout fails the build without any JUnit failure, so nothing is filed.

## Using the plugin on per-package issues

A `[<pkg>] Failing test daily: <test>` issue has the same body format (`First build failed`, `Latest 5 failed builds`), so `scope.sh` works on it. The package list is just that one package. The "Too many" issues are ecosystem's queue. Per-package issues belong to the package owners, and one root cause often explains several of them across stacks (8.19, LogsDB, basic). Group them by cause, as for a build.

## History and conventions (as of 2026-11)

- **Each version gets its own "Too many" issue.** Most 8.19 patches that went over the threshold had a pair (stack and LogsDB): 8.19.1, 8.19.3–8.19.12, 8.19.20 and 8.19.21 (#14901 … #20949). The others never went over, and each 9.x minor had one (9.1 #14022 … 9.5 #18803, 9.6 #20180, 9.7 #22189). Basic subscription and serverless issues carry no version, so they are reused, and a new one opens once the previous is closed.
- **Ecosystem closes them by hand, as completed,** with a comment that starts "Closing this issue since …": either the latest build over the threshold is old (#18575), or the causes were fixed (#20949, an elastic-package release). Superseded issues are expected to be closed the same way. #14020 and #14021 were missed, and stayed open for 15 months.
- **`updatedAt` is not the last nightly.** Bots also bump it; for example, botelastic adds a `Stale` comment after a year (#14021: updated 2026-08-11, last build 2025-08-11). Use the last body edit, which is the last row of `nights.tsv` from `scope.sh`.
- **Below the threshold there is no "Too many" issue at all.** 8.19.22 to 8.19.26 (like 8.19.2 and 8.19.13–8.19.19) stayed at 30 failing tests or fewer, so the 8.19 failures are only in per-package issues.
