# integrations-triage (Claude Code plugin)

Daily triage for the elastic/integrations scheduled jobs and the issues they file automatically:

- **"[Stack X] Too many packages failing in daily job"**: one issue per job and version when more than 30 tests fail (owner: `@elastic/ecosystem`).
- **"[<pkg>] Failing test daily: <test>"**: one issue per failing test otherwise (owner: the package team).

Every weekday it starts from the Buildkite builds, triages what failed into the issues that track it, and sweeps the backlog for issues that are stale or superseded, so the backlog trends to clean. **It is draft-only**: it never posts, comments, files, closes or retries anything. It writes drafts and a digest, and you review and post them.

How the daily jobs file and update these issues (and why so many go stale): [`references/auto-issues.md`](skills/integrations-build-triage/references/auto-issues.md).

## 1. Requirements

Everything runs on your machine (macOS or Linux; tested on Ubuntu 24.04), from an elastic/integrations checkout, with your own CLI logins. The plugin itself can live anywhere: below, `<plugin>` is its root directory (the folder with `.claude-plugin/`), and nothing in it depends on where that is. Check with:

```sh
cd <your integrations checkout> && <plugin>/skills/integrations-build-triage/scripts/doctor.sh
```

| Needed for | Tool | macOS | Ubuntu / Linux | Then |
|---|---|---|---|---|
| **Required** | `gh` (GitHub CLI) | `brew install gh` | [GitHub's apt repo](https://github.com/cli/cli/blob/trunk/docs/install_linux.md) | `gh auth login` (scopes `repo`, `read:org`; SSO-authorize for elastic) |
| **Required** | `bk` (Buildkite CLI) | `brew install buildkite/buildkite/bk` | [Buildkite CLI install docs](https://buildkite.com/docs/platform/cli/installation) | `bk configure` (org `elastic`; token with `read_builds`, `read_build_logs`, `read_artifacts`) |
| **Required** | `jq`, `yq` (mikefarah v4), bash | `brew install jq yq` | `sudo apt install jq` and `sudo snap install yq` (not `apt install yq`: that's a different, Python-based `yq`) | |
| **Required** | elastic/integrations checkout with a remote pointing to `github.com/elastic/integrations` (any name, e.g. `elastic`) | | | the triage runs from its root |
| Interactive only: private logs (asked each time) | `gcloud` | `brew install --cask google-cloud-sdk` | [Google's apt repo](https://cloud.google.com/sdk/docs/install#deb) | `gcloud auth login` |
| Interactive only: local repro | `elastic-package`, Docker | `go install github.com/elastic/elastic-package@latest`, Docker Desktop | same, Docker Engine | |

The scripts use the `gh`/`bk` CLIs, not the GitHub/Buildkite MCP servers. The CLIs keep output out of the model's context, work unattended, and use their own tokens.

## 2. Install and update

```sh
claude plugin marketplace add <plugin>        # a local path, or the git URL / owner/repo of a repo that hosts it
claude plugin install integrations-triage@integrations-triage
```

After pulling or editing the plugin, update the installed copy:

```sh
claude plugin marketplace update integrations-triage
claude plugin update integrations-triage@integrations-triage
```

To try changes without installing: `claude --plugin-dir <plugin>`. If you used a personal copy of the skill before, remove `~/.claude/skills/integrations-build-triage` so it isn't loaded twice.

## 3. Run it

Always run from the **root of the integrations checkout**. Each run first brings the checkout to the latest `elastic/main` (see [Repo state](#repo-state)).

| What | How |
|---|---|
| The whole daily run (the normal case) | In Claude Code, from the checkout root: `/integrations-triage:triage-daily` (today, UTC) or `/integrations-triage:triage-daily 2026-11-17`. Headless, from the checkout root: `<plugin>/bin/triage-unattended.sh` |
| One issue ("Too many" or per-package) | `/integrations-triage:triage-nightly 22189`, or `<plugin>/bin/triage-unattended.sh 22189` |
| Only the backlog sweep (no LLM, about 20 s once cached) | `<plugin>/skills/integrations-build-triage/scripts/sweep.sh` |
| Only "what ran today and where it was reported" (no LLM) | `…/scripts/daily.sh` |
| An interactive deep dive into one cause | Ask in a normal session ("investigate the vectra_rux failure on 9.7"). The `integrations-build-triage` skill loads, and can use private logs (it asks first) and local repros |

The daily jobs run Mon–Fri between 00:30 and 04:30 UTC and file issues right after. Run the triage **after about 06:30 UTC**.

## 4. Schedule it every weekday

Claude Code's **cloud** scheduled tasks (`/schedule`) don't fit. They run in a fresh cloud clone without your `gh`/`bk` logins (their `gh` can't run `gh issue`), and anything written to the gitignored `build/` dir is lost after the run. Use one of these local options. All of them need the machine awake at the scheduled time.

**Option A: Claude desktop app, local scheduled task (simplest; macOS and Windows only, there is no Linux desktop app).** Create a *Local task*: folder: your integrations checkout, schedule *Weekdays* at a local time after 06:30 UTC (e.g. 08:00), permission mode *Accept edits*, prompt `/integrations-triage:triage-daily`. It runs only while the desktop app is open. If the machine slept through the time, it does one catch-up run on wake. *Accept edits* auto-approves file edits only, so every shell command would wait for you in the task's session. Either choose a permission mode that doesn't prompt for Bash, or add allow rules in `~/.claude/settings.json`: at least the plugin's scripts plus `gh`, `bk`, `jq`, `yq` and `git` (fetch/merge/log). The guard hook still blocks every write. Do one manual run first, to check that the plugin and its guard hook are loaded in desktop tasks and that nothing stalls on a prompt.

**Option B (macOS): launchd + the headless runner (works with the app closed).** Save as `~/Library/LaunchAgents/local.integrations-triage.daily.plist`, then run `launchctl load ~/Library/LaunchAgents/local.integrations-triage.daily.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>local.integrations-triage.daily</string>
  <key>ProgramArguments</key><array>
    <string>/bin/bash</string>
    <string>/path/to/plugin/bin/triage-unattended.sh</string>
    <string>daily</string>
    <string>/path/to/integrations</string>
  </array>
  <key>EnvironmentVariables</key><dict>
    <key>TRIAGE_MAX_BUDGET_USD</key><string>20</string>
  </dict>
  <key>StartCalendarInterval</key><array>
    <dict><key>Weekday</key><integer>1</integer><key>Hour</key><integer>8</integer><key>Minute</key><integer>0</integer></dict>
    <dict><key>Weekday</key><integer>2</integer><key>Hour</key><integer>8</integer><key>Minute</key><integer>0</integer></dict>
    <dict><key>Weekday</key><integer>3</integer><key>Hour</key><integer>8</integer><key>Minute</key><integer>0</integer></dict>
    <dict><key>Weekday</key><integer>4</integer><key>Hour</key><integer>8</integer><key>Minute</key><integer>0</integer></dict>
    <dict><key>Weekday</key><integer>5</integer><key>Hour</key><integer>8</integer><key>Minute</key><integer>0</integer></dict>
  </array>
  <key>StandardOutPath</key><string>/tmp/integrations-triage.out</string>
  <key>StandardErrorPath</key><string>/tmp/integrations-triage.err</string>
</dict></plist>
```

Test it right away with `launchctl kickstart -k gui/$(id -u)/local.integrations-triage.daily`. The hours are local time. The runner sets its own `PATH` (Homebrew, Linuxbrew, snap, `~/go/bin`, `~/.local/bin`), since launchd doesn't load your shell profile. If `claude` can't reach your login from launchd, create a token with `claude setup-token` and add it as `CLAUDE_CODE_OAUTH_TOKEN` under `EnvironmentVariables`. `TRIAGE_MAX_BUDGET_USD` caps the spend per run. Pick your own value; 20 above is only an example.

**Option C (Linux): systemd user timer + the headless runner.** Save these two files under `~/.config/systemd/user/`:

```ini
# integrations-triage.service
[Unit]
Description=integrations-triage daily run (draft-only)

[Service]
Type=oneshot
Environment=TRIAGE_MAX_BUDGET_USD=20
ExecStart=/bin/bash /path/to/plugin/bin/triage-unattended.sh daily /path/to/integrations
```

```ini
# integrations-triage.timer
[Unit]
Description=integrations-triage on weekdays

[Timer]
OnCalendar=Mon..Fri 08:00
Persistent=true

[Install]
WantedBy=timers.target
```

Then `systemctl --user daemon-reload && systemctl --user enable --now integrations-triage.timer`. Test it right away with `systemctl --user start integrations-triage.service` and read the output with `journalctl --user -u integrations-triage`. `Persistent=true` does one catch-up run if the machine was off at 08:00 (local time). To run while you're logged out, also run `loginctl enable-linger`. The same notes as launchd apply: the runner sets its own `PATH`, and if `claude` can't reach your login, put `CLAUDE_CODE_OAUTH_TOKEN` (from `claude setup-token`) in an `Environment=` line, or better in an `EnvironmentFile=` readable only by you. A plain crontab line (`0 8 * * 1-5 /bin/bash …/triage-unattended.sh daily /path/to/integrations`) also works, without the catch-up run.

Runner exit codes: `0` done · `3` setup missing (see `runs/<time>.log.doctor`) · `4` checkout not synced (see `runs/<time>.log.sync`) · anything else: the Claude run failed (see `runs/<time>.log`). Each run also posts a desktop notification (`osascript` on macOS, `notify-send` on Linux, if available).

## Repo state

Every run starts with `scripts/sync.sh`, so the triage reads the **latest `elastic/main`**:

- **On `main`:** it fetches `elastic/main` and fast-forwards. Your uncommitted changes are kept and listed in the run output, and the triage treats those files as local edits, not as upstream state.
- **A detached checkout (a dedicated worktree):** it moves to the latest `elastic/main` if the tree is clean.
- **Another branch:** your branch is left alone. The triage runs in a detached worktree next to the checkout, `../integrations-triage-run` (override with `TRIAGE_WORKTREE`), which `sync.sh` creates on first use and moves to the latest `elastic/main` on every run. Drafts and memory (`build/triage/`) live in that worktree. `sync.sh` ends with `root: <path>`, and the commands and the runner continue from there.
- **Local commits on `main`, or local changes that conflict with upstream:** it **stops without touching anything** (runner exit `4`, or a `SETUP-NEEDED.md` from the commands). It never switches branches, stashes or resets.

## 5. Expected outcome

A daily run ends with a reply of up to five lines (builds failed/total, issues touched, findings, close candidates, digest path). It leaves these files under `<checkout>/build/triage/` (gitignored, never committed):

| Path | What | What you do with it |
|---|---|---|
| `daily/<date>/DIGEST.md` | **Start here.** Today's builds and where each reported, what changed since the last run, status by cause across 8.19 / LogsDB / 9.x / basic, new findings, the backlog summary, and a **"Proposed actions (needs human)"** checklist with a draft path on each item | Read it, tick through the checklist |
| `daily/<date>/builds.tsv`, `issues.tsv` | Raw output of `daily.sh`: label, build, state, failed packages, report mode (`too-many` / `per-package` / `none`), issue numbers | Reference |
| `issue-<n>/` | Per issue: `COMMENT_DRAFT_<date>.md` (cause, evidence, owner), `ISSUE_DRAFT_<cause>.md` (new owner issues), `build-<B>-summary.md` (public summary for a "Too many" issue), `COMMENT_DRAFT_close_superseded.md`, `TRACKING.md`, `known.tsv` | Post the text after the `---` line of each draft yourself |
| `job-<label>/` | Memory per daily job for nights that filed per-package issues (`known.tsv`, script output per build) | Nothing; it makes the next night cheaper |
| `sweep/<date>/` | `sweep.tsv` (a verdict for every open auto-filed issue), `close-candidates.tsv`, `CLOSE_COMMANDS.sh` | Review the candidates, then run `CLOSE_COMMANDS.sh` yourself, all at once or a prefix at a time. Claude can't run it |
| `cache/` | Job states and report-step results per build | Safe to delete |

Sweep verdicts: **SUPERSEDED** (the job moved to a newer version, so nothing updates the issue again), **RETIRED** (the job is gone), **NOT-FAILING** (3 or more later runs passed or reported other tests only), **QUIET** (a "Too many" issue whose job stayed under the threshold for 3 or more runs). These four are proposed for closing. **ACTIVE** issues are kept. Issues with an assignee are commented out in `CLOSE_COMMANDS.sh`. The closing comments follow ecosystem's convention (closed as completed, "Closing this issue since …").

What it doesn't do on its own: read private CI logs, run local stacks or tests, or post anything. These show up in the digest as proposals (`[ ] Approve private logs: …`, `[ ] Local repro: …`) for an interactive session.

Known limits:
- **Serverless:** the daily serverless builds run every package in one job, so a timeout shows only as "timed out", with no per-package triage.
- **Unknown nights:** "Too many" nights and failures outside JUnit can't show that a given test passed, so they don't count towards NOT-FAILING.

## 6. Safety

`hooks/guard.sh` (PreToolUse) is always on in an elastic/integrations checkout. It blocks GitHub and Buildkite writes (gh CLI and MCP: comment, create, edit, close, merge, retry, rebuild, …) and running a generated `CLOSE_COMMANDS.sh`. In unattended runs (`TRIAGE_UNATTENDED=1`) it also blocks gcloud/gsutil, `elastic-package stack/test/service` and docker runs. The runner also passes `--permission-prompts none`, so anything that would need approval is denied instead of hanging.

## 7. Troubleshooting

| Symptom | Fix |
|---|---|
| Exit `3` / `SETUP-NEEDED.md` from doctor | Run `doctor.sh` by hand; it prints the fix (e.g. `bk configure --force` on a 401) |
| Exit `4` / not synced | `main` diverged from `elastic/main`, local changes conflict, or the triage worktree path is taken by something else. Resolve by hand, or set `TRIAGE_WORKTREE` (see [Repo state](#repo-state)) |
| "no scheduler runs on <date>" | Weekend, or it ran before 00:30 UTC |
| Digest says "no new failing night" | The issue's job passed or stayed under the threshold; nothing to triage |
| Old numbers in the sweep | `rm -rf build/triage/cache` and run again |

## Pieces (for maintainers)

| Piece | Role |
|---|---|
| `commands/triage-daily.md` | `/integrations-triage:triage-daily [date]`: builds → issues → backlog sweep → `DIGEST.md` |
| `commands/triage-nightly.md` | `/integrations-triage:triage-nightly <issue>`: one issue, "Too many" or per-package |
| `agents/cause-investigator.md` | One per unexplained failure group (parallel, at most 5 per run). Public evidence only; returns a structured verdict |
| `skills/integrations-build-triage/` | Interactive playbook (deep dives, private-logs gate, rollout checks), references and scripts |
| `skills/…/scripts/` | `sync.sh` (latest elastic/main), `daily.sh` (a day's builds and the issues each reported to), `sweep.sh` (backlog verdicts + `CLOSE_COMMANDS.sh`), `scope.sh` → `collect.sh` → `match.sh` → `lookup.sh` → `history.sh` (deterministic, no LLM), `lib.sh` (shared: title → job, cached build data), `doctor.sh`, `gcs-preflight.sh` (interactive only) |
| `hooks/guard.sh` | The write and safety guard above |
| `bin/triage-unattended.sh` | Headless runner: doctor → sync → `claude -p`, logs to `build/triage/daily/<date>/runs/` (or `issue-<n>/runs/`), desktop notification |

The memory files (`issue-<n>/known.tsv` for "Too many" issues, `job-<label>/known.tsv` per daily job) make repeat nights cheap: unchanged failures are matched without reasoning, and investigators only look at what's new or changed.
