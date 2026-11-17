# Commands

`B=<build>`, `P=elastic/integrations`, `S=~/.claude/skills/integrations-build-triage/scripts`. Run from the repo root and write to `build/triage/…` (gitignored).

## Scripts (use these first)

| Script | Replaces | Cost |
|---|---|---|
| `$S/scope.sh <issue>` | issue body, edit-history GraphQL, per-night package lists, deltas, linked-issue states | ~20 s, ~3 KB output |
| `$S/collect.sh <B>` | build JSON, parallel log download, ANSI strip, failure blocks, log-line links | ~10 s, ~3 KB output (logs 8 MB stay on disk) |
| `$S/history.sh <B> [days]` | per-night job states, first failing build of each streak | ~50 s, ~2 KB output |

All three are idempotent: re-running skips logs that are already downloaded.

## Buildkite

```sh
# Log line link (line numbers = lines of the stripped log)
https://buildkite.com/elastic/integrations/builds/$B#<job-id>/<start>-<end>

# Hit progression (system tests): compare a passing and a failing night
grep -o 'found [0-9]* hits in [^ ]*' logs/<pkg>.log | sed 's/-[0-9]* *$//' | uniq -c

# elastic-package timeline events
grep -n -E 'Policy revision assigned|Killing|service_notify|Wait for|found [0-9]+ hits' logs/<pkg>.log | head -40

# JUnit (pipeline/policy diffs) and stack dump
bk artifacts list $B -p $P --job <job-id>    # build/test-results/<pkg>-<type>-*.xml, build/elastic-stack-dump/<pkg>/logs/*.log
bk artifacts download <artifact-id> -p $P    # into its own empty dir

# Same nightly on other nights (history.sh does this): --since <h>h + client-side message filter
bk build list -p $P --branch main --since 720h --limit 300 -o json | jq -r '.[] | select(.message|test("local stacks")) | [.number,.created_at[:10],.state,.message] | @tsv'
```

Nightlies: "Check integrations local stacks - Stack Version v9.7" / "v9.6" / "v8.19". The control on a released stack is "… local stacks and basic subscription".

## Private logs (GCS): through the SKILL.md gate only, never cite publicly

```sh
$S/gcs-preflight.sh                 # before asking: gcloud installed, account active, token valid (no bucket access)
$S/gcs-preflight.sh $B <pkg>        # after the user says yes: checks access and lists the files with sizes
L=gs://ecosystem-ci-internal/buildkite/integrations/main-integrations-$B/insecure-logs
#   elastic-agent-<id>.log  ~850 KB, one per test: the useful one
#   <pkg>-<service>-<id>.log  mock/service output (small, often decisive: Oracle setup, mock 404s)
gcloud storage cat "$L/<pkg>/container-logs/elastic-agent-<id>.log" | sed 's/^[^|]*| //' |
  jq -Rc 'fromjson? | select(.["log.level"]=="error") | .message' | sort | uniq -c | sort -rn | head
```

Never `cp` and never redirect large output to files: both were denied. Auto-mode once denied a `gcloud storage cat` of an agent log as "Undermining Oversight". If that happens, stop and ask; don't work around it.

## GitHub (read-only)

```sh
gh issue view <n> -R <repo> --json number,title,state,stateReason,closedAt,labels,assignees,closedByPullRequestsReferences \
  --jq '{number,title,state,closedAt,labels:[.labels[].name],prs:[.closedByPullRequestsReferences[].url]}'
gh search issues -R $P "<pkg> Failing test daily" --state open --json number,title --limit 30   # per-package flakes on other stacks
gh search prs -R $P "<keyword>" --json number,title,state
gh label list -R $P --search "<pkg>"; yq '.owner.github' packages/<pkg>/manifest.yml; grep "/packages/<pkg> " .github/CODEOWNERS
# Upstream source / history at an exact ref, no clone
gh api "repos/elastic/<repo>/contents/<path>?ref=<sha|tag>" -H 'Accept: application/vnd.github.raw'
gh api "repos/elastic/<repo>/commits?path=<path>&since=<iso>&until=<iso>" --jq '.[] | [.sha[:10], .commit.committer.date[:10], (.commit.message|split("\n")[0])] | @tsv'
gh repo view <owner>/<repo> --json visibility    # before quoting code
```

`elastic-package` source at the version in use: `~/go/pkg/mod/github.com/elastic/elastic-package@$(grep -o 'elastic-package v[^ ]*' go.mod | cut -d' ' -f2)`.

## Rollout check (Mode C)

```sh
# Upstream PR: merged? which release/milestone?
gh pr view <n> -R <owner>/<repo> --json state,mergedAt,mergeCommit,milestone --jq '{state,mergedAt,sha:.mergeCommit.oid[:10],milestone:.milestone.title}'
gh api repos/<owner>/<repo>/releases --jq '.[0:5][] | [.tag_name,.published_at[:10]] | @tsv'
# Is that version bundled in elastic-agent on each branch? (otel-contrib / beats components)
for b in main 9.6 9.5 9.4 8.19; do printf '%s: ' $b; gh api "repos/elastic/elastic-agent/contents/go.mod?ref=$b" --jq .content | base64 -d | grep -m1 '<module path>'; done
# Open bump PRs
gh search prs -R elastic/elastic-agent "<module or version>" --state open --json number,title,url
```

The snapshot picks up merged changes in about 1 day. The issue then drops out of the next bot edit (check with `scope.sh`).

## Package traits (group by trigger)

```sh
for m in packages/*/manifest.yml; do yq -r '.policy_templates[]?.name' "$m" | grep ' ' | sed "s|^|$(basename $(dirname $m)): |"; done
grep -rl 'azurite' packages/*/_dev/deploy --include='docker-compose.yml' | xargs grep -L skipApiVersionCheck
```

## Local repro

```sh
elastic-package stack up -d --version <X>-SNAPSHOT [--services elasticsearch]   # --provider compose for a stale profile
eval "$(elastic-package stack shellinit)"
cd packages/<pkg> && elastic-package build && elastic-package install
elastic-package test pipeline --data-streams <ds> [--generate]
elastic-package test system -v --data-streams <ds> [--config-file …] [--defer-cleanup 120s] > <scratch>/run.log 2>&1   # run_in_background
docker logs <agent-container> 2>&1 | grep …   # collector: /usr/share/elastic-agent/state/data/logs/elastic-otel-collector-*.ndjson
elastic-package stack down
```

A minimal single-service repro is often enough, e.g. Azurite plus the beats SDK version, or the oracle compose with its healthcheck.
