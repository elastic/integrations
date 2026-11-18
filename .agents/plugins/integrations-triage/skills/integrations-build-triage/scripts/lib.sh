#!/usr/bin/env bash
# Shared helpers for the triage scripts. Source it: . "$(dirname "$0")/lib.sh"
# Facts behind these helpers: references/auto-issues.md.
# Caches live in build/triage/cache/ (run from the integrations repo root).

R=elastic/integrations
SCHED=.buildkite/pipeline.schedule-daily.yml
CACHE=${TRIAGE_CACHE:-build/triage/cache}
mkdir -p "$CACHE"

# Build states that can't change any more. Only these get cached: "failing" means a job failed while others still run.
FINAL_STATES='passed|failed|canceled|skipped|not_run'
build_finished() { [[ $1 =~ ^($FINAL_STATES)$ ]]; }

# Strip Buildkite log noise: ESC _ timestamps, ANSI, CR, leading "_" left by timestamps.
clean_log() { perl -pe 's/\e_[^\a]*\a//g; s/\e_//g; s/\e\[[0-9;]*[a-zA-Z]//g; s/\r//g; s/^_//'; }

# The daily schedule on main, cached per day.
schedule() {
  local f="$CACHE/schedule-daily-$(date -u +%F).yml"
  [ -s "$f" ] || gh api "repos/$R/contents/$SCHED?ref=main" -H 'Accept: application/vnd.github.raw' > "$f" 2>/dev/null || : > "$f"
  echo "$f"
}

# title_job "<issue title>" -> '|'-separated (empty fields kept; read with IFS='|'):
#   kind|pipeline|label|issue_stack|current_label|current_stack|package
#   kind: too-many | per-package | other
#   label: the job the issue was filed from; current_*: that job family in today's schedule (empty = retired)
#   The 9.x step is renamed on bumps (v9.6 -> v9.7), so the family match keeps the major and ignores the minor.
title_job() {
  local t=$1 kind=other pipe=$R label="" st logsdb=false pkg=""
  [[ $t == *"Too many packages failing in daily job"* ]] && kind=too-many
  [[ $t == *"] Failing test daily: "* ]] && { kind=per-package; pkg=$(sed -nE 's/.*\[([a-z0-9_]+)\] Failing test daily: .*/\1/p' <<<"$t"); }
  st=$(sed -nE 's/.*\[Stack ([^]]+)\].*/\1/p' <<<"$t")
  [[ $t == *"[LogsDB]"* ]] && logsdb=true
  local re='\[Serverless ([a-z]+)\]'
  if [[ $t =~ $re ]]; then
    local p=${BASH_REMATCH[1]}; pipe=elastic/integrations-serverless
    label="Check integrations in serverless - project: $(tr '[:lower:]' '[:upper:]' <<<"${p:0:1}")${p:1}"
  elif [[ $t == *"[Subscription basic]"* ]]; then
    label="Check integrations local stacks and basic subscription"; $logsdb && label+=" and LogsDB"
  elif [ -n "$st" ]; then
    label="Check integrations local stacks - Stack Version v$(cut -d. -f1-2 <<<"$st")"; $logsdb && label+=" - LogsDB"
  fi
  local cur=""
  if [ -n "$label" ]; then
    local f; f=$(schedule)
    cur=$(L="$label" yq -r '.steps[] | select(.label == strenv(L)) | .label + "\t" + (.build.env.STACK_VERSION // "")' "$f" 2>/dev/null | head -1)
    [ -z "$cur" ] && cur=$(L="$label" yq -r '.steps[] | select(.label != null) |
      select((.label | sub("(?P<m>v[0-9]+)\.[0-9]+"; "${m}.Y")) == (strenv(L) | sub("(?P<m>v[0-9]+)\.[0-9]+"; "${m}.Y"))) |
      .label + "\t" + (.build.env.STACK_VERSION // "")' "$f" 2>/dev/null | head -1)
  fi
  [ -n "$cur" ] || cur=$'\t'
  printf '%s|%s|%s|%s|%s|%s\n' "$kind" "$pipe" "$label" "$st" "${cur//$'\t'/|}" "$pkg"
}

# daily_builds <pipeline> <days> -> TSV: number, state, date, label   (main-branch builds triggered by the scheduler)
#   Cached per day, refetched while any build in it is unfinished.
daily_builds() {
  local p=$1 d=${2:-30} f="$CACHE/builds-${1//\//_}-$(date -u +%F)-$2d.tsv"
  if [ ! -s "$f" ] || awk -F'\t' -v re="^($FINAL_STATES)$" '$2 !~ re {u=1} END {exit !u}' "$f"; then
    bk build list -p "$p" --branch main --since "$((d*24))h" --limit 500 -o json 2>/dev/null |
      jq -r '.[] | select(.source=="trigger_job") | [.number, .state, .created_at[:10], ((.message // "") | split("\n")[0])] | @tsv' | sort -n > "$f"
  fi
  cat "$f"
}

# build_jobs <pipeline> <number> -> TSV: package, state  (package check jobs only), cached forever once the build is finished
build_jobs() {
  local f="$CACHE/jobs-${1//\//_}-$2.tsv" j rows
  [ -s "$f" ] && { cat "$f"; return; }
  j=$(bk build view "$2" -p "$1" -o json 2>/dev/null) || return 0
  rows=$(jq -r '.jobs[] | select(.name // "" | startswith("Check integrations ")) | [(.name | split(" ") | last), .state] | @tsv' <<<"$j")
  [ -n "$rows" ] || return 0
  build_finished "$(jq -r .state <<<"$j")" && printf '%s\n' "$rows" > "$f"
  printf '%s\n' "$rows"
}

# reported_issues <pipeline> <number> -> TSV: mode, issue_url, title   (what the report step did for that build)
#   mode: too-many | updated | created | none | no-report-step | running (build unfinished: not cached)
reported_issues() {
  local f="$CACHE/report-${1//\//_}-$2.tsv"
  if [ ! -s "$f" ]; then
    local j job; j=$(bk build view "$2" -p "$1" -o json 2>/dev/null) || j='{}'
    if ! build_finished "$(jq -r '.state // ""' <<<"$j")"; then printf 'running\t\t\n'; return; fi
    job=$(jq -r '.jobs[] | select((.name // "") | test("Report failed tests")) | .id' <<<"$j" | head -1)
    if [ -z "$job" ]; then printf 'no-report-step\t\t\n' > "$f"
    else
      bk job log "$job" -p "$1" -b "$2" --no-timestamps --no-pager -q 2>/dev/null | clean_log |
        awk -v OFS='\t' '
          { sub(/[ \t]+$/, "") }
          /^Skip creating GitHub issues/ { many=1 }
          /^Title: / { t=substr($0, 8); gsub(/^"|"$/, "", t) }
          /^(Updating issue|Created issue:) / { u=$0; sub(/^(Updating issue|Created issue:) /, "", u); sub(/\.\.\.$/, "", u)
            print (many ? "too-many" : (/^Created/ ? "created" : "updated")), u, t; n++ }
          END { if (!n) print "none", "", "" }' > "$f"
    fi
  fi
  cat "$f"
}
