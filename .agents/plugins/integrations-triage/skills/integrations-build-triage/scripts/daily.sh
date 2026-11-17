#!/usr/bin/env bash
# Builds first: what did the daily schedule run on <date>, what failed, and which issues did each build report to?
# Usage: daily.sh [YYYY-MM-DD=today UTC] [out-dir=build/triage/daily/<date>]
# Writes builds.tsv (label, pipeline, build, state, failed_pkgs, report_mode, issues) and issues.tsv
# (build, pipeline, mode, issue, title), and prints a compact table. Read-only. See references/auto-issues.md.
#   report_mode: too-many (one "Too many" issue) | per-package (Failing test daily issues) | none (failed, nothing
#   filed: failures outside JUnit) | no-report-step | - (passed/not run)
set -euo pipefail
. "$(dirname "$0")/lib.sh"
D=${1:-$(date -u +%F)}
OUT=${2:-build/triage/daily/$D}
mkdir -p "$OUT"

# Scheduler runs started that day (they run 00:30-04:30 UTC, Mon-Fri)
age_h=$(( ( $(date -u +%s) - $(date -u -j -f %F "$D" +%s 2>/dev/null || date -u -d "$D" +%s) ) / 3600 + 30 ))
bk build list -p elastic/integrations-schedule-daily --branch main --since "${age_h}h" --limit 50 -o json 2>/dev/null |
  jq -r --arg d "$D" '.[] | select(.created_at[:10] == $d) | [.number, ((.message // "") | split("\n")[0])] | @tsv' > "$OUT/scheduler.tsv"
[ -s "$OUT/scheduler.tsv" ] || { echo "no scheduler runs on $D (weekend, or not started yet)"; exit 0; }

: > "$OUT/triggers.tsv"
while IFS=$'\t' read -r sn smsg; do
  bk build view "$sn" -p elastic/integrations-schedule-daily -o json 2>/dev/null |
    jq -r '.jobs[] | select(.type=="trigger" and .triggered_build != null) |
      [.name, (.triggered_build.web_url | capture("buildkite.com/(?<p>[^/]+/[^/]+)/builds").p), .triggered_build.number] | @tsv' >> "$OUT/triggers.tsv"
done < "$OUT/scheduler.tsv"

printf 'label\tpipeline\tbuild\tstate\tfailed_pkgs\treport_mode\tissues\n' > "$OUT/builds.tsv"
printf 'build\tpipeline\tmode\tissue\ttitle\n' > "$OUT/issues.tsv"
while IFS=$'\t' read -r label pipe n; do
  state=$(bk build view "$n" -p "$pipe" -o json 2>/dev/null | jq -r .state)
  nf=$(build_jobs "$pipe" "$n" | awk -F'\t' '$2=="failed" || $2=="timed_out"' | wc -l | tr -d ' ')
  # serverless runs every package in one job ("Check integrations in serverless"): no per-package jobs
  [ "$pipe" = elastic/integrations-serverless ] && nf="$nf(single-job:$(build_jobs "$pipe" "$n" | awk -F'\t' '$1=="serverless"{print $2}'))"
  mode=-; iss=""
  if [ "$state" != passed ]; then
    rep=$(reported_issues "$pipe" "$n")
    mode=$(cut -f1 <<<"$rep" | head -1); [ "$mode" = created ] || [ "$mode" = updated ] && mode=per-package
    awk -F'\t' -v OFS='\t' -v b="$n" -v p="$pipe" '$2!="" {u=$2; sub(/.*\//, "", u); print b, p, $1, u, $3}' <<<"$rep" >> "$OUT/issues.tsv"
    iss=$(awk -F'\t' '$2!="" {u=$2; sub(/.*\//, "#", u); printf "%s%s", s, u; s=","}' <<<"$rep")
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$label" "$pipe" "$n" "$state" "$nf" "$mode" "$iss" >> "$OUT/builds.tsv"
done < "$OUT/triggers.tsv"

echo "# daily jobs on $D: $(($(wc -l < "$OUT/builds.tsv") - 1)) builds -> $OUT/builds.tsv, $OUT/issues.tsv"
tail -n +2 "$OUT/builds.tsv" | awk -F'\t' '{ printf "%-70s %-30s %6s %-7s failed=%-3s %-12s %s\n", $1, $2, $3, $4, $5, $6, substr($7,1,60) }'
echo "only triggered builds are listed. Serverless runs all packages in one job: per-package triage (collect.sh) doesn't apply."
