#!/usr/bin/env bash
# Backlog sweep: classify every open auto-filed daily-job issue and propose closing the stale ones.
# Usage: [MIN_CLEAN=3] [DAYS=30] sweep.sh [out-dir=build/triage/sweep/<today>]
# Writes sweep.tsv (all issues), close-candidates.tsv, CLOSE_COMMANDS.sh (for a human to review and run) and
# prints counts. Read-only: it never closes or comments. Verdicts (references/auto-issues.md):
#   SUPERSEDED  the job moved to another version/label, so the reporter writes under another title  -> close
#   RETIRED     the job no longer exists in the schedule                                          -> close
#   NOT-FAILING per-package: >= MIN_CLEAN runs since its last failure where the reporter filed per test
#               (or the build passed) and did not touch this issue                                 -> close
#   QUIET       "Too many": >= MIN_CLEAN runs since its last update, none over the threshold        -> close
#   ACTIVE      updated recently, or not enough clean runs to tell ("Too many" nights and failures
#               outside JUnit are unknown: the per-test reporter didn't run)                       -> keep
#   UNKNOWN     title doesn't map to a daily job                                                   -> look
set -euo pipefail
. "$(dirname "$0")/lib.sh"
OUT=${1:-build/triage/sweep/$(date -u +%F)}
MIN=${MIN_CLEAN:-3}; DAYS=${DAYS:-30}
mkdir -p "$OUT"

gh issue list -R "$R" --label automation --label flaky-test --state open --limit 1000 \
  --json number,title,body,updatedAt,assignees > "$OUT/issues.json"
jq -r '.[] | [.number, .title, ((.body | [scan("builds/([0-9]+)")] | last | .[0]) // "0"), (.assignees | length), .updatedAt[:10]] | @tsv' \
  "$OUT/issues.json" > "$OUT/base.tsv"
jq -r '.[].title' "$OUT/issues.json" > "$OUT/open-titles.txt"
echo "open auto-filed issues: $(wc -l < "$OUT/base.tsv" | tr -d ' ')"

# Daily builds of the current schedule labels in the window, and what the reporter did for each failed one (cached)
: > "$OUT/window.tsv"
for p in elastic/integrations elastic/integrations-serverless; do
  daily_builds "$p" "$DAYS" | awk -F'\t' -v OFS='\t' -v p="$p" '{print p, $0}' >> "$OUT/window.tsv"
done
export -f reported_issues clean_log; export R CACHE
awk -F'\t' '$3!="passed" {print $1, $2}' "$OUT/window.tsv" |
  xargs -P 6 -n 2 bash -c 'reported_issues "$0" "$1" >/dev/null 2>&1 || true'
# window rows: pipeline, number, state, date, label, mode (passed | too-many | per-package | none | no-report-step)
while IFS=$'\t' read -r p n st d l; do
  m=passed; [ "$st" = passed ] || { m=$(reported_issues "$p" "$n" | cut -f1 | head -1); [ "$m" = created ] || [ "$m" = updated ] && m=per-package; }
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$p" "$n" "$st" "$d" "$l" "$m"
done < "$OUT/window.tsv" > "$OUT/window-modes.tsv"

printf 'issue\tkind\tverdict\tdetail\tsuccessor\tassignees\tlast_build\ttitle\n' > "$OUT/sweep.tsv"
while IFS=$'\t' read -r num title lb na upd; do
  IFS='|' read -r kind pipe label ist curl curst pkg <<<"$(title_job "$title")"
  url="https://buildkite.com/$pipe/builds/$lb"; succ=""; verdict=ACTIVE; detail=""
  if [ "$kind" = other ] || [ -z "$label" ]; then verdict=UNKNOWN; detail="title doesn't map to a daily job"
  elif [ -z "$curl" ]; then verdict=RETIRED; detail="'$label' is no longer in the schedule"
  elif [ "$curl" != "$label" ] || { [ -n "$ist" ] && [ -n "$curst" ] && [ "$curst" != "$ist" ]; }; then
    verdict=SUPERSEDED; detail="moved from ${ist:-$label} to ${curst:-$curl}"
    nt=${title/"[Stack $ist]"/"[Stack $curst]"}
    grep -qxF -- "$nt" "$OUT/open-titles.txt" && succ=$(jq -r --arg t "$nt" '.[] | select(.title == $t) | "#\(.number)"' "$OUT/issues.json" | head -1)
  else
    # runs of the current job after the issue's last failing build
    read -r clean unknown latest <<<"$(awk -F'\t' -v p="$pipe" -v l="$curl" -v b="${lb:-0}" '
      $1==p && $5==l && $2>b { if ($6=="passed" || $6=="per-package") c++; else u++; last=$2 "@" $4 }
      END { print c+0, u+0, (last ? last : "-") }' "$OUT/window-modes.tsv")"
    if [ "$kind" = too-many ]; then
      [ "$clean" -ge "$MIN" ] || [ $((clean + unknown)) -ge "$MIN" ] && { verdict=QUIET; detail="$((clean + unknown)) runs since, none over the threshold (latest ${latest/@/ on })"; }
    else
      if [ "$clean" -ge "$MIN" ]; then
        verdict=NOT-FAILING; lbn=${latest%@*}; lbd=${latest#*@}
        detail="$clean later runs of \`$curl\` passed or reported only other tests (latest: https://buildkite.com/$pipe/builds/$lbn on $lbd)"
        [ "$unknown" -gt 0 ] && detail+="; $unknown more runs could not be checked"
      fi
    fi
    [ "$verdict" = ACTIVE ] && detail="$clean clean / $unknown unknown runs since its last failure"
  fi
  # never leave a field empty: bash `read` with IFS=tab collapses empty fields
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$num" "$kind" "$verdict" "${detail:--}" "${succ:--}" "$na" "$url" "$title"
done < "$OUT/base.tsv" >> "$OUT/sweep.tsv"

awk -F'\t' 'NR==1 || $3 ~ /^(SUPERSEDED|RETIRED|NOT-FAILING|QUIET)$/' "$OUT/sweep.tsv" > "$OUT/close-candidates.tsv"

# Commands for a human to review and run. Ecosystem closes these as completed with a "Closing this issue since …" comment.
{
  echo "#!/usr/bin/env bash"
  echo "# Generated by sweep.sh on $(date -u +%F). REVIEW BEFORE RUNNING: each line closes one issue with a comment."
  echo "# Issues with assignees are commented out: check with the assignee first."
  echo "set -euo pipefail"
  tail -n +2 "$OUT/close-candidates.tsv" | while IFS=$'\t' read -r num kind verdict detail succ na url title; do
    case $verdict in
      SUPERSEDED) c="Closing this issue since the daily job that filed it $detail, so it no longer updates this issue (the reporter matches issues by exact title, which includes the stack version). Last failing build: $url."
                  [ "$succ" != - ] && c+=" It is tracked now in $succ." || c+=" If it still fails, the daily job files a new issue with the current version in its title." ;;
      RETIRED)    c="Closing this issue since $detail. Last failing build: $url." ;;
      NOT-FAILING) c="Closing this issue since the test has not failed again: $detail. Last failing build: $url. If it fails again, the daily job opens a new issue that links to this one." ;;
      QUIET)      c="Closing this issue since the latest build failing more than 30 tests was $url; $detail, so their failures are tracked in per-package issues." ;;
    esac
    line="gh issue close $num -R $R --reason completed --comment '${c//\'/\'\\\'\'}'"
    if [ "$kind" = too-many ]; then echo "# \"Too many\" issue: use build/triage/issue-$num/COMMENT_DRAFT_close_superseded.md (or write it with /integrations-triage:triage-nightly $num)"
    elif [ "$na" -gt 0 ]; then echo "# assigned: $line"
    else echo "$line"; fi
  done
} > "$OUT/CLOSE_COMMANDS.sh"

echo "# verdicts"; tail -n +2 "$OUT/sweep.tsv" | cut -f2,3 | sort | uniq -c | sort -rn
echo "# close candidates by title prefix"
tail -n +2 "$OUT/close-candidates.tsv" | awk -F'\t' '{ t=$8; sub(/\[[a-z0-9_]+\] Failing test daily.*/, "[pkg] Failing test daily", t); print $3 "\t" t }' | sort | uniq -c | sort -rn | head -20
echo "-> $OUT/sweep.tsv, $OUT/close-candidates.tsv ($(($(wc -l < "$OUT/close-candidates.tsv") - 1))), $OUT/CLOSE_COMMANDS.sh"
