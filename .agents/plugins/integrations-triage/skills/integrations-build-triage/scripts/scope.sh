#!/usr/bin/env bash
# Step 1: scope an auto-filed daily-job issue: "Too many packages failing in daily job" or "[<pkg>] Failing test daily: …".
# Usage: scope.sh <issue-number> [out-dir]
# Writes issue.json, edits.json, packages.txt, nights.tsv, scope.env to out-dir and prints a compact summary.
# scope.env (sourceable): KIND PIPELINE REF_BUILD STATUS (ACTIVE|SUPERSEDED|RETIRED|UNKNOWN) LATEST (verdict) SUCCESSOR
set -euo pipefail
. "$(dirname "$0")/lib.sh"
N=${1:?issue number}
OUT=${2:-build/triage/issue-$N}
mkdir -p "$OUT"

gh issue view "$N" -R "$R" --json title,state,body,labels,updatedAt,comments,assignees > "$OUT/issue.json"
gh api graphql -f query="{repository(owner:\"elastic\",name:\"integrations\"){issue(number:$N){userContentEdits(first:60){nodes{editedAt diff}}}}}" > "$OUT/edits.json"

TITLE=$(jq -r .title "$OUT/issue.json")
IFS='|' read -r KIND PIPELINE LABEL ISSUE_STACK NEW_LABEL NEW_STACK PKG <<<"$(title_job "$TITLE")"

# Too many: the package list. Per-package: the one package.
pkgs() { { grep -E '^    - ' || true; } | { grep -v '@' || true; } | sed 's/^ *- //' | sort -u; }
if [ "$KIND" = per-package ]; then echo "$PKG" > "$OUT/packages.txt"; else jq -r .body "$OUT/issue.json" | pkgs > "$OUT/packages.txt"; fi

# One row per failing night (oldest first): date, newest build in that edit, package count
jq -r '.data.repository.issue.userContentEdits.nodes | reverse | .[] |
  [.editedAt[:16], ((.diff | [scan("builds/([0-9]+)")] | last | .[0]) // "-"), .diff] | @json' "$OUT/edits.json" |
while read -r row; do
  d=$(jq -r '.[0]' <<<"$row"); b=$(jq -r '.[1]' <<<"$row")
  c=$(jq -r '.[2]' <<<"$row" | pkgs | wc -l | tr -d ' ')
  printf '%s\t%s\t%s\n' "$d" "$b" "$c"
done > "$OUT/nights.tsv"

B=$(jq -r .body "$OUT/issue.json" | grep -o 'builds/[0-9]*' | tail -1 | cut -d/ -f2)
LASTEDIT=$(tail -1 "$OUT/nights.tsv" | cut -f1); [ -n "$LASTEDIT" ] || LASTEDIT="$(jq -r '.updatedAt[:16]' "$OUT/issue.json") (never edited)"

echo "# $(jq -r '"\(.title) [\(.state)] updated \(.updatedAt[:16])"' "$OUT/issue.json")"
echo "kind:            $KIND  (pipeline $PIPELINE)"
echo "last reporter edit: $LASTEDIT  (updatedAt can be later: bots, e.g. the stale bot, also bump it)"
jq -r .body "$OUT/issue.json" | grep -m1 'Stack version' || true
[ "$KIND" = per-package ] && jq -r .body "$OUT/issue.json" | grep -E '^- (Failing test|DataStream):' || true
echo "first build:     $(jq -r .body "$OUT/issue.json" | grep -m1 -o 'First build failed.*builds/[0-9]*' | grep -o '[0-9]*$' || echo '?')"
echo "reference build: $B  (newest = last URL)"
echo "packages:        $(wc -l < "$OUT/packages.txt" | tr -d ' ') -> $OUT/packages.txt"
if [ "$KIND" = too-many ]; then
  prev=$(jq -r '.data.repository.issue.userContentEdits.nodes[1].diff // ""' "$OUT/edits.json" | pkgs)
  first=$(jq -r '.data.repository.issue.userContentEdits.nodes[-1].diff // ""' "$OUT/edits.json" | pkgs)
  echo "## per-night (date, build, #pkgs): $OUT/nights.tsv"; tail -8 "$OUT/nights.tsv"
  echo "## new vs previous night:";  comm -13 <(echo "$prev")  "$OUT/packages.txt" | paste -sd' ' - || true
  echo "## fixed vs previous night:"; comm -23 <(echo "$prev") "$OUT/packages.txt" | paste -sd' ' - || true
  echo "## new vs first build:";     comm -13 <(echo "$first") "$OUT/packages.txt" | paste -sd' ' - || true
else
  echo "## failing nights (date, build): $(cut -f1,2 "$OUT/nights.tsv" | tail -6 | tr '\t' ' ' | paste -sd',' -)"
fi

# Is the job that feeds this issue still alive, and is this issue still the one it writes to?
# The reporter matches issues by exact title, and the title embeds STACK_VERSION (references/auto-issues.md).
echo "## triggering job:"
TODAY=$(date -u +%F); STATUS=UNKNOWN; LATEST=""; SUCC=""
if [ -z "$LABEL" ]; then
  echo "job status: UNKNOWN (no daily job matches this title)"
elif [ -z "$NEW_LABEL" ]; then
  STATUS=RETIRED
  echo "  label: $LABEL"
  echo "job status: RETIRED (no '$LABEL' step, or one of its family, in $SCHED on main)"
  echo "  -> $B is the final build. Say so at the top of every draft and propose closing this issue"
else
  echo "  label: $LABEL"
  STATUS=ACTIVE
  if [ "$NEW_LABEL" != "$LABEL" ] || { [ -n "$ISSUE_STACK" ] && [ -n "$NEW_STACK" ] && [ "$NEW_STACK" != "$ISSUE_STACK" ]; }; then
    STATUS=SUPERSEDED
    MAINREF=$(git rev-parse -q --verify main >/dev/null && echo main || echo --all)
    c=$(git log "$MAINREF" -1 --format='%h %ad %s' --date=short -S "${ISSUE_STACK:-$LABEL}" -- "$SCHED" 2>/dev/null || true)
    NEW_TITLE=${TITLE/"[Stack $ISSUE_STACK]"/"[Stack $NEW_STACK]"}
    SUCC=$(gh issue list -R "$R" --state all --search "\"$NEW_TITLE\" in:title" --limit 20 --json number,title,state,updatedAt \
      -q "map(select(.title == \"$NEW_TITLE\")) | first // empty | \"#\(.number) \(.state) updated \(.updatedAt[:10])\"" 2>/dev/null || true)
    echo "job status: SUPERSEDED (job now '$NEW_LABEL' on ${NEW_STACK:-?}; this issue is for ${ISSUE_STACK:-?}; changed by: ${c:-? (not in local history)})"
    echo "  successor issue: ${SUCC:-none} — title \"$NEW_TITLE\""
    if [ -z "$SUCC" ] && [ "$KIND" = too-many ]; then
      PREFIX=${NEW_TITLE%%Too many packages failing in daily job}
      np=$(gh issue list -R "$R" --state open --label automation --search "\"$PREFIX\" \"Failing test daily\" in:title" --limit 200 --json title \
        -q "map(select(.title | startswith(\"$PREFIX[\"))) | length" 2>/dev/null || echo '?')
      echo "  no successor 'Too many' issue: nights stayed <= CI_MAX_TESTS_REPORTED; $np open per-package issues titled \"$PREFIX[<pkg>] Failing test daily: …\""
    fi
    echo "  -> $B is the final build for this issue. Say so at the top of every draft, name the successor, and propose closing this one"
  fi
  last=$(daily_builds "$PIPELINE" 3 | awk -F'\t' -v l="$NEW_LABEL" '$4==l' | tail -1)
  if [ -z "$last" ]; then
    LATEST=NOT-RUN; echo "latest run: NOT-RUN (no '$NEW_LABEL' build in the last 3 days; the schedule runs Mon-Fri)"
  else
    IFS=$'\t' read -r lb ls ld _ <<<"$last"
    case "$ls:$ld" in
      passed:"$TODAY") LATEST=PASSED-TODAY ;;
      failed:"$TODAY") LATEST=FAILED-TODAY ;;
      *:"$TODAY") LATEST="RUNNING-OR-OTHER-TODAY" ;;
      *) LATEST="NOT-RUN-TODAY" ;;
    esac
    echo "latest run: $LATEST  build $lb $ld $ls  (reference build $B)"
    if [ "$STATUS" = ACTIVE ] && [ "$lb" != "$B" ]; then
      if [ "$KIND" = per-package ]; then
        ps=$(build_jobs "$PIPELINE" "$lb" | awk -F'\t' -v p="$PKG" '$1==p{print $2}' | head -1)
        mode=$(reported_issues "$PIPELINE" "$lb" | cut -f1 | head -1)
        echo "  -> $PKG in build $lb: ${ps:-not run}; report step: $mode"
        [ "$ps" = passed ] && echo "     the package passed: candidate to close if it keeps passing (sweep.sh counts the nights)"
        [ "$ps" = failed ] && [ "$mode" = too-many ] && echo "     it failed, but that night went to the 'Too many' issue, so this issue was not updated"
        [ "$ps" = failed ] && [ "$mode" != too-many ] && echo "     it failed in a different test (another per-package issue), or the report step failed"
      elif [ "$LATEST" = FAILED-TODAY ]; then
        echo "  -> failed today but this issue still points at $B: that night had <= CI_MAX_TESTS_REPORTED failing tests (per-package issues filed instead), or the report step failed/is still running"
      fi
    fi
  fi
fi
printf 'KIND=%s\nPIPELINE=%s\nREF_BUILD=%s\nSTATUS=%s\nLATEST=%s\nSUCCESSOR=%q\n' "$KIND" "$PIPELINE" "$B" "$STATUS" "$LATEST" "$SUCC" > "$OUT/scope.env"

echo "## issues/PRs referenced in comments (state):"
jq -r '.comments[].body' "$OUT/issue.json" |
  grep -oE '(github\.com/[a-z0-9_.-]+/[a-z0-9_.-]+/(issues|pull)/[0-9]+|[^a-z/]#[0-9]{3,6})' |
  sed -E 's#github\.com/([^/]+/[^/]+)/(issues|pull)/#\1 #; s#^[^a-z]?\##elastic/integrations #' | sort -u |
  while read -r repo num; do
    s=$(gh issue view "$num" -R "$repo" --json state,title -q '"\(.state) \(.title[:70])"' 2>/dev/null || echo '?')
    printf '  %s#%s %s\n' "$repo" "$num" "$s"
  done || true
