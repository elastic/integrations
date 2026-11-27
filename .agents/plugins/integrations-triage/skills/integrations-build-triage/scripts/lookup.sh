#!/usr/bin/env bash
# Is there already an issue or PR for each problem, and what is its status?
# Usage: lookup.sh <match.tsv>      (output of match.sh)
#  - tracked refs (owner/repo#n): state, assignees, last update, and PRs that reference it (state/draft/review/merged)
#  - packages without a tracked ref (UNKNOWN, SIG:*, CHANGED, or KNOWN with none): open issues and PRs mentioning the package
#    in elastic/integrations, auto-filed "Failing test daily" issues counted separately.
# Read-only. Search API is rate limited (30/min), so searches are throttled.
set -euo pipefail
M=${1:?match.tsv}

ref_status() { # owner/repo#n
  local repo=${1%#*} n=${1##*#} j kind
  j=$(gh api "repos/$repo/issues/$n" 2>/dev/null) || { printf '  %s  ?\n' "$1"; return; }
  kind=$(jq -r 'if .pull_request then "PR" else "issue" end' <<<"$j")
  if [ "$kind" = PR ]; then
    gh pr view "$n" -R "$repo" --json state,isDraft,reviewDecision,mergedAt,updatedAt,title \
      --jq '"  '"$1"'  PR \(.state)\(if .isDraft then " draft" else "" end) review=\(.reviewDecision // "-") \(if .mergedAt then "merged " + .mergedAt[:10] else "updated " + .updatedAt[:10] end) | \(.title[:70])"'
  else
    jq -r '"  '"$1"'  issue \(.state | ascii_upcase) assignees=\([.assignees[].login] | join(",") | if .=="" then "none" else . end) updated \(.updated_at[:10]) | \(.title[:70])"' <<<"$j"
    gh api "repos/$repo/issues/$n/timeline?per_page=100" --jq '.[] | select(.event=="cross-referenced" and .source.issue.pull_request) |
      .source.issue | "      ↳ PR \(.repository.full_name // "")#\(.number) \(.state)\(if .pull_request.merged_at then " merged " + .pull_request.merged_at[:10] else "" end)\(if .draft then " draft" else "" end) | \(.title[:60])"' 2>/dev/null | sort -u | head -5
  fi
}

echo "## Tracked refs"
awk -F'\t' 'NR>1 && $5!="" {n=split($5,a,","); for(i=1;i<=n;i++) print a[i]}' "$M" | sort -u | while read -r r; do
  pk=$(awk -F'\t' -v r="$r" 'NR>1 && index(","$5",", ","r",") {printf "%s ", $1}' "$M")
  echo "- $r  (${pk% })"; ref_status "$r"
done

echo "## Packages without a tracked issue"
awk -F'\t' 'NR>1 && $5=="" && $2!="DROPPED" {print $1"\t"$2}' "$M" | while IFS=$'\t' read -r pkg st; do
  iss=$(gh search issues -R elastic/integrations "$pkg in:title" --state open --json number,title,updatedAt --limit 30 2>/dev/null || echo '[]')
  flaky=$(jq '[.[] | select(.title | test("Failing test daily"))] | length' <<<"$iss")
  echo "- $pkg [$st]: $flaky open auto-filed flaky issue(s)"
  jq -r '.[] | select(.title | test("Failing test daily|Too many packages") | not) | "    issue #\(.number) updated \(.updatedAt[:10]) | \(.title[:80])"' <<<"$iss" | head -5
  gh search prs -R elastic/integrations "$pkg in:title" --state open --json number,title,isDraft,updatedAt --limit 5 2>/dev/null |
    jq -r '.[] | "    PR #\(.number)\(if .isDraft then " draft" else "" end) updated \(.updatedAt[:10]) | \(.title[:80])"'
  sleep 4
done
