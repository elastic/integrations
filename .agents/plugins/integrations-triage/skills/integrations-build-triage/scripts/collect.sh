#!/usr/bin/env bash
# Step 2: collect failed jobs of one Buildkite build and print one compact row per failed package.
# Usage: [P=elastic/integrations-serverless] [ONLY=pkg1,pkg2] collect.sh <build-number> [out-dir]
#   P: pipeline (serverless daily builds live in elastic/integrations-serverless). ONLY: restrict to these packages (per-package issues).
# Writes build.json, logs/<pkg>.log (ANSI-stripped, line numbers match Buildkite anchors),
# logs/<pkg>.fail (failure block only) and failures.tsv. Read the .fail files, not the .log files.
set -euo pipefail
B=${1:?build number}
P=${P:-elastic/integrations}
OUT=${2:-build/triage/build-$B}
mkdir -p "$OUT/logs"
cd "$OUT"

bk build view "$B" -p "$P" -o json > build.json

jq -r '"# build \(.number) \(.state) | \(.message) | \(.created_at[:16])Z | commit \(.commit[:10]) | \(.branch)",
  "jobs: " + ([.jobs[] | select(.type=="script") | .state] | group_by(.) | map("\(.[0])=\(length)") | join(" "))' build.json

# Failed jobs that are not package checks (CI infra, etc.)
jq -r '.jobs[] | select(.state=="failed" and (.name // "" | startswith("Check integrations ") | not)) | "non-package failure: \(.name)"' build.json

jq -r '.jobs[] | select(.state=="failed" and (.name // "" | startswith("Check integrations "))) | "\(.id) \(.name | split(" ") | last)"' build.json > failed.txt
if [ -n "${ONLY:-}" ]; then
  awk -v only=",$ONLY," 'index(only, "," $2 ",")' failed.txt > failed.only && mv failed.only failed.txt
  echo "restricted to: $ONLY ($(wc -l < failed.txt | tr -d ' ') failed)"
fi

# Parallel download; skip logs already present (re-runs are cheap)
export B P
xargs -P 10 -n 2 sh -c '[ -s "logs/$1.log" ] || bk job log "$0" -p "$P" -b "$B" --no-timestamps --no-pager -q 2>/dev/null |
  sed -e "s/\x1b_//g" -e "s/\x1b\[[0-9;]*[a-zA-Z]//g" -e "s/\r$//" > "logs/$1.log"' < failed.txt

ep=$(grep -h -m1 -o 'elastic-package v[0-9.]*' logs/*.log 2>/dev/null | sort | uniq -c | sort -rn | head -1 | awk '{print $3}')
echo "elastic-package: ${ep:-?}"

printf 'pkg\ttests\tlink\tdetail\n' > failures.tsv
while read -r job pkg; do
  f=logs/$pkg.log
  s=$(grep -n -m1 -E 'test case\(s\) failed|^Error: ' "$f" | cut -d: -f1 || true)
  if [ -z "$s" ]; then
    # No test failure block: infra error (gvm, docker pull, timeout) — keep the last 40 lines
    s=$(( $(wc -l < "$f") - 40 )); [ "$s" -lt 1 ] && s=1; e=$(wc -l < "$f" | tr -d ' ')
  else
    e=$(awk -v s="$s" 'NR>s && /^\^\^\^ \+\+\+/{print NR-1; exit}' "$f"); e=${e:-$((s+30))}
  fi
  sed -n "${s},${e}p" "$f" > "logs/$pkg.fail"
  tests=$(grep '^FAIL: ' "logs/$pkg.fail" | sed -E 's/^FAIL: [^/]*\///' | paste -sd',' - || true)
  detail=$(grep -v -E '^(FAIL:|Error: |[[:space:]]*$)' "logs/$pkg.fail" | head -1 | sed -e 's/^ *//' -e 's/^test case failed: //' -e 's/[0-9]\{4,\}/N/g' | cut -c1-180)
  printf '%s\t%s\t%s\t%s\n' "$pkg" "${tests:-no-test-block}" \
    "https://buildkite.com/$P/builds/$B#$job/$s-$e" "$detail" >> failures.tsv
done < failed.txt

echo "failed packages: $(wc -l < failed.txt | tr -d ' ')  -> $OUT/failures.tsv"
# Compact view grouped by the detail text (first-pass signature grouping)
tail -n +2 failures.tsv | sort -t$'\t' -k4,4 -k1,1 | awk -F'\t' '{printf "%-28s %-45s %s\n", $1, substr($2,1,45), substr($4,1,110)}'
if [ "$P" = elastic/integrations ]; then
  echo "private logs (do NOT open without user go-ahead): gs://ecosystem-ci-internal/buildkite/integrations/main-integrations-$B/insecure-logs/<pkg>/"
else echo "private logs: path for $P not verified; ask before looking"; fi
