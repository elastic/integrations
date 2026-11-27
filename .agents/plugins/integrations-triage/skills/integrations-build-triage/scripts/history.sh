#!/usr/bin/env bash
# Step 4: per-package pass/fail history of the same nightly, from job states only (no logs).
# Usage: history.sh [-p <pipeline>] [-k pkg1,pkg2] <build-number> [days=30] [out-dir]
#   packages default to the failed jobs of <build>; -k overrides (per-package issues). P / PKGS env vars also work.
# Prints one row per package: timeline oldest→newest (X failed, . passed, - not run) and the first
# build of the current failing streak. Use that build to bisect (upstream commits, package changes).
set -euo pipefail
while getopts p:k: o; do case $o in p) P=$OPTARG ;; k) PKGS=$OPTARG ;; *) exit 2 ;; esac; done; shift $((OPTIND-1))
B=${1:?build number}; DAYS=${2:-30}
P=${P:-elastic/integrations}
OUT=${3:-build/triage/build-$B}/history
mkdir -p "$OUT"

bk build view "$B" -p "$P" -o json > "$OUT/ref.json"
msg=$(jq -r .message "$OUT/ref.json")
if [ -n "${PKGS:-}" ]; then tr ',' '\n' <<<"$PKGS" | sort > "$OUT/pkgs.txt"
else jq -r '.jobs[] | select(.state=="failed" and (.name // "" | startswith("Check integrations "))) | .name | split(" ") | last' "$OUT/ref.json" | sort > "$OUT/pkgs.txt"; fi

bk build list -p "$P" --branch main --since "$((DAYS*24))h" --limit 300 -o json |
  jq -r --arg m "$msg" --argjson b "$B" '[.[] | select(.message==$m and .number<=$b)] | sort_by(.number) | .[] | "\(.number) \(.created_at[:10])"' > "$OUT/builds.txt"

export P OUT
cut -d' ' -f1 "$OUT/builds.txt" | xargs -P 8 -I{} sh -c '[ -s "$OUT/{}.tsv" ] || bk build view {} -p "$P" -o json 2>/dev/null |
  jq -r ".jobs[] | select(.name // \"\" | startswith(\"Check integrations \")) | [(.name|split(\" \")|last), .state] | @tsv" > "$OUT/{}.tsv"'

echo "# \"$msg\": $(wc -l < "$OUT/builds.txt" | tr -d ' ') builds, $(head -1 "$OUT/builds.txt" | cut -d' ' -f2) → $(tail -1 "$OUT/builds.txt" | cut -d' ' -f2)"
while read -r pkg; do
  line=""; first=""; firstd=""
  while read -r n d; do
    st=$(awk -F'\t' -v p="$pkg" '$1==p{print $2}' "$OUT/$n.tsv" | head -1)
    case "$st" in failed) c=X; [ -z "$first" ] && { first=$n; firstd=$d; } ;; passed) c=.; first="" ;; *) c=- ;; esac
    line="$line$c"
  done < "$OUT/builds.txt"
  printf '%-28s %s  streak since %s (%s)\n' "$pkg" "$line" "${first:-?}" "${firstd:-?}"
done < "$OUT/pkgs.txt" | sort -k4,4n
