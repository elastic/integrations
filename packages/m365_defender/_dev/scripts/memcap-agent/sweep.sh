#!/usr/bin/env bash
#
# m365_defender agentless inputs - memory sweep driver.
#
# Runs ./run.sh several times at a BIG cap (so nothing OOMs) across a range of
# page sizes for one STREAM, then fits memory.peak = base + k * raw_page and
# derives the OOM boundary for the real caps (1Gi enforced today, 512Mi target).
#
# Why a big cap: an OOM run pins memory.peak at the cap and tells you nothing
# about the true peak. Non-OOM runs give the real multiplier k; the boundary is
# then just (cap - base) / k.
#
# Override via env:
#   STREAM=alert    SWEEP_EVENTS="250 500 1000 2000" ./sweep.sh
#   STREAM=incident SWEEP_EVENTS="10 25 50 100" ALERTS_PER_INCIDENT=100 ./sweep.sh
#   STREAM=vulnerability SWEEP_EVENTS="2500 5000 10000 20000" ./sweep.sh
#   SWEEP_CAP=6g STACK_VERSION=9.4.2 STREAM=alert ./sweep.sh

set -euo pipefail

STREAM="${STREAM:?set STREAM=alert|incident|vulnerability}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SWEEP_CAP="${SWEEP_CAP:-6g}"                        # big enough that no point OOMs
export STACK_VERSION="${STACK_VERSION:-9.4.2}"
export ALERTS_PER_INCIDENT="${ALERTS_PER_INCIDENT:-100}"

case "$STREAM" in
  alert)         SWEEP_EVENTS="${SWEEP_EVENTS:-250 500 1000 2000}" ;;
  incident)      SWEEP_EVENTS="${SWEEP_EVENTS:-10 25 50 100}" ;;
  vulnerability) SWEEP_EVENTS="${SWEEP_EVENTS:-2500 5000 10000 20000}" ;;
  *) echo "unknown STREAM=$STREAM"; exit 1 ;;
esac

LOGDIR="$HERE/logs"
mkdir -p "$LOGDIR"
TS="$(date +%Y%m%d-%H%M%S)"
LOG="$LOGDIR/sweep-$STREAM-$TS.log"
CSV="$LOGDIR/sweep-$STREAM-$TS.csv"

exec > >(tee -a "$LOG") 2>&1

echo "=================================================================="
echo " m365_defender memory sweep   $(date)"
echo " stream        : $STREAM"
echo " agent version : $STACK_VERSION"
echo " sweep cap     : $SWEEP_CAP (chosen so runs do NOT OOM)"
echo " page sizes    : $SWEEP_EVENTS"
[ "$STREAM" = "incident" ] && echo " alerts/incid. : $ALERTS_PER_INCIDENT"
echo " log           : $LOG"
echo " csv           : $CSV"
echo "=================================================================="

echo "records,raw_page_bytes,memory_peak_bytes,oom" > "$CSV"
rows=""   # "page peak" pairs for the fit (non-OOM only)

for N in $SWEEP_EVENTS; do
  echo
  echo ">>>>>> run: STREAM=$STREAM TOTAL_EVENTS=$N MEM_LIMIT=$SWEEP_CAP <<<<<<"
  runlog="$LOGDIR/run-$STREAM-$TS-$N.log"
  STREAM="$STREAM" MEM_LIMIT="$SWEEP_CAP" TOTAL_EVENTS="$N" "$HERE/run.sh" 2>&1 | tee "$runlog" || true

  page=$(grep 'raw page bytes' "$runlog" | grep -oE '[0-9]+' | head -1 || echo 0)
  peak=$(grep 'memory.peak'    "$runlog" | grep -oE '[0-9]+' | head -1 || echo 0)
  oom=$(grep 'OOM killed'      "$runlog" | grep -oE 'true|false' | head -1 || echo unknown)
  page=${page:-0}; peak=${peak:-0}; oom=${oom:-unknown}
  echo "$N,$page,$peak,$oom" >> "$CSV"
  echo ">>>>>> parsed: records=$N page=$page peak=$peak oom=$oom"

  if [ "$oom" = "true" ]; then
    echo "   (excluded from fit: OOM pins memory.peak at the cap - raise SWEEP_CAP)"
  elif [ "$page" -gt 0 ] && [ "$peak" -gt 0 ]; then
    rows="$rows$page $peak"$'\n'
  fi
done

echo
echo "=================================================================="
echo " SWEEP SUMMARY ($STREAM)"
echo "=================================================================="
printf ' %-8s %-14s %-14s %-6s %-10s\n' records raw_page_MB peak_MB oom peak/page
awk -F, 'NR>1{printf " %-8s %-14.1f %-14.1f %-6s %-10s\n", $1, $2/1048576, $3/1048576, $4, ($2>0?sprintf("%.2fx",$3/$2):"-")}' "$CSV"

# Linear fit peak = base + k*page over the non-OOM points, then boundaries.
printf '%s' "$rows" | awk -v cap1=1073741824 -v cap2=536870912 '
  NF==2 { n++; sx+=$1; sy+=$2; sxx+=$1*$1; sxy+=$1*$2 }
  END {
    if (n < 2) { print "\nNeed >=2 non-OOM points for a fit. Raise SWEEP_CAP or lower record counts."; exit }
    k = (n*sxy - sx*sy) / (n*sxx - sx*sx)
    b = (sy - k*sx) / n
    printf "\nFit over %d non-OOM points:\n", n
    printf "  memory.peak ~= %.1f MB baseline + %.2f x raw_page\n", b/1048576, k
    if (k > 0) {
      printf "\nDerived OOM boundary (largest raw page that fits):\n"
      printf "  1Gi  cap: ~%.1f MB raw page\n", (cap1-b)/k/1048576
      printf "  512Mi cap: ~%.1f MB raw page\n", (cap2-b)/k/1048576
      printf "\n(These are RAW page sizes. Compare against the realistic max page\n"
      printf " this stream can return to judge whether production can reach it.)\n"
    }
  }'

echo
echo "Full log : $LOG"
echo "CSV      : $CSV"
echo "Per-run  : $LOGDIR/run-$STREAM-$TS-*.log"
