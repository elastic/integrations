#!/usr/bin/env bash
#
# o365 CEL input - memory sweep driver.
#
# Runs ./run.sh several times at a BIG cap (so nothing OOMs) across a range of
# blob sizes, then fits memory.peak = base + k * raw_blob and derives the OOM
# boundary for the real caps (1Gi enforced today, 512Mi forward target).
#
# Why a big cap: an OOM run pins memory.peak at the cap and tells you nothing
# about the true peak. Non-OOM runs give the real multiplier k; the boundary is
# then just (cap - base) / k.
#
# Everything (per-run output + the final fit) is tee'd to logs/sweep-<ts>.log.
#
# Override via env:
#   SWEEP_CAP=6g SWEEP_EVENTS="2000 5000 10000 20000" ./sweep.sh
#   STACK_VERSION=9.4.2 ./sweep.sh

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SWEEP_CAP="${SWEEP_CAP:-6g}"                        # big enough that no point OOMs
SWEEP_EVENTS="${SWEEP_EVENTS:-2000 5000 10000 20000}"
export STACK_VERSION="${STACK_VERSION:-9.4.2}"

LOGDIR="$HERE/logs"
mkdir -p "$LOGDIR"
TS="$(date +%Y%m%d-%H%M%S)"
LOG="$LOGDIR/sweep-$TS.log"
CSV="$LOGDIR/sweep-$TS.csv"

# tee all of this script's stdout/stderr to the master log.
exec > >(tee -a "$LOG") 2>&1

echo "=================================================================="
echo " o365 memory sweep   $(date)"
echo " agent version : $STACK_VERSION"
echo " sweep cap     : $SWEEP_CAP (chosen so runs do NOT OOM)"
echo " event counts  : $SWEEP_EVENTS"
echo " log           : $LOG"
echo " csv           : $CSV"
echo "=================================================================="

echo "events,raw_blob_bytes,memory_peak_bytes,oom" > "$CSV"
rows=""   # "blob peak" pairs for the fit (non-OOM only)

for N in $SWEEP_EVENTS; do
  echo
  echo ">>>>>> run: TOTAL_EVENTS=$N MEM_LIMIT=$SWEEP_CAP <<<<<<"
  runlog="$LOGDIR/run-$TS-$N.log"
  # run.sh regenerates the corpus + mock + capped agent each invocation and
  # cleans up its own containers on exit.
  MEM_LIMIT="$SWEEP_CAP" TOTAL_EVENTS="$N" "$HERE/run.sh" 2>&1 | tee "$runlog" || true

  blob=$(grep 'raw blob bytes' "$runlog" | grep -oE '[0-9]+' | head -1 || echo 0)
  peak=$(grep 'memory.peak'    "$runlog" | grep -oE '[0-9]+' | head -1 || echo 0)
  oom=$(grep 'OOM killed'      "$runlog" | grep -oE 'true|false' | head -1 || echo unknown)
  blob=${blob:-0}; peak=${peak:-0}; oom=${oom:-unknown}
  echo "$N,$blob,$peak,$oom" >> "$CSV"
  echo ">>>>>> parsed: events=$N blob=$blob peak=$peak oom=$oom"

  if [ "$oom" = "true" ]; then
    echo "   (excluded from fit: OOM pins memory.peak at the cap - raise SWEEP_CAP)"
  elif [ "$blob" -gt 0 ] && [ "$peak" -gt 0 ]; then
    rows="$rows$blob $peak"$'\n'
  fi
done

echo
echo "=================================================================="
echo " SWEEP SUMMARY"
echo "=================================================================="
printf ' %-8s %-14s %-14s %-6s %-10s\n' events raw_blob_MB peak_MB oom peak/blob
awk -F, 'NR>1{printf " %-8s %-14.1f %-14.1f %-6s %-10s\n", $1, $2/1048576, $3/1048576, $4, ($2>0?sprintf("%.2fx",$3/$2):"-")}' "$CSV"

# Linear fit peak = base + k*blob over the non-OOM points, then boundaries.
printf '%s' "$rows" | awk -v cap1=1073741824 -v cap2=536870912 '
  NF==2 { n++; sx+=$1; sy+=$2; sxx+=$1*$1; sxy+=$1*$2 }
  END {
    if (n < 2) { print "\nNeed >=2 non-OOM points for a fit. Raise SWEEP_CAP or lower event counts."; exit }
    k = (n*sxy - sx*sy) / (n*sxx - sx*sx)
    b = (sy - k*sx) / n
    printf "\nFit over %d non-OOM points:\n", n
    printf "  memory.peak ~= %.1f MB baseline + %.2f x raw_blob\n", b/1048576, k
    if (k > 0) {
      printf "\nDerived OOM boundary (largest raw blob that fits):\n"
      printf "  1Gi  cap: ~%.1f MB raw blob\n", (cap1-b)/k/1048576
      printf "  512Mi cap: ~%.1f MB raw blob\n", (cap2-b)/k/1048576
      printf "\n(These are RAW blob sizes. Compare against the realistic max o365\n"
      printf " content-blob size to judge whether production can reach the boundary.)\n"
    }
  }'

echo
echo "Full log : $LOG"
echo "CSV      : $CSV"
echo "Per-run  : $LOGDIR/run-$TS-*.log"
