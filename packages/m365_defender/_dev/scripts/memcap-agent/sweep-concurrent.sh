#!/usr/bin/env bash
#
# m365_defender agentless memory sweep - all three agentless streams concurrently.
#
# sweep.sh fits one stream at a time, which gives three separate `base + k x page` lines
# whose bases cannot simply be added: every input runs in the same beat process, so the
# per-process baseline is paid once. This sweep scales all three pages together and fits
# ONE line for the pod:
#
#     working_set ~= base_shared + k x total_raw_pages
#
# base_shared is the whole-container floor (agent + beat + monitoring) and k is the
# multiplier from raw page bytes to resident bytes. That is the formula an agentless memory
# request should be derived from, because a pod runs all enabled streams, not one.
#
# Two sweep axes:
#
# SCALES (default) scales all three page sizes together from the shipped defaults. Good
#   for measuring the transfer function - base and k - over a wide range. Note that past
#   1.0 the alert and vulnerability points are NOT production-reachable: alert is capped at
#   batch_size=1000 because Graph caps $top at 1000, and vulnerability is fixed at
#   pageSize=10000 in the CEL program. Treat scale>1 as a way to measure k, not as a
#   tenant that can exist.
#
# SWEEP_APC sweeps alerts-per-incident with every page size held at its production value.
#   This is the decision-relevant curve: with alert and vulnerability both capped by
#   config, alerts-per-incident is the ONE input to pod memory that no setting bounds. An
#   incident carrying a large alerts[] array is expanded by $expand=alerts and then split
#   with keep_parent, so it lands in memory as alerts-per-incident events that each also
#   carry the parent incident.
#
# Run at a cap comfortably above the largest expected peak - an OOM pins memory.peak at
# the cap and contributes nothing to the fit.
#
#   SWEEP_CAP=3g SCALES="0.25 0.5 1 2 3" ./sweep-concurrent.sh
#   SWEEP_CAP=3g SWEEP_APC="25 50 100 200 400" ./sweep-concurrent.sh
#
# Needs enough free memory in the Docker VM for the largest run; check `docker info` and
# stop other containers first, or the host will reclaim and distort the numbers.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SWEEP_CAP="${SWEEP_CAP:-3g}"
SCALES="${SCALES:-0.25 0.5 1 2 3}"
SWEEP_APC="${SWEEP_APC:-}"   # set to sweep alerts-per-incident at production page sizes
export STACK_VERSION="${STACK_VERSION:-9.6.0-SNAPSHOT}"
export AGENT_IMAGE="${AGENT_IMAGE:-docker.elastic.co/elastic-agent/elastic-agent:$STACK_VERSION}"
export ALERTS_PER_INCIDENT="${ALERTS_PER_INCIDENT:-100}"
export INTERVAL="${INTERVAL:-24h}"
export HOLD_S="${HOLD_S:-0}"

# Shipped production page sizes, scaled by each factor.
BASE_ALERT="${BASE_ALERT:-1000}"
BASE_INCIDENT="${BASE_INCIDENT:-50}"
BASE_VULN="${BASE_VULN:-10000}"

LOGDIR="$HERE/logs"
mkdir -p "$LOGDIR"
TS="$(date +%Y%m%d-%H%M%S)"
LOG="$LOGDIR/sweep-concurrent-$TS.log"
CSV="$LOGDIR/sweep-concurrent-$TS.csv"

exec > >(tee -a "$LOG") 2>&1

if [ -n "$SWEEP_APC" ]; then
  AXIS="alerts-per-incident"; POINTS="$SWEEP_APC"
else
  AXIS="page scale"; POINTS="$SCALES"
fi

echo "=================================================================="
echo " m365_defender concurrent memory sweep   $(date)"
echo " streams        : alert + incident + vulnerability (the agentless three)"
echo " agent version  : $STACK_VERSION"
echo " cap            : $SWEEP_CAP (chosen so runs do NOT OOM)"
echo " sweep axis     : $AXIS"
echo " points         : $POINTS"
if [ -n "$SWEEP_APC" ]; then
  echo " page sizes     : alert=$BASE_ALERT incident=$BASE_INCIDENT vuln=$BASE_VULN (production defaults, fixed)"
else
  echo " scaled from    : alert=$BASE_ALERT incident=$BASE_INCIDENT vuln=$BASE_VULN (production defaults)"
  echo " alerts/incident: $ALERTS_PER_INCIDENT"
fi
echo " csv            : $CSV"
echo "=================================================================="

echo "point,alert_recs,incident_recs,vuln_recs,alerts_per_incident,total_raw_bytes,peak_bytes,workingset_bytes,anon_bytes,oom" > "$CSV"
rows=""

for p in $POINTS; do
  if [ -n "$SWEEP_APC" ]; then
    a="$BASE_ALERT"; i="$BASE_INCIDENT"; v="$BASE_VULN"; apc="$p"
  else
    a=$(awk -v b="$BASE_ALERT"    -v f="$p" 'BEGIN{printf "%d", b*f}' </dev/null)
    i=$(awk -v b="$BASE_INCIDENT" -v f="$p" 'BEGIN{printf "%d", b*f}' </dev/null)
    v=$(awk -v b="$BASE_VULN"     -v f="$p" 'BEGIN{printf "%d", b*f}' </dev/null)
    apc="$ALERTS_PER_INCIDENT"
  fi
  echo
  echo ">>>>>> $AXIS=$p  alert=$a incident=$i vuln=$v alerts/incident=$apc  cap=$SWEEP_CAP <<<<<<"
  runlog="$LOGDIR/run-concurrent-$TS-$p.log"
  ALERT_EVENTS="$a" INCIDENT_EVENTS="$i" VULN_EVENTS="$v" ALERTS_PER_INCIDENT="$apc" MEM_LIMIT="$SWEEP_CAP" \
    "$HERE/run-concurrent.sh" 2>&1 | tee "$runlog" || true

  total=$(grep 'total raw pages' "$runlog" | grep -oE '[0-9]+' | head -1 || echo 0)
  peak=$(grep 'memory.peak'      "$runlog" | grep -oE '[0-9]+' | head -1 || echo 0)
  ws=$(grep 'working set'        "$runlog" | grep -oE '[0-9]+' | head -1 || echo 0)
  anon=$(grep 'anon (heap)'      "$runlog" | grep -oE '[0-9]+' | head -1 || echo 0)
  oom=$(grep 'OOM killed'        "$runlog" | grep -oE 'true|false' | head -1 || echo unknown)
  total=${total:-0}; peak=${peak:-0}; ws=${ws:-0}; anon=${anon:-0}; oom=${oom:-unknown}
  # working set and anon are printed in MB; normalise to bytes for the CSV.
  ws=$((ws * 1048576)); anon=$((anon * 1048576))
  echo "$p,$a,$i,$v,$apc,$total,$peak,$ws,$anon,$oom" >> "$CSV"
  echo ">>>>>> parsed: point=$p raw=$total peak=$peak ws=$ws oom=$oom"

  if [ "$oom" = "true" ]; then
    echo "   (excluded from fit: OOM pins memory.peak at the cap - raise SWEEP_CAP)"
  elif [ "$total" -gt 0 ] && [ "$peak" -gt 0 ]; then
    rows="$rows$total $peak"$'\n'
  fi
done

echo
echo "=================================================================="
echo " CONCURRENT SWEEP SUMMARY"
echo "=================================================================="
printf ' %-8s %-8s %-8s %-8s %-8s %-11s %-10s %-10s %-5s\n' point alert incid vuln apc raw_MB peak_MB ws_MB oom
awk -F, 'NR>1{printf " %-8s %-8s %-8s %-8s %-8s %-11.1f %-10.1f %-10.1f %-5s\n", $1,$2,$3,$4,$5,$6/1048576,$7/1048576,$8/1048576,$10}' "$CSV"

printf '%s' "$rows" | awk -v cap1=1073741824 -v cap2=2147483648 -v cap3=4294967296 '
  NF==2 { n++; sx+=$1; sy+=$2; sxx+=$1*$1; sxy+=$1*$2 }
  END {
    if (n < 2) { print "\nNeed >=2 non-OOM points for a fit. Raise SWEEP_CAP or lower the scales."; exit }
    k = (n*sxy - sx*sy) / (n*sxx - sx*sx)
    b = (sy - k*sx) / n
    printf "\nFit over %d non-OOM points (all three streams in one agent):\n", n
    printf "  working_set ~= %.1f MB shared baseline + %.2f x total_raw_pages\n", b/1048576, k
    if (k > 0) {
      printf "\nTotal raw page budget per cap (all three streams combined):\n"
      printf "  1Gi : %.1f MB of raw pages\n", (cap1-b)/k/1048576
      printf "  2Gi : %.1f MB of raw pages\n", (cap2-b)/k/1048576
      printf "  4Gi : %.1f MB of raw pages\n", (cap3-b)/k/1048576
      printf "\nCompare against the raw page total a real tenant can produce to decide the\n"
      printf "memory request. The budget is shared: a fat incident page consumes the\n"
      printf "headroom the other two streams need.\n"
    }
  }'

echo
echo "Full log : $LOG"
echo "CSV      : $CSV"
