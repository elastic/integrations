#!/usr/bin/env bash
#
# m365_defender agentless memory sweep - repeat bin/run.sh along one axis.
#
# A single run gives one point. Sizing needs the transfer function:
#
#     working_set ~= base + k x <axis>
#
# base is the whole-container floor (agent + beat + monitoring), paid once no matter how
# many streams are enabled, and k is what each extra unit of load costs. That is the shape
# an agentless memory request should be derived from, because it says what happens when a
# tenant is bigger than the one you measured.
#
# Three axes, one per invocation:
#
#   AXIS=scale (default)  scales every stream's page size together from the shipped
#     defaults. Measures k over a wide range. Past 1.0 the points are NOT tenants that can
#     exist - alert is capped at batch_size=1000 because Graph caps $top at 1000, and
#     vulnerability is fixed at pageSize=10000 in the CEL program - so treat scale>1 as a
#     way to measure the multiplier, not as a load anyone will see.
#
#   AXIS=alerts_per_incident   holds every page size at its shipped value and sweeps the
#     alerts[] array. With alert and vulnerability both capped by config, this is the ONE
#     input to pod memory that nothing bounds: $expand=alerts plus a nested split with
#     keep_parent turns each embedded alert into an event that also carries its parent.
#
#   AXIS=knob   not a curve but a ladder: the same worst case with one thing changed per
#     row, which is what answers "what would it take to fit in 1Gi". Rows come from
#     KNOB_ROWS, one per line: `label | ENV=V ENV=V ...`.
#
# Sizing runs should be sustained (DRAIN=1 with a short INTERVAL): a cold page understates
# a production pod by ~2x because production fetches back-to-back. Cold is the cheaper
# mode and is fine for measuring the shape of a curve.
#
# Run at a cap comfortably above the largest expected peak - an OOM pins memory.peak at
# the cap and is excluded from the fit.
#
#   AXIS=scale SWEEP_CAP=3g POINTS="0.25 0.5 1 2 3" bin/sweep.sh
#   AXIS=alerts_per_incident SWEEP_CAP=3g POINTS="25 50 100 200 400" bin/sweep.sh
#   AXIS=knob DRAIN=1 INTERVAL=10s HOLD_S=300 bin/sweep.sh
#
# Needs enough free memory in the Docker VM for the largest run; check `docker info` and
# stop other containers first, or the host will reclaim and distort the numbers.
#
# Writes one CSV per sweep under logs/. Promote the file to results/ when its numbers are
# the ones a document publishes - see README.md, "Publishing a number".

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

AXIS="${AXIS:-scale}"
SWEEP_CAP="${SWEEP_CAP:-3g}"
export STACK_VERSION="${STACK_VERSION:-9.6.0-SNAPSHOT}"
export AGENT_IMAGE="${AGENT_IMAGE:-docker.elastic.co/elastic-agent/elastic-agent:$STACK_VERSION}"
export ALERTS_PER_INCIDENT="${ALERTS_PER_INCIDENT:-100}"
export INTERVAL="${INTERVAL:-24h}"
export HOLD_S="${HOLD_S:-0}"
export DRAIN="${DRAIN:-0}"
export STREAMS="${STREAMS:-alert incident vulnerability}"

# Shipped production page sizes: the scale axis multiplies these, the other axes hold them.
BASE_ALERT="${BASE_ALERT:-1000}"
BASE_INCIDENT="${BASE_INCIDENT:-50}"
BASE_VULN="${BASE_VULN:-10000}"

# The knob ladder. Each row is `label | env assignments`; the first row is the untouched
# worst case so every other row reads as a delta from it.
KNOB_ROWS="${KNOB_ROWS:-baseline (nothing changed) |
GOMEMLIMIT=850MiB (nothing else) | GOMEMLIMIT=850MiB MEM_LIMIT=1g
incident batch_size 50->10 + vulnerability pageSize 10000->1000 | INCIDENT_EVENTS=10 VULN_EVENTS=1000 MEM_LIMIT=1g}"

case "$AXIS" in
  scale)               POINTS="${POINTS:-0.25 0.5 1 2 3}" ;;
  alerts_per_incident) POINTS="${POINTS:-25 50 100 200 400}" ;;
  knob)                POINTS="" ;;
  *) echo "unknown AXIS=$AXIS (want: scale | alerts_per_incident | knob)"; exit 1 ;;
esac

LOGDIR="$ROOT/logs"
mkdir -p "$LOGDIR"
TS="$(date +%Y%m%d-%H%M%S)"
LOG="$LOGDIR/sweep-$AXIS-$TS.log"
CSV="${RESULTS_CSV:-$LOGDIR/sweep-$AXIS-$TS.csv}"

exec > >(tee -a "$LOG") 2>&1

echo "=================================================================="
echo " m365_defender memory sweep   $(date)"
echo " streams        : $STREAMS"
echo " agent version  : $STACK_VERSION"
echo " cap            : $SWEEP_CAP (chosen so runs do NOT OOM)"
echo " mode           : $([ "$HOLD_S" -gt 0 ] && echo "sustained (${HOLD_S}s at interval=$INTERVAL, drain=$DRAIN)" || echo "cold single page")"
echo " sweep axis     : $AXIS"
if [ "$AXIS" = "knob" ]; then
  echo " ladder         :"
  printf '%s\n' "$KNOB_ROWS" | while IFS= read -r r; do [ -n "$r" ] && echo "                  ${r%%|*}"; done
  echo " worst case     : alert=$BASE_ALERT incident=$BASE_INCIDENT vuln=$BASE_VULN apc=$ALERTS_PER_INCIDENT"
else
  echo " points         : $POINTS"
  if [ "$AXIS" = "scale" ]; then
    echo " scaled from    : alert=$BASE_ALERT incident=$BASE_INCIDENT vuln=$BASE_VULN (shipped defaults)"
    echo " alerts/incident: $ALERTS_PER_INCIDENT"
  else
    echo " page sizes     : alert=$BASE_ALERT incident=$BASE_INCIDENT vuln=$BASE_VULN (shipped defaults, fixed)"
  fi
fi
echo " csv            : $CSV"
echo "=================================================================="

# One run. run.sh appends the row itself (see harness_emit_result_row in lib.sh) so the
# numbers in the CSV are the measured bytes, not a re-parse of rounded console output.
sweep_run() {
  local point="$1" label="$2"; shift 2
  local runlog="$LOGDIR/run-$AXIS-$TS-$point.log"
  echo
  echo ">>>>>> $AXIS=$point ${label:+($label) }cap=$SWEEP_CAP <<<<<<"
  # Sweep defaults first, the row's own assignments last: a knob row that sets MEM_LIMIT
  # is choosing the cap it is being tested at and must win over SWEEP_CAP.
  env MEM_LIMIT="$SWEEP_CAP" RESULTS_CSV="$CSV" RUN_LOG="$runlog" \
    RESULT_AXIS="$AXIS" RESULT_POINT="$point" RESULT_LABEL="$label" \
    "$@" "$HERE/run.sh" 2>&1 | tee "$runlog" || true
}

if [ "$AXIS" = "knob" ]; then
  n=0
  printf '%s\n' "$KNOB_ROWS" | while IFS= read -r row; do
    [ -n "$row" ] || continue
    n=$((n + 1))
    label="$(printf '%s' "${row%%|*}" | sed -e 's/[[:space:]]*$//')"
    # shellcheck disable=SC2086  # the assignments after `|` are deliberately word-split
    sweep_run "$n" "$label" \
      ALERT_EVENTS="$BASE_ALERT" INCIDENT_EVENTS="$BASE_INCIDENT" VULN_EVENTS="$BASE_VULN" \
      ALERTS_PER_INCIDENT="$ALERTS_PER_INCIDENT" ${row#*|}
  done
else
  for p in $POINTS; do
    if [ "$AXIS" = "alerts_per_incident" ]; then
      a="$BASE_ALERT"; i="$BASE_INCIDENT"; v="$BASE_VULN"; apc="$p"
    else
      a=$(awk -v b="$BASE_ALERT"    -v f="$p" 'BEGIN{printf "%d", b*f}' </dev/null)
      i=$(awk -v b="$BASE_INCIDENT" -v f="$p" 'BEGIN{printf "%d", b*f}' </dev/null)
      v=$(awk -v b="$BASE_VULN"     -v f="$p" 'BEGIN{printf "%d", b*f}' </dev/null)
      apc="$ALERTS_PER_INCIDENT"
    fi
    sweep_run "$p" "" ALERT_EVENTS="$a" INCIDENT_EVENTS="$i" VULN_EVENTS="$v" ALERTS_PER_INCIDENT="$apc"
  done
fi

echo
echo "=================================================================="
echo " SWEEP SUMMARY"
echo "=================================================================="
printf ' %-10s %-11s %-10s %-10s %-6s %s\n' point raw_MB peak_MB ws_MB oom label
awk -F, 'NR>1{printf " %-10s %-11.1f %-10.1f %-10.1f %-6s %s\n", $2,$10/1048576,$11/1048576,$12/1048576,$14,$3}' "$CSV"

# The fit and the published tables come from one implementation, so a number in a
# document and a number on this terminal cannot disagree. That implementation ships
# with the agentless-orr skill rather than this repository, because it is shared by
# every package's ORR; point ORR_RENDERER at it to get the fit printed here. Without
# it the sweep still produces the CSV, which is the part that matters.
RENDERER="${ORR_RENDERER:-}"
if [ -n "$RENDERER" ] && [ -x "$RENDERER" ]; then
  echo
  "$RENDERER" --fit "$CSV" || true
else
  echo
  echo "Fit: not computed. Set ORR_RENDERER to the agentless-orr skill's"
  echo "harness_autofill.sh and re-run, or run it directly over the CSV:"
  echo "  ORR_RENDERER=/path/to/harness_autofill.sh"
  echo "  \$ORR_RENDERER --fit $CSV"
  if [ -n "$RENDERER" ]; then
    echo "(ORR_RENDERER is set to '$RENDERER', which is not executable.)"
  fi
fi

echo
echo "Full log : $LOG"
echo "CSV      : $CSV"
echo
echo "To publish these numbers: copy the CSV into results/ and re-render the documents"
echo "(README.md, the ORR) with the renderer - see README.md, \"Publishing a number\"."
