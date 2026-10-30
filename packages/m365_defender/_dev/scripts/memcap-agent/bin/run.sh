#!/usr/bin/env bash
#
# m365_defender agentless memory run - one elastic-agent, one page per enabled stream.
#
# A pod runs every enabled stream of the policy in a single elastic-agent, and every
# httpjson/cel input lives in the same beat process and therefore the same Go heap. So
# this runner is concurrent by default and single-stream only as a special case
# (STREAMS=incident). Profiling streams separately and adding the results is wrong in
# both directions:
#   - the per-process baseline (agent + beat + monitoring) is paid ONCE, not per stream,
#     so summing single-stream peaks over-counts the base;
#   - the decode peaks share one heap and one GC cycle, so pages that overlap in time add
#     on top of each other with no allowance in between.
# Size the pod from a run with every stream enabled. Use STREAMS to attribute a peak to
# the stream that causes it, never to build up a total.
#
# Scope: the three streams agentless actually runs - alert, incident, vulnerability. The
# `event` data stream is deliberately absent: its input is azure-eventhub, which is not
# supported in agentless, so it never contributes to an agentless pod's memory.
#
# Two modes:
#   cold (default, INTERVAL=24h) - every input fires once and the run stops at the decode
#     plateau. Measures the cost of a single page.
#   sustained (DRAIN=1 INTERVAL=10s HOLD_S=600) - inputs re-fetch for HOLD_S. Each cycle
#     decodes a fresh page while the previous one is still garbage, so the heap reaches
#     the steady state a long-running pod sits at. This is the mode to compare against
#     production working-set telemetry; a cold page understates it by ~2x.
#
# Pages come from the corpus generator, whose templates are calibrated against a real
# tenant response - see "Record shapes" in README.md. Nothing here needs tenant access.
#
# Examples:
#   # shipped page sizes, single cold page
#   bin/run.sh
#
#   # sustained 10 minutes - the mode that reproduces production working-set peaks
#   DRAIN=1 INTERVAL=10s HOLD_S=600 MEM_LIMIT=4g bin/run.sh
#
#   # attribution: what does the incident stream contribute on its own?
#   STREAMS=incident ALERTS_PER_INCIDENT=400 bin/run.sh
#
# Match STACK_VERSION/AGENT_IMAGE to the build agentless ships or the numbers are not
# representative. Every run appends a row to RESULTS_CSV (default logs/runs.csv).

set -euo pipefail

# --------------------------- config (override via env) ---------------------------
STACK_VERSION="${STACK_VERSION:-9.6.0-SNAPSHOT}"
AGENT_IMAGE="${AGENT_IMAGE:-docker.elastic.co/elastic-agent/elastic-agent:$STACK_VERSION}"
STREAM_IMAGE="${STREAM_IMAGE:-docker.elastic.co/observability/stream:v0.20.0}"
MEM_LIMIT="${MEM_LIMIT:-4g}"          # default generous: measure the peak, do not clip it
KEEP="${KEEP:-0}"
DRAIN="${DRAIN:-0}"                   # 1 = drain the output through fake-es.py (see below)
GOMEMLIMIT="${GOMEMLIMIT:-}"          # e.g. 900MiB - soft heap ceiling, off by default (as agentless ships)
PYTHON_IMAGE="${PYTHON_IMAGE:-python:3.12-alpine}"

# Page size per stream. Defaults are the shipped production page sizes:
#   alert          batch_size=1000 (the Graph $top cap)
#   incident       batch_size=50
#   vulnerability  pageSize=10000 (hard-coded in the CEL program)
ALERT_EVENTS="${ALERT_EVENTS:-1000}"
INCIDENT_EVENTS="${INCIDENT_EVENTS:-50}"
VULN_EVENTS="${VULN_EVENTS:-10000}"
ALERTS_PER_INCIDENT="${ALERTS_PER_INCIDENT:-100}"

# Timing. INTERVAL=24h fires each input once (cold page). A short INTERVAL plus HOLD_S
# holds the run open so the heap reaches its sustained state.
INTERVAL="${INTERVAL:-24h}"
HOLD_S="${HOLD_S:-0}"                 # 0 = stop at the decode plateau
MAX_WAIT_S="${MAX_WAIT_S:-900}"
PLATEAU_S="${PLATEAU_S:-30}"
STREAMS="${STREAMS:-alert incident vulnerability}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"
TOOL="${TOOL:-$HOME/go/src/github.com/elastic/elastic-integration-corpus-generator-tool}"

# Where this run records itself. The sweep overrides these to group its runs into one
# file along one axis; a bare run lands in the scratch log of runs.
RESULTS_CSV="${RESULTS_CSV:-$HARNESS_ROOT/logs/runs.csv}"
RESULT_AXIS="${RESULT_AXIS:-adhoc}"
RESULT_POINT="${RESULT_POINT:-}"
RESULT_LABEL="${RESULT_LABEL:-}"
RUN_LOG="${RUN_LOG:-}"

NET="m365d-memcap-net"
SVC="svc-m365d"
AGENT="m365d-agent"
SINK="sink-m365d"
WORK="$HARNESS_ROOT/work"
AGENT_YML="$WORK/elastic-agent.yml"
MOCK_YML="$WORK/mock-config.yml"

cleanup() {
  if [ "$KEEP" = "1" ]; then
    echo "KEEP=1: leaving $SVC / $AGENT / $SINK up"
    return
  fi
  docker rm -f "$SVC" "$AGENT" "$SINK" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

records_for() {
  case "$1" in
    alert)         echo "$ALERT_EVENTS" ;;
    incident)      echo "$INCIDENT_EVENTS" ;;
    vulnerability) echo "$VULN_EVENTS" ;;
  esac
}

# --------------------------- 0. sanity ---------------------------
harness_require_docker || exit 1
harness_find_eicgt "$TOOL" || exit 1

rm -rf "$WORK"; mkdir -p "$WORK"

# --------------------------- 1. corpora + per-stream configs ---------------------------
MOUNTS=()
TOTAL_PAGE=0
PAGE_PAIRS=""   # "stream=bytes" per line; bash 3.2 (macOS) has no associative arrays
page_bytes() { printf '%s\n' "$PAGE_PAIRS" | awk -F= -v s="$1" '$1==s{print $2; found=1} END{if(!found) print 0}'; }
for s in $STREAMS; do
  n="$(records_for "$s")"
  swork="$WORK/$s"
  mkdir -p "$swork"
  bytes="$(harness_gen_corpus "$s" "$swork" "$HARNESS_STREAMS/$s/corpus" "$n" "$ALERTS_PER_INCIDENT")"
  PAGE_PAIRS="$PAGE_PAIRS$s=$bytes
"
  TOTAL_PAGE=$((TOTAL_PAGE + bytes))
  MOUNTS[${#MOUNTS[@]}]="-v"
  MOUNTS[${#MOUNTS[@]}]="$swork/corpus/corpus-1:/var/log/$s/corpus-1:ro"
  harness_render_config "$s" "$swork" "$swork/elastic-agent.yml" || exit 1
  printf '>> [%s] page: %s records, %s bytes (~%s MB raw)\n' "$s" "$n" "$bytes" "$((bytes / 1048576))"
done

# --------------------------- 2. merge into one agent config ---------------------------
# One header (outputs + agent monitoring) taken from the first stream - all three tmpls
# declare the same one - then every stream's inputs[] entry appended under a single
# `inputs:` key. The per-stream bodies are the spliced ship logic, untouched.
first="${STREAMS%% *}"
awk '/^inputs:/{exit} {print}' "$WORK/$first/elastic-agent.yml" > "$AGENT_YML"
echo "inputs:" >> "$AGENT_YML"
for s in $STREAMS; do
  awk 'f{print} /^inputs:/{f=1}' "$WORK/$s/elastic-agent.yml" >> "$AGENT_YML"
done

# Apply the run interval to the stream-level `interval:` only. The 4-space indent pins it
# to inputs[].streams[]; `state.initial_interval` sits deeper and must keep its own value
# because it is the API lookback, not the poll period.
if [ "$INTERVAL" != "24h" ]; then
  sed -i.bak -E "s/^    interval: 24h$/    interval: $INTERVAL/" "$AGENT_YML"
  rm -f "$AGENT_YML.bak"
  echo ">> poll interval set to $INTERVAL (sustained mode)"
fi

# With DRAIN=1 the output points at fake-es.py instead of an unreachable Elasticsearch, so
# events leave the queue and the inputs keep fetching. Required for sustained mode: with an
# unreachable output the queue fills, the input blocks on publish and no second page is ever
# decoded, which is the opposite of a catching-up production pod.
if [ "$DRAIN" = "1" ]; then
  sed -i.bak -E 's#hosts: \["http://127\.0\.0\.1:9200"\]#hosts: ["http://'"$SINK"':9200"]#' "$AGENT_YML"
  rm -f "$AGENT_YML.bak"
  grep -q "$SINK:9200" "$AGENT_YML" || { echo "ERROR: DRAIN=1 but the output host was not rewritten - check the outputs block in the .tmpl"; exit 1; }
  echo ">> output drains to $SINK (fake-es)"
fi

got=$(grep -c '^- type:' "$AGENT_YML" || true)
want=$(echo "$STREAMS" | wc -w | tr -d ' ')
[ "$got" = "$want" ] || { echo "ERROR: merged config has $got inputs, expected $want"; exit 1; }

# --------------------------- 3. merge the mock configs ---------------------------
# Every stream's mock config is `rules:` + the shared token rule + exactly one data rule.
# Take the first file whole, then append only the data rules from the rest. Assert the
# two-rule shape so a mock config that grows a rule fails here instead of silently losing
# an endpoint.
for s in $STREAMS; do
  cnt=$(grep -c '^  - path:' "$HARNESS_STREAMS/$s/mock-config.yml" || true)
  [ "$cnt" = "2" ] || { echo "ERROR: $s/mock-config.yml has $cnt rules, expected 2 (token + data). Update the merge in bin/run.sh."; exit 1; }
done
cat "$HARNESS_STREAMS/$first/mock-config.yml" > "$MOCK_YML"
for s in $STREAMS; do
  [ "$s" = "$first" ] && continue
  awk '/^  - path:/{n++} n>=2{print}' "$HARNESS_STREAMS/$s/mock-config.yml" >> "$MOCK_YML"
done

# --------------------------- 4. mock ---------------------------
docker network create "$NET" >/dev/null 2>&1 || true
docker rm -f "$SVC" "$AGENT" >/dev/null 2>&1 || true
docker run -d --name "$SVC" --network "$NET" --network-alias "$SVC" \
  -v "$MOCK_YML":/files/config.yml:ro \
  "${MOUNTS[@]}" \
  "$STREAM_IMAGE" http-server --addr=:8082 --config=/files/config.yml >/dev/null
echo ">> waiting for mock token endpoint ..."
for i in $(seq 1 30); do
  code=$(docker run --rm --network "$NET" curlimages/curl:8.9.1 -s -o /dev/null -w '%{http_code}' \
    -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
    --data 'grant_type=client_credentials' \
    "http://$SVC:8082/tenant_id/oauth2/v2.0/token" 2>/dev/null || echo 000)
  [ "$code" = "200" ] && { echo "   mock ready"; break; }
  sleep 1
  [ "$i" = "30" ] && { echo "   mock did not become ready"; docker logs "$SVC"; exit 1; }
done

# --------------------------- 4b. draining sink ---------------------------
if [ "$DRAIN" = "1" ]; then
  echo ">> starting fake-es sink ..."
  docker run -d --name "$SINK" --network "$NET" --network-alias "$SINK" \
    -v "$HERE/fake-es.py":/fake-es.py:ro \
    "$PYTHON_IMAGE" python3 /fake-es.py --port 9200 >/dev/null
  for i in $(seq 1 30); do
    code=$(docker run --rm --network "$NET" curlimages/curl:8.9.1 -s -o /dev/null -w '%{http_code}' \
      "http://$SINK:9200/" 2>/dev/null || echo 000)
    [ "$code" = "200" ] && { echo "   sink ready"; break; }
    sleep 1
    [ "$i" = "30" ] && { echo "   sink did not become ready"; docker logs "$SINK"; exit 1; }
  done
fi

# --------------------------- 5. capped elastic-agent ---------------------------
echo ">> starting capped elastic-agent (mem=$MEM_LIMIT, $want inputs)${GOMEMLIMIT:+, GOMEMLIMIT=$GOMEMLIMIT} ..."
GOMEMLIMIT_ARGS=""
[ -n "$GOMEMLIMIT" ] && GOMEMLIMIT_ARGS="-e GOMEMLIMIT=$GOMEMLIMIT"
# shellcheck disable=SC2086  # GOMEMLIMIT_ARGS is intentionally word-split (empty = absent)
docker run -d --name "$AGENT" --network "$NET" \
  --memory="$MEM_LIMIT" --memory-swap="$MEM_LIMIT" \
  --log-driver=none \
  -e ELASTIC_CONTAINER=true \
  -e ELASTIC_AGENT_IS_AGENTLESS=1 \
  -e AGENT_MONITORING_PORT=6791 \
  -e "BEATS_ADD_CLOUD_METADATA_PROVIDERS= " \
  -e GODEBUG=madvdontneed=1 \
  $GOMEMLIMIT_ARGS \
  -v "$AGENT_YML":/usr/share/elastic-agent/elastic-agent.yml:ro \
  "$AGENT_IMAGE" >/dev/null

served_count() { harness_served_count "$SVC" "$1"; }

# A flat memory reading means nothing until every input has actually pulled its page:
# early in the run the agent is still starting beats, and flatness there is just an idle
# process. Gate the plateau on all endpoints having been served.
all_streams_fetched() {
  local s
  for s in $STREAMS; do
    [ "$(served_count "$s")" -gt 0 ] || return 1
  done
  return 0
}

mem_now() {
  local raw
  raw=$(docker stats --no-stream --format '{{.MemUsage}}' "$AGENT" 2>/dev/null | awk '{print $1}')
  awk -v s="$raw" 'BEGIN{
    u=s; n=s; sub(/[A-Za-z]+$/,"",n); unit=substr(u,length(n)+1)
    m=1; if(unit=="KiB")m=1024; else if(unit=="MiB")m=1024*1024;
    else if(unit=="GiB")m=1024*1024*1024; else if(unit=="B")m=1;
    printf "%d", n*m
  }' </dev/null
}

# --------------------------- 6. watch (host-side, no exec) ---------------------------
if [ "$HOLD_S" -gt 0 ]; then
  echo ">> sustained mode: holding ${HOLD_S}s at interval=$INTERVAL ..."
else
  echo ">> waiting for decode plateau (flat ${PLATEAU_S}s) or OOM ..."
fi
oom=false; exitc=-; last=0; flat=0; maxseen=0; elapsed=0; fetched=0
limit=$MAX_WAIT_S
[ "$HOLD_S" -gt 0 ] && limit=$HOLD_S
for i in $(seq 1 $((limit / 3))); do
  running=$(docker inspect -f '{{.State.Running}}' "$AGENT" 2>/dev/null || echo false)
  oom=$(docker inspect -f '{{.State.OOMKilled}}' "$AGENT" 2>/dev/null || echo false)
  exitc=$(docker inspect -f '{{.State.ExitCode}}' "$AGENT" 2>/dev/null || echo -)
  cur=$(mem_now); cur=${cur:-0}
  [ "$cur" -gt "$maxseen" ] && maxseen=$cur
  elapsed=$((i * 3))
  if [ "$fetched" = "0" ] && all_streams_fetched; then
    fetched=1
    echo "   all $want endpoints served at t=${elapsed}s - plateau detection armed"
  fi
  printf '   t=%4ss running=%s oom=%s fetched=%s mem=%sMB max=%sMB\n' \
    "$elapsed" "$running" "$oom" "$fetched" "$((cur / 1048576))" "$((maxseen / 1048576))"
  if [ "$oom" = "true" ]; then echo "   OOM detected - memory.peak is pinned at the cap; re-run with a bigger MEM_LIMIT for the true peak"; break; fi
  if [ "$running" != "true" ]; then echo "   agent stopped (oom=$oom exit=$exitc)"; break; fi
  # Only trust flatness once every input has pulled its page (see all_streams_fetched).
  if [ "$HOLD_S" -eq 0 ] && [ "$fetched" = "1" ] && [ "$cur" -gt 52428800 ] && \
     awk -v c="$cur" -v l="$last" 'BEGIN{d=c-l; if(d<0)d=-d; exit !(l>0 && d < l*0.02)}'; then
    flat=$((flat + 3))
    [ "$flat" -ge "$PLATEAU_S" ] && { echo "   memory plateau reached"; break; }
  else
    flat=0
  fi
  last=$cur
  sleep 3
done
if [ "$fetched" = "0" ]; then
  echo "WARN: not every endpoint was served - an input may not have run. Re-run with --log-driver=json-file to inspect agent logs."
fi

# --------------------------- 7. report ---------------------------
harness_read_memory "$AGENT"
peak=$MEM_PEAK
[ "$peak" -lt "$maxseen" ] && peak=$maxseen   # fall back to the observed max if the exec read failed
MEM_PEAK=$peak
# `docker stats` reports memory.current - inactive_file on cgroup v2, the same arithmetic
# kubelet uses, so the running maximum of the samples above is a working-set high-water
# mark and is the figure to hold against production workingset.bytes. MEM_WORKINGSET is
# the closing snapshot of the same quantity, which is lower whenever the run tails off.
MEM_WORKINGSET_PEAK=$maxseen
[ "$MEM_WORKINGSET_PEAK" -lt "$MEM_WORKINGSET" ] && MEM_WORKINGSET_PEAK=$MEM_WORKINGSET
echo
echo "============== RESULT (elastic-agent, concurrent) =============="
echo " streams         : $STREAMS"
echo " agent version   : $STACK_VERSION"
echo " agent image     : $AGENT_IMAGE"
echo " corpus          : generated from <stream>/corpus/ (shape calibrated to a real response)"
for s in $STREAMS; do
  b="$(page_bytes "$s")"
  printf ' page %-14s: %s records, %s bytes (~%s MB)\n' "$s" "$(records_for "$s")" "$b" "$((b / 1048576))"
done
case " $STREAMS " in *" incident "*) echo " alerts/incident : $ALERTS_PER_INCIDENT" ;; esac
echo " total raw pages : $TOTAL_PAGE (~$((TOTAL_PAGE / 1048576)) MB)"
echo " poll interval   : $INTERVAL$([ "$HOLD_S" -gt 0 ] && echo " (sustained, held ${elapsed}s)" || echo " (single page)")"
echo " output          : $([ "$DRAIN" = "1" ] && echo "draining to fake-es (events leave the queue; inputs keep fetching)" || echo "unreachable ES (events retained; halts after one page)")"
[ -n "$GOMEMLIMIT" ] && echo " GOMEMLIMIT      : $GOMEMLIMIT (soft heap ceiling; agentless does not set one)"
echo " cgroup cap      : $MEM_LIMIT"
harness_print_memory
if [ "$peak" -gt 0 ] && [ "$TOTAL_PAGE" -gt 0 ]; then
  echo " peak / raw pages: $(awk -v p="$peak" -v b="$TOTAL_PAGE" 'BEGIN{printf "%.2fx", p/b}' </dev/null)"
  echo " anon / raw pages: $(awk -v p="$MEM_ANON" -v b="$TOTAL_PAGE" 'BEGIN{printf "%.2fx", p/b}' </dev/null)"
fi
echo " OOM killed      : $oom (exit=$exitc)"
for s in $STREAMS; do
  printf ' fetches %-11s: %s\n' "$s" "$(served_count "$s")"
done
if [ "$DRAIN" = "1" ]; then
  echo " drained         : $(docker logs "$SINK" 2>&1 | grep -c 'drained' || true) checkpoints - $(docker logs "$SINK" 2>&1 | tail -1)"
fi
echo "==============================================================="
[ "$oom" = "true" ] && echo "NOTE: OOM at this cap. Record the largest page set that fits."

# Record the run. A number that only ever existed on a terminal cannot be re-checked, and
# the published tables are rendered from these rows - see the contract in lib.sh.
PARAMS=""
for s in $STREAMS; do PARAMS="$PARAMS$s=$(records_for "$s") "; done
case " $STREAMS " in *" incident "*) PARAMS="${PARAMS}alerts_per_incident=$ALERTS_PER_INCIDENT " ;; esac
harness_emit_result_row "$RESULTS_CSV" "$RESULT_AXIS" "${RESULT_POINT:-$TOTAL_PAGE}" \
  "$RESULT_LABEL" "${PARAMS% }" "$RUN_LOG"
echo " recorded        : $RESULTS_CSV"
