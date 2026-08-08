#!/usr/bin/env bash
#
# m365_defender agentless inputs - synthetic worst-case memory run.
#
# One harness, three streams (STREAM=alert|incident|vulnerability). Each input
# runs inside a real elastic-agent container configured the way agentless-controller
# deploys it (single container, monitoring enabled with logs/metrics collection off,
# no GOMEMLIMIT, agentless env flags). This is the authoritative harness for the ORR
# memory profile. Unlike o365 (one giant content blob) the m365_defender memory
# driver is a single API PAGE:
#
#   alert         httpjson  - one alerts_v2 page (server caps $top at 1000);
#                             peak ~ records x per-alert size (fat evidence[]).
#   incident      httpjson  - one incidents page expanded with alerts[]; nested
#                             split keep_parent means peak ~ incidents x
#                             alerts-per-incident x per-alert size.
#   vulnerability cel       - one SoftwareVulnerabilityChangesByMachine page
#                             (pageSize=10000 hard-coded); peak ~ records x size,
#                             plus the CEL re-encode into message strings.
#
# The stream config and the corpus are assembled by lib.sh, shared with
# run-concurrent.sh, so the single-stream and all-streams runs exercise the same page and
# the same spliced ship logic. Every stream splices the ship logic from its .hbs into
# <stream>/elastic-agent.yml.tmpl and aborts on a token the splice does not understand,
# so drift is caught, not silently mis-rendered.
#
# Sweep the page size with TOTAL_EVENTS and the cap with MEM_LIMIT, e.g.:
#   STREAM=alert         MEM_LIMIT=1g   TOTAL_EVENTS=1000  ./run.sh
#   STREAM=incident      MEM_LIMIT=1g   TOTAL_EVENTS=50 ALERTS_PER_INCIDENT=100 ./run.sh
#   STREAM=vulnerability MEM_LIMIT=512m TOTAL_EVENTS=10000 ./run.sh
# Or use ./sweep.sh to fit the peak/page multiplier across several page sizes.
#
# This measures ONE stream, which is useful for attribution but is not what an agentless
# pod runs. Size against ./run-concurrent.sh, which runs all three agentless streams in a
# single agent.
#
# Match STACK_VERSION to the agent build agentless actually ships, otherwise the
# numbers are not representative for the ORR. Serverless agentless runs elastic-agent
# `main` (the observability-ci ecp-elastic-agent-service:git-<sha> image, which
# rotates every ~1-2 days), NOT a cloud-release GA tag - the pod's `agent.version`
# field is stale metadata. main currently declares 9.6.0, so 9.6.0-SNAPSHOT is the
# closest reproducible, publicly pullable proxy. Use AGENT_IMAGE to pin the exact
# serverless image instead (e.g. the ecp-...:git-<sha> build) for max fidelity.

set -euo pipefail

# --------------------------- config (override via env) ---------------------------
STREAM="${STREAM:?set STREAM=alert|incident|vulnerability}"
STACK_VERSION="${STACK_VERSION:-9.6.0-SNAPSHOT}"  # serverless agentless == elastic-agent main (~9.6.0-SNAPSHOT)
AGENT_IMAGE="${AGENT_IMAGE:-docker.elastic.co/elastic-agent/elastic-agent:$STACK_VERSION}"  # override to pin the exact ecp-...:git-<sha> serverless build
MEM_LIMIT="${MEM_LIMIT:-1g}"                       # cgroup cap = agentless pod mem limit
STREAM_IMAGE="${STREAM_IMAGE:-docker.elastic.co/observability/stream:v0.20.0}"
KEEP="${KEEP:-0}"                                  # KEEP=1 to leave containers up
MAX_WAIT_S="${MAX_WAIT_S:-600}"                    # hard cap on the wait loop
PLATEAU_S="${PLATEAU_S:-30}"                       # memory flat this long => decode done
ALERTS_PER_INCIDENT="${ALERTS_PER_INCIDENT:-100}" # incident stream only

case "$STREAM" in
  alert)         TOTAL_EVENTS="${TOTAL_EVENTS:-1000}" ;;
  incident)      TOTAL_EVENTS="${TOTAL_EVENTS:-50}" ;;
  vulnerability) TOTAL_EVENTS="${TOTAL_EVENTS:-10000}" ;;
  *) echo "unknown STREAM=$STREAM (want alert|incident|vulnerability)"; exit 1 ;;
esac

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS_HERE="$HERE"
# shellcheck source=lib.sh
. "$HERE/lib.sh"
DIR="$HERE/$STREAM"
TOOL="${TOOL:-$HOME/go/src/github.com/elastic/elastic-integration-corpus-generator-tool}"
PKG="$DIR/corpus"
MOCK_CONFIG="$DIR/mock-config.yml"

NET="m365d-memcap-net"
SVC="svc-m365d"
AGENT="m365d-agent"
WORK="$DIR/work"
AGENT_YML="$WORK/elastic-agent.yml"

cleanup() {
  [ "$KEEP" = "1" ] && { echo "KEEP=1: leaving $SVC / $AGENT up"; return; }
  docker rm -f "$SVC" "$AGENT" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# --------------------------- 0. sanity ---------------------------
harness_require_docker || exit 1
[ -d "$DIR" ] || { echo "missing stream dir $DIR"; exit 1; }
[ -f "$MOCK_CONFIG" ] || { echo "missing $MOCK_CONFIG"; exit 1; }
harness_find_eicgt "$TOOL" || exit 1

# --------------------------- 1. corpus + agent config ---------------------------
rm -rf "$WORK"; mkdir -p "$WORK"
BLOB=$(harness_gen_corpus "$STREAM" "$WORK" "$PKG" "$TOTAL_EVENTS" "$ALERTS_PER_INCIDENT")
echo ">> page: $TOTAL_EVENTS records, $BLOB bytes (~$((BLOB/1024/1024)) MB raw), cap=$MEM_LIMIT, agent=$STACK_VERSION"
harness_render_config "$STREAM" "$HERE" "$WORK" "$AGENT_YML" || exit 1

# --------------------------- 2. mock ---------------------------
docker network create "$NET" >/dev/null 2>&1 || true
docker rm -f "$SVC" "$AGENT" >/dev/null 2>&1 || true
docker run -d --name "$SVC" --network "$NET" --network-alias "$SVC" \
  -v "$MOCK_CONFIG":/files/config.yml:ro \
  -v "$WORK/corpus/corpus-1":"/var/log/$STREAM/corpus-1":ro \
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

# --------------------------- 3. capped elastic-agent ---------------------------
# Standalone agent with the agentless env flags. No FLEET_* -> the container
# entrypoint runs standalone against the mounted elastic-agent.yml. No GOMEMLIMIT.
echo ">> starting capped elastic-agent (mem=$MEM_LIMIT) ..."
docker run -d --name "$AGENT" --network "$NET" \
  --memory="$MEM_LIMIT" --memory-swap="$MEM_LIMIT" \
  --log-driver=none \
  -e ELASTIC_CONTAINER=true \
  -e ELASTIC_AGENT_IS_AGENTLESS=1 \
  -e AGENT_MONITORING_PORT=6791 \
  -e "BEATS_ADD_CLOUD_METADATA_PROVIDERS= " \
  -e GODEBUG=madvdontneed=1 \
  -v "$AGENT_YML":/usr/share/elastic-agent/elastic-agent.yml:ro \
  "$AGENT_IMAGE" >/dev/null

# Current cgroup usage, host-side (no exec). memory.peak and the anon/cache breakdown are
# read once at the end by harness_read_memory: each exec joins the container cgroup and
# would ratchet the peak up, so they must never be read inside this loop.
mem_now() {  # current cgroup usage in bytes, host-side (no exec)
  local raw
  raw=$(docker stats --no-stream --format '{{.MemUsage}}' "$AGENT" 2>/dev/null | awk '{print $1}')
  awk -v s="$raw" 'BEGIN{
    u=s; n=s; sub(/[A-Za-z]+$/,"",n); unit=substr(u,length(n)+1)
    m=1; if(unit=="KiB")m=1024; else if(unit=="MiB")m=1024*1024;
    else if(unit=="GiB")m=1024*1024*1024; else if(unit=="B")m=1;
    printf "%d", n*m
  }' </dev/null
}

# --------------------------- 4. watch (host-side, no exec) ---------------------------
echo ">> waiting for decode plateau (flat ${PLATEAU_S}s) or OOM ..."
oom=false; exitc=-; last=0; flat=0; maxseen=0; fetched=0
for i in $(seq 1 $((MAX_WAIT_S / 3))); do
  running=$(docker inspect -f '{{.State.Running}}' "$AGENT" 2>/dev/null || echo false)
  oom=$(docker inspect -f '{{.State.OOMKilled}}' "$AGENT" 2>/dev/null || echo false)
  exitc=$(docker inspect -f '{{.State.ExitCode}}' "$AGENT" 2>/dev/null || echo -)
  cur=$(mem_now); cur=${cur:-0}
  [ "$cur" -gt "$maxseen" ] && maxseen=$cur
  if [ "$fetched" = "0" ] && [ "$(harness_served_count "$SVC" "$STREAM")" -gt 0 ]; then
    fetched=1
    echo "   page served at t=$((i*3))s - plateau detection armed"
  fi
  printf '   t=%3ss running=%s oom=%s fetched=%s mem=%sMB\n' "$((i*3))" "$running" "$oom" "$fetched" "$((cur/1024/1024))"
  if [ "$oom" = "true" ]; then echo "   OOM detected - stopping (memory.peak is at the cap; use a bigger cap for the true peak)"; break; fi
  if [ "$running" != "true" ]; then echo "   agent stopped (oom=$oom exit=$exitc)"; break; fi
  if [ "$fetched" = "1" ] && [ "$cur" -gt 52428800 ] && awk -v c="$cur" -v l="$last" 'BEGIN{d=c-l; if(d<0)d=-d; exit !(l>0 && d < l*0.02)}'; then
    flat=$((flat + 3))
    [ "$flat" -ge "$PLATEAU_S" ] && { echo "   memory plateau reached"; break; }
  else
    flat=0
  fi
  last=$cur
  sleep 3
done

# --------------------------- 5. report ---------------------------
harness_read_memory "$AGENT"
peak=$MEM_PEAK
[ "$peak" -lt "$maxseen" ] && peak=$maxseen   # fall back to observed max if exec read failed
MEM_PEAK=$peak
served=$(harness_served_count "$SVC" "$STREAM")
echo
echo "================= RESULT (elastic-agent) ================="
echo " stream          : $STREAM"
echo " agent version   : $STACK_VERSION"
echo " agent image     : $AGENT_IMAGE"
echo " records in page : $TOTAL_EVENTS"
[ "$STREAM" = "incident" ] && echo " alerts/incident : $ALERTS_PER_INCIDENT"
echo " raw page bytes  : $BLOB (~$((BLOB/1024/1024)) MB)"
echo " cgroup cap      : $MEM_LIMIT"
harness_print_memory
if [ "$peak" -gt 0 ] && [ "$BLOB" -gt 0 ]; then
  echo " peak / raw page : $(awk -v p="$peak" -v b="$BLOB" 'BEGIN{printf "%.2fx", p/b}' </dev/null)"
  echo " anon / raw page : $(awk -v p="$MEM_ANON" -v b="$BLOB" 'BEGIN{printf "%.2fx", p/b}' </dev/null)"
fi
echo " OOM killed      : $oom (exit=$exitc)"
echo " page fetches    : $served (expect >=1; counted from the mock access log)"
echo "=========================================================="
[ "$oom" = "true" ] && echo "NOTE: OOM at this cap. Page too large for $MEM_LIMIT - record the largest page that fits."
[ "$served" = "0" ] && echo "WARN: mock never served the data page - the input may not have run; inspect with --log-driver=json-file."
