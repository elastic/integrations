#!/usr/bin/env bash
#
# o365 CEL input - synthetic worst-case memory run.
#
# The CEL input runs inside a real elastic-agent container configured the way
# agentless-controller deploys it (single container, monitoring enabled with
# logs/metrics collection off, no GOMEMLIMIT, agentless env flags). This is the
# authoritative harness for the ORR memory profile. The input config is assembled
# at run time from elastic-agent.yml.tmpl with the CEL program extracted verbatim
# from the shipping data stream (data_stream/audit/agent/stream/cel.yml.hbs), so it
# always matches what o365 ships. The only external dependency is the corpus
# generator; the corpus/mock files live in this directory.
#
# Deviations from a live agentless pod (do not materially change decode peak):
#   - output points at an unreachable ES (events are held, never drained), so no
#     real Elasticsearch is needed and drained events add no page cache;
#   - AGENTLESS_ELASTICSEARCH_STATE_STORE_INPUT_TYPES is NOT set (CEL cursor state
#     lives on local disk here; the cursor is a few KB and irrelevant to memory);
#   - APM is off (no APM server).
#
# Sweep the blob size with TOTAL_EVENTS and the cap with MEM_LIMIT:
#   MEM_LIMIT=1g   TOTAL_EVENTS=100000 ./run.sh
#   MEM_LIMIT=512m TOTAL_EVENTS=50000  ./run.sh
# Or use ./sweep.sh to fit the peak/blob multiplier across several blob sizes.
#
# Match STACK_VERSION to the agent version agentless actually ships, otherwise the
# numbers are not representative for the ORR.

set -euo pipefail

# --------------------------- config (override via env) ---------------------------
STACK_VERSION="${STACK_VERSION:-9.4.2}"           # MUST match the shipped agent version
TOTAL_EVENTS="${TOTAL_EVENTS:-100000}"            # events in the single blob
MEM_LIMIT="${MEM_LIMIT:-1g}"                       # cgroup cap = agentless pod mem limit
STREAM_IMAGE="${STREAM_IMAGE:-docker.elastic.co/observability/stream:v0.20.0}"
KEEP="${KEEP:-0}"                                  # KEEP=1 to leave containers up
MAX_WAIT_S="${MAX_WAIT_S:-600}"                    # hard cap on the wait loop
PLATEAU_S="${PLATEAU_S:-30}"                       # memory flat this long => decode done

# This harness is self-contained under packages/o365/_dev/scripts/memcap-agent/:
# corpus/ holds the generator template/config/fields, mock-config.yml is the
# elastic/stream mock config, elastic-agent.yml.tmpl is the input-config template
# (the CEL program is pulled from the shipping cel.yml.hbs at run time - see step 1b).
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOL="${TOOL:-$HOME/go/src/github.com/elastic/elastic-integration-corpus-generator-tool}"
PKG="$HERE/corpus"
MOCK_CONFIG="$HERE/mock-config.yml"
AGENT_TMPL="$HERE/elastic-agent.yml.tmpl"
CEL_HBS="$HERE/../../../data_stream/audit/agent/stream/cel.yml.hbs"

NET=o365-memcap-net
WORK="$HERE/work"
AGENT_YML="$WORK/elastic-agent.yml"                 # assembled at run time from AGENT_TMPL + CEL_HBS (step 1b)

cleanup() {
  [ "$KEEP" = "1" ] && { echo "KEEP=1: leaving svc-o365 / o365-agent up"; return; }
  docker rm -f svc-o365 o365-agent >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# --------------------------- 0. sanity ---------------------------
command -v docker >/dev/null || { echo "docker not found"; exit 1; }
[ -x "$TOOL/eicgt" ] || [ -x "$TOOL/elastic-integration-corpus-generator-tool" ] || {
  echo "corpus tool binary not found in $TOOL (build it first: cd $TOOL && go build -o eicgt .)"; exit 1; }
EICGT="$TOOL/eicgt"; [ -x "$EICGT" ] || EICGT="$TOOL/elastic-integration-corpus-generator-tool"
[ -f "$AGENT_TMPL" ] || { echo "missing $AGENT_TMPL"; exit 1; }
[ -f "$CEL_HBS" ]    || { echo "missing $CEL_HBS (needed to assemble the agent config)"; exit 1; }

# --------------------------- 1. generate corpus ---------------------------
rm -rf "$WORK"; mkdir -p "$WORK/corpus"
echo ">> generating $TOTAL_EVENTS events ..."
CORPORA_LOCATION="$WORK/corpus" "$EICGT" generate-with-template \
  "$PKG/template.ndjson" "$PKG/fields.yml" -c "$PKG/config.yml" \
  -y gotext -t "$TOTAL_EVENTS" >/dev/null
GEN="$(ls -1 "$WORK/corpus"/*template.ndjson | head -n1)"
cp "$GEN" "$WORK/corpus/corpus-1"                  # mock globs /var/log/corpus-*
BLOB=$(wc -c < "$WORK/corpus/corpus-1" | tr -d ' ')
echo ">> blob: $TOTAL_EVENTS events, $BLOB bytes (~$((BLOB/1024/1024)) MB raw), cap=$MEM_LIMIT, agent=$STACK_VERSION"

# --------------------------- 1b. assemble agent config ---------------------------
# Keep the harness honest: rather than storing a copy of the CEL program that can
# drift, extract the shipping `program:` block verbatim from cel.yml.hbs and splice
# it into the template, so every run exercises exactly what o365 ships. The block in
# cel.yml.hbs is indented 2 spaces; the stream in the template wants 6, so re-indent
# by 4. The block runs from the `program: |-` line to the next top-level key.
echo ">> assembling agent config (CEL program from $CEL_HBS) ..."
awk '
  /^program: \|-$/ { f=1; next }
  f && /^[^[:space:]]/ { f=0 }
  f { if ($0 ~ /^[[:space:]]*$/) print ""; else print "    " $0 }
' "$CEL_HBS" > "$WORK/program.indented"
[ -s "$WORK/program.indented" ] || { echo "failed to extract 'program:' block from $CEL_HBS"; exit 1; }
awk 'FNR==NR { prog[++n]=$0; next }
     /^[[:space:]]*#__CEL_PROGRAM__[[:space:]]*$/ { for (i=1;i<=n;i++) print prog[i]; next }
     { print }' "$WORK/program.indented" "$AGENT_TMPL" > "$AGENT_YML"

# --------------------------- 2. mock ---------------------------
docker network create "$NET" >/dev/null 2>&1 || true
docker rm -f svc-o365 o365-agent >/dev/null 2>&1 || true
docker run -d --name svc-o365 --network "$NET" --network-alias svc-o365 \
  -v "$MOCK_CONFIG":/files/config.yml:ro \
  -v "$WORK/corpus/corpus-1":/var/log/corpus-1:ro \
  "$STREAM_IMAGE" http-server --addr=:8082 --config=/files/config.yml >/dev/null
echo ">> waiting for mock token endpoint ..."
for i in $(seq 1 30); do
  code=$(docker run --rm --network "$NET" curlimages/curl:8.9.1 -s -o /dev/null -w '%{http_code}' \
    -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
    "http://svc-o365:8082/test-cel-tenant-id/oauth2/v2.0/token?client_id=test-cel-client-id&client_secret=test-cel-client-secret&grant_type=client_credentials&scope=https://manage.office.com/.default" 2>/dev/null || echo 000)
  [ "$code" = "200" ] && { echo "   mock ready"; break; }
  sleep 1
  [ "$i" = "30" ] && { echo "   mock did not become ready"; docker logs svc-o365; exit 1; }
done

# --------------------------- 3. capped elastic-agent ---------------------------
# Standalone agent with the agentless env flags. No FLEET_* -> the container
# entrypoint runs standalone against the mounted elastic-agent.yml. No GOMEMLIMIT,
# matching agentless.
echo ">> starting capped elastic-agent (mem=$MEM_LIMIT) ..."
docker run -d --name o365-agent --network "$NET" \
  --memory="$MEM_LIMIT" --memory-swap="$MEM_LIMIT" \
  --log-driver=none \
  -e ELASTIC_CONTAINER=true \
  -e ELASTIC_AGENT_IS_AGENTLESS=1 \
  -e AGENT_MONITORING_PORT=6791 \
  -e "BEATS_ADD_CLOUD_METADATA_PROVIDERS= " \
  -e GODEBUG=madvdontneed=1 \
  -v "$AGENT_YML":/usr/share/elastic-agent/elastic-agent.yml:ro \
  "docker.elastic.co/elastic-agent/elastic-agent:$STACK_VERSION" >/dev/null

# memory.peak is monotonic; read it ONCE at the very end with a single exec. We do
# NOT exec inside the loop (each exec joins the container cgroup and ratchets the
# peak up). Completion is detected host-side via `docker stats`, which reads the
# cgroup from the daemon and does not enter the container.
read_peak() {
  docker exec o365-agent sh -c \
    'cat /sys/fs/cgroup/memory.peak 2>/dev/null || cat /sys/fs/cgroup/memory/memory.max_usage_in_bytes 2>/dev/null' \
    2>/dev/null || echo 0
}
mem_now() {  # current cgroup usage in bytes, host-side (no exec)
  local raw
  raw=$(docker stats --no-stream --format '{{.MemUsage}}' o365-agent 2>/dev/null | awk '{print $1}')
  awk -v s="$raw" 'BEGIN{
    u=s; n=s; sub(/[A-Za-z]+$/,"",n); unit=substr(u,length(n)+1)
    m=1; if(unit=="KiB")m=1024; else if(unit=="MiB")m=1024*1024;
    else if(unit=="GiB")m=1024*1024*1024; else if(unit=="B")m=1;
    printf "%d", n*m
  }' </dev/null
}

# --------------------------- 4. watch (host-side, no exec) ---------------------------
# Agent takes ~15-40s to bootstrap the filebeat component before the CEL input
# runs. We watch memory rise then plateau (events are held because output is
# unreachable); a flat window of PLATEAU_S means the decode peak is reached.
echo ">> waiting for decode plateau (flat ${PLATEAU_S}s) or OOM ..."
oom=false; exitc=-; last=0; flat=0; maxseen=0
for i in $(seq 1 $((MAX_WAIT_S / 3))); do
  running=$(docker inspect -f '{{.State.Running}}' o365-agent 2>/dev/null || echo false)
  oom=$(docker inspect -f '{{.State.OOMKilled}}' o365-agent 2>/dev/null || echo false)
  exitc=$(docker inspect -f '{{.State.ExitCode}}' o365-agent 2>/dev/null || echo -)
  cur=$(mem_now); cur=${cur:-0}
  [ "$cur" -gt "$maxseen" ] && maxseen=$cur
  printf '   t=%3ss running=%s oom=%s mem=%sMB\n' "$((i*3))" "$running" "$oom" "$((cur/1024/1024))"
  # On OOM the beat is killed but the Agent supervisor restarts it, so the
  # container keeps running and crash-loops. memory.peak is already pinned at the
  # cap, so stop immediately instead of waiting for the (never-clean) plateau.
  if [ "$oom" = "true" ]; then echo "   OOM detected - stopping (memory.peak is at the cap; use a bigger cap for the true peak)"; break; fi
  if [ "$running" != "true" ]; then echo "   agent stopped (oom=$oom exit=$exitc)"; break; fi
  # plateau: within ~2% of last sample and non-trivial usage
  if [ "$cur" -gt 52428800 ] && awk -v c="$cur" -v l="$last" 'BEGIN{d=c-l; if(d<0)d=-d; exit !(l>0 && d < l*0.02)}'; then
    flat=$((flat + 3))
    [ "$flat" -ge "$PLATEAU_S" ] && { echo "   memory plateau reached"; break; }
  else
    flat=0
  fi
  last=$cur
  sleep 3
done

# --------------------------- 5. report ---------------------------
peak=$(read_peak); peak=${peak:-0}
[ "$peak" -lt "$maxseen" ] && peak=$maxseen   # fall back to observed max if exec read failed
served=$(docker logs svc-o365 2>&1 | grep -c 'activity/feed/audit/' || true)
echo
echo "================= RESULT (elastic-agent) ================="
echo " agent version   : $STACK_VERSION"
echo " events in blob  : $TOTAL_EVENTS"
echo " raw blob bytes  : $BLOB (~$((BLOB/1024/1024)) MB)"
echo " cgroup cap      : $MEM_LIMIT"
echo " memory.peak     : $peak (~$((peak/1024/1024)) MB)"
if [ "$peak" -gt 0 ] && [ "$BLOB" -gt 0 ]; then
  echo " peak / raw blob : $(awk -v p="$peak" -v b="$BLOB" 'BEGIN{printf "%.2fx", p/b}' </dev/null)"
fi
echo " OOM killed      : $oom (exit=$exitc)"
echo " content fetches : $served (expect >=1; confirms the blob was served)"
echo "=========================================================="
[ "$oom" = "true" ] && echo "NOTE: OOM at this cap. Blob too large for $MEM_LIMIT - record the largest blob that fits."
[ "$served" = "0" ] && echo "WARN: mock never served a content fetch - the input may not have run; inspect 'docker logs o365-agent' with --log-driver=json-file."
