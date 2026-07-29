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
# The stream config is assembled at run time from this directory so it never drifts
# from what the package ships - every stream splices the ship logic from its .hbs into
# <stream>/elastic-agent.yml.tmpl:
#   - httpjson streams (alert/incident) splice request.transforms + response.pagination
#     + response.split + cursor from the shipping httpjson.yml.hbs, resolving the few
#     Handlebars tokens the harness cares about (batch_size, initial_interval, the
#     include_* conditionals);
#   - the cel stream splices the CEL program from the shipping cel.yml.hbs.
# Change the .hbs and the next run picks it up - no hand-maintained copy. run.sh errors
# out if a .hbs grows a token the render step does not understand, so drift is caught,
# not silently mis-rendered.
#
# Sweep the page size with TOTAL_EVENTS and the cap with MEM_LIMIT, e.g.:
#   STREAM=alert         MEM_LIMIT=1g   TOTAL_EVENTS=1000  ./run.sh
#   STREAM=incident      MEM_LIMIT=1g   TOTAL_EVENTS=50 ALERTS_PER_INCIDENT=100 ./run.sh
#   STREAM=vulnerability MEM_LIMIT=512m TOTAL_EVENTS=10000 ./run.sh
# Or use ./sweep.sh to fit the peak/page multiplier across several page sizes.
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
  alert)         TOTAL_EVENTS="${TOTAL_EVENTS:-1000}";  SERVED_GREP='security/alerts_v2'; CEL=0 ;;
  incident)      TOTAL_EVENTS="${TOTAL_EVENTS:-50}";    SERVED_GREP='security/incidents'; CEL=0 ;;
  vulnerability) TOTAL_EVENTS="${TOTAL_EVENTS:-10000}"; SERVED_GREP='SoftwareVulnerabilityChangesByMachine'; CEL=1 ;;
  *) echo "unknown STREAM=$STREAM (want alert|incident|vulnerability)"; exit 1 ;;
esac

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIR="$HERE/$STREAM"
TOOL="${TOOL:-$HOME/go/src/github.com/elastic/elastic-integration-corpus-generator-tool}"
PKG="$DIR/corpus"
MOCK_CONFIG="$DIR/mock-config.yml"
CEL_HBS="$HERE/../../../data_stream/vulnerability/agent/stream/cel.yml.hbs"
HBS="$HERE/../../../data_stream/$STREAM/agent/stream/httpjson.yml.hbs"  # httpjson streams

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
command -v docker >/dev/null || { echo "docker not found"; exit 1; }
[ -d "$DIR" ] || { echo "missing stream dir $DIR"; exit 1; }
[ -f "$MOCK_CONFIG" ] || { echo "missing $MOCK_CONFIG"; exit 1; }
[ -x "$TOOL/eicgt" ] || [ -x "$TOOL/elastic-integration-corpus-generator-tool" ] || {
  echo "corpus tool binary not found in $TOOL (build it first: cd $TOOL && go build -o eicgt .)"; exit 1; }
EICGT="$TOOL/eicgt"; [ -x "$EICGT" ] || EICGT="$TOOL/elastic-integration-corpus-generator-tool"

# --------------------------- 1. generate corpus ---------------------------
rm -rf "$WORK"; mkdir -p "$WORK/corpus"
# Copy the template so we can substitute markers without touching the source, and
# strip the trailing newline (the generator appends one after every record; a
# newline in the template would double up and leave blank lines between records).
printf '%s' "$(cat "$PKG/template.ndjson")" > "$WORK/template.ndjson"
if [ "$STREAM" = "incident" ]; then
  sed -i.bak "s/__ALERTS_PER_INCIDENT__/$ALERTS_PER_INCIDENT/g" "$WORK/template.ndjson"
  rm -f "$WORK/template.ndjson.bak"
  echo ">> incident: $ALERTS_PER_INCIDENT alerts per incident"
fi
echo ">> generating $TOTAL_EVENTS records for '$STREAM' ..."
CORPORA_LOCATION="$WORK/corpus" "$EICGT" generate-with-template \
  "$WORK/template.ndjson" "$PKG/fields.yml" -c "$PKG/config.yml" \
  -y gotext -t "$TOTAL_EVENTS" >/dev/null
GEN="$(ls -1 "$WORK/corpus"/*template.ndjson | head -n1)"
cp "$GEN" "$WORK/corpus/corpus-1"                  # mock globs /var/log/corpus-*
BLOB=$(wc -c < "$WORK/corpus/corpus-1" | tr -d ' ')
echo ">> page: $TOTAL_EVENTS records, $BLOB bytes (~$((BLOB/1024/1024)) MB raw), cap=$MEM_LIMIT, agent=$STACK_VERSION"

# --------------------------- 1b. assemble agent config ---------------------------
if [ "$CEL" = "1" ]; then
  [ -f "$CEL_HBS" ] || { echo "missing $CEL_HBS (needed to assemble the cel config)"; exit 1; }
  echo ">> assembling agent config (CEL program from $CEL_HBS) ..."
  # cel.yml.hbs indents the program body 2 spaces; the tmpl stream wants 6, so
  # re-indent by 4. The block runs from `program: |-` to the next top-level key.
  awk '
    /^program: \|-$/ { f=1; next }
    f && /^[^[:space:]]/ { f=0 }
    f { if ($0 ~ /^[[:space:]]*$/) print ""; else print "    " $0 }
  ' "$CEL_HBS" > "$WORK/program.indented"
  [ -s "$WORK/program.indented" ] || { echo "failed to extract 'program:' block from $CEL_HBS"; exit 1; }
  # Drift guard: the program is spliced verbatim; a Handlebars token inside it would be
  # copied literally into the config. The program is Handlebars-free today - fail loudly
  # if that ever changes rather than run a broken config.
  if grep -n '{{' "$WORK/program.indented" >/dev/null 2>&1; then
    echo "ERROR: Handlebars token(s) inside the CEL program spliced from $CEL_HBS:"
    grep -n '{{' "$WORK/program.indented"
    echo "The harness splices the program verbatim and cannot resolve Handlebars inside it."
    exit 1
  fi
  awk 'FNR==NR { prog[++n]=$0; next }
       /^[[:space:]]*#__CEL_PROGRAM__[[:space:]]*$/ { for (i=1;i<=n;i++) print prog[i]; next }
       { print }' "$WORK/program.indented" "$DIR/elastic-agent.yml.tmpl" > "$AGENT_YML"
else
  [ -f "$HBS" ] || { echo "missing $HBS (needed to assemble the httpjson config)"; exit 1; }
  [ -f "$DIR/elastic-agent.yml.tmpl" ] || { echo "missing $DIR/elastic-agent.yml.tmpl"; exit 1; }
  echo ">> assembling agent config (request/pagination/split/cursor from $HBS) ..."
  # Extract the ship "behaviour" region: from `request.transforms:` up to `tags:`
  # (request.transforms + response.pagination + response.split + cursor). These are
  # column-0 keys in the .hbs; the second awk re-indents them by 4 to sit under
  # inputs[].streams[]. We resolve only the tokens the harness needs and KEEP the
  # include_* conditional bodies (worst case: alerts expanded + nested split).
  # batch_size is neutralised to a huge sentinel so the real gt/$skip=0 pagination
  # guard is false and the input halts after one page (single-page decode = the peak).
  BATCH_SENTINEL=2000000000
  awk '
    /^request\.transforms:/ { f=1 }
    /^tags:/                { f=0 }
    f { print }
  ' "$HBS" \
  | awk -v batch="$BATCH_SENTINEL" -v initint="24h" '
      /^[[:space:]]*\{\{#if include_alerts\}\}[[:space:]]*$/               { next }
      /^[[:space:]]*\{\{#if include_unknown_enum_members\}\}[[:space:]]*$/ { next }
      /^[[:space:]]*\{\{\/if\}\}[[:space:]]*$/                             { next }
      {
        gsub(/\{\{batch_size\}\}/, batch)
        gsub(/\{\{initial_interval\}\}/, initint)
        if ($0 ~ /^[[:space:]]*$/) print ""; else print "    " $0
      }
    ' > "$WORK/behavior.rendered"
  [ -s "$WORK/behavior.rendered" ] || { echo "failed to extract behaviour block from $HBS"; exit 1; }
  # Drift guard: any Handlebars token we did not resolve means the .hbs changed in a
  # way this render step does not understand - fail loudly rather than run a broken config.
  if grep -n '{{' "$WORK/behavior.rendered" >/dev/null 2>&1; then
    echo "ERROR: unresolved Handlebars token(s) in the spliced block from $HBS:"
    grep -n '{{' "$WORK/behavior.rendered"
    echo "Update the render step (section 1b) in run.sh to handle them."
    exit 1
  fi
  awk 'FNR==NR { body[++n]=$0; next }
       /^[[:space:]]*#__STREAM_BEHAVIOR__[[:space:]]*$/ { for (i=1;i<=n;i++) print body[i]; next }
       { print }' "$WORK/behavior.rendered" "$DIR/elastic-agent.yml.tmpl" > "$AGENT_YML"
fi

# --------------------------- 2. mock ---------------------------
docker network create "$NET" >/dev/null 2>&1 || true
docker rm -f "$SVC" "$AGENT" >/dev/null 2>&1 || true
docker run -d --name "$SVC" --network "$NET" --network-alias "$SVC" \
  -v "$MOCK_CONFIG":/files/config.yml:ro \
  -v "$WORK/corpus/corpus-1":/var/log/corpus-1:ro \
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

# memory.peak is monotonic; read it ONCE at the very end with a single exec. We do
# NOT exec inside the loop (each exec joins the container cgroup and ratchets the
# peak up). Completion is detected host-side via `docker stats`.
read_peak() {
  docker exec "$AGENT" sh -c \
    'cat /sys/fs/cgroup/memory.peak 2>/dev/null || cat /sys/fs/cgroup/memory/memory.max_usage_in_bytes 2>/dev/null' \
    2>/dev/null || echo 0
}
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
oom=false; exitc=-; last=0; flat=0; maxseen=0
for i in $(seq 1 $((MAX_WAIT_S / 3))); do
  running=$(docker inspect -f '{{.State.Running}}' "$AGENT" 2>/dev/null || echo false)
  oom=$(docker inspect -f '{{.State.OOMKilled}}' "$AGENT" 2>/dev/null || echo false)
  exitc=$(docker inspect -f '{{.State.ExitCode}}' "$AGENT" 2>/dev/null || echo -)
  cur=$(mem_now); cur=${cur:-0}
  [ "$cur" -gt "$maxseen" ] && maxseen=$cur
  printf '   t=%3ss running=%s oom=%s mem=%sMB\n' "$((i*3))" "$running" "$oom" "$((cur/1024/1024))"
  if [ "$oom" = "true" ]; then echo "   OOM detected - stopping (memory.peak is at the cap; use a bigger cap for the true peak)"; break; fi
  if [ "$running" != "true" ]; then echo "   agent stopped (oom=$oom exit=$exitc)"; break; fi
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
served=$(docker logs "$SVC" 2>&1 | grep -c "$SERVED_GREP" || true)
echo
echo "================= RESULT (elastic-agent) ================="
echo " stream          : $STREAM"
echo " agent version   : $STACK_VERSION"
echo " agent image     : $AGENT_IMAGE"
echo " records in page : $TOTAL_EVENTS"
[ "$STREAM" = "incident" ] && echo " alerts/incident : $ALERTS_PER_INCIDENT"
echo " raw page bytes  : $BLOB (~$((BLOB/1024/1024)) MB)"
echo " cgroup cap      : $MEM_LIMIT"
echo " memory.peak     : $peak (~$((peak/1024/1024)) MB)"
if [ "$peak" -gt 0 ] && [ "$BLOB" -gt 0 ]; then
  echo " peak / raw page : $(awk -v p="$peak" -v b="$BLOB" 'BEGIN{printf "%.2fx", p/b}' </dev/null)"
fi
echo " OOM killed      : $oom (exit=$exitc)"
echo " page fetches    : $served (expect >=1; confirms the page was served)"
echo "=========================================================="
[ "$oom" = "true" ] && echo "NOTE: OOM at this cap. Page too large for $MEM_LIMIT - record the largest page that fits."
[ "$served" = "0" ] && echo "WARN: mock never served the data page - the input may not have run; inspect with --log-driver=json-file."
