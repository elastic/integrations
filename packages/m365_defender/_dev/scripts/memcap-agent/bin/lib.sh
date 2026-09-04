#!/usr/bin/env bash
#
# Shared corpus + config assembly for the m365_defender memory harness.
#
# Sourced by bin/run.sh (one agent, one or more streams) and bin/sweep.sh (many runs
# along one axis). Both must exercise the same page and the same spliced ship logic, so
# that logic lives here once rather than being copied per runner.
#
# Provides:
#   harness_gen_corpus <stream> <work> <pkg> <records> <alerts_per_incident>
#       writes <work>/corpus/corpus-1 and echoes its size in bytes.
#   harness_render_config <stream> <work> <out>
#       writes a runnable per-stream agent config, splicing ship logic from the .hbs.
#
# Neither function starts containers; the runners own that.

# Layout anchors, derived once so no caller carries a relative path around:
#   HARNESS_ROOT    memcap-agent/            (bin/, streams/, results/, logs/, work/)
#   HARNESS_STREAMS memcap-agent/streams/    per-stream inputs to a run
#   HARNESS_PKG     packages/m365_defender/  the shipping package the configs are spliced from
HARNESS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HARNESS_STREAMS="$HARNESS_ROOT/streams"
HARNESS_PKG="$(cd "$HARNESS_ROOT/../../.." && pwd)"

# --------------------------- corpus ---------------------------
#
# Pages come from the corpus generator, so a run needs nothing but this repo: no tenant
# access, no sample file, no network. The output contract is a JSON fragment - compact
# records, each ending in a trailing comma - which mock-config.yml splices between
# `{"value":[` and a closing record.
#
# The templates under <stream>/corpus/ are not guesses: their key set, nesting, array
# cardinality and string lengths are calibrated against a real tenant response, so a
# generated page matches a real one in both bytes and key count (the two things Go's JSON
# decode cost tracks). Only those statistics crossed into the repo; see "Record shapes"
# in README.md.
harness_gen_corpus() {
  local stream="$1" work="$2" pkg="$3" records="$4" alerts_per_incident="$5"

  mkdir -p "$work/corpus"

  # Copy the template so markers can be substituted without touching the source, and
  # strip the trailing newline (the generator appends one after every record; a newline
  # in the template would double up and leave blank lines between records).
  printf '%s' "$(cat "$pkg/template.ndjson")" > "$work/template.ndjson"
  if [ "$stream" = "incident" ]; then
    sed -i.bak "s/__ALERTS_PER_INCIDENT__/$alerts_per_incident/g" "$work/template.ndjson"
    rm -f "$work/template.ndjson.bak"
    echo ">> [$stream] $alerts_per_incident alerts per incident" >&2
  fi
  echo ">> [$stream] generating $records records ..." >&2
  CORPORA_LOCATION="$work/corpus" "$HARNESS_EICGT" generate-with-template \
    "$work/template.ndjson" "$pkg/fields.yml" -c "$pkg/config.yml" \
    -y gotext -t "$records" >/dev/null
  local gen
  gen="$(ls -1 "$work/corpus"/*template.ndjson | head -n1)"
  cp "$gen" "$work/corpus/corpus-1"          # mock globs /var/log/<stream>/corpus-*

  wc -c < "$work/corpus/corpus-1" | tr -d ' '
}

# --------------------------- agent config ---------------------------
#
# The stream config is assembled from the shipping .hbs at run time so it cannot drift
# from what the package ships:
#   - cel streams: the `program:` block is spliced verbatim;
#   - httpjson streams: request.transforms + response.pagination + response.split +
#     cursor are spliced, resolving only the tokens the harness needs and KEEPING the
#     include_* conditional bodies (worst case: alerts expanded + nested split).
# Both paths abort on an unresolved Handlebars token, so a .hbs change is a loud failure
# rather than a silently mis-rendered config and a wrong ORR number.
harness_render_config() {
  local stream="$1" work="$2" out="$3"
  local tmpl="$HARNESS_STREAMS/$stream/elastic-agent.yml.tmpl"
  [ -f "$tmpl" ] || { echo "missing $tmpl"; return 1; }

  if [ "$stream" = "vulnerability" ]; then
    local cel_hbs="$HARNESS_PKG/data_stream/vulnerability/agent/stream/cel.yml.hbs"
    [ -f "$cel_hbs" ] || { echo "missing $cel_hbs (needed to assemble the cel config)"; return 1; }
    echo ">> [$stream] assembling config (CEL program from $(basename "$cel_hbs")) ..." >&2
    # Extract the program body, which runs from `program: |-` to the next top-level key.
    awk '
      /^program: \|-$/ { f=1; next }
      f && /^[^[:space:]]/ { f=0 }
      f { print }
    ' "$cel_hbs" > "$work/program.cel"
    [ -s "$work/program.cel" ] || { echo "failed to extract 'program:' block from $cel_hbs"; return 1; }
    if grep -n '{{' "$work/program.cel" >/dev/null 2>&1; then
      echo "ERROR: Handlebars token(s) inside the CEL program spliced from $cel_hbs:"
      grep -n '{{' "$work/program.cel"
      echo "The harness splices the program verbatim and cannot resolve Handlebars inside it."
      return 1
    fi
    # Parse the extraction before using it. A non-empty block is not evidence of a
    # complete one: if the `program:` terminator ever changes shape the awk above would
    # stop early and yield a program that is still valid-looking text, and the run would
    # measure the wrong thing. celfmt parses CEL, so a truncated or over-long extraction
    # fails here with a line number instead of silently producing a wrong ORR number.
    if command -v celfmt >/dev/null 2>&1; then
      if ! celfmt -i "$work/program.cel" > "$work/program.celfmt" 2> "$work/program.celfmt.err"; then
        echo "ERROR: the CEL program extracted from $cel_hbs does not parse:"
        cat "$work/program.celfmt.err"
        echo "The extraction is incomplete or the 'program:' block shape changed; fix the awk in harness_render_config."
        return 1
      fi
    else
      echo "WARN: celfmt not found, so the extracted CEL program was not parse-checked." >&2
      echo "      Install it with: go install github.com/elastic/celfmt/cmd/celfmt@latest" >&2
    fi
    # cel.yml.hbs indents the program body 2 spaces; the tmpl stream wants 6, so
    # re-indent by 4. Indent the verbatim extraction, not celfmt's output: the harness
    # must run exactly what the package ships, and celfmt is only the validator.
    awk '{ if ($0 ~ /^[[:space:]]*$/) print ""; else print "    " $0 }' \
      "$work/program.cel" > "$work/program.indented"
    awk 'FNR==NR { prog[++n]=$0; next }
         /^[[:space:]]*#__CEL_PROGRAM__[[:space:]]*$/ { for (i=1;i<=n;i++) print prog[i]; next }
         { print }' "$work/program.indented" "$tmpl" > "$out"
    return 0
  fi

  local hbs="$HARNESS_PKG/data_stream/$stream/agent/stream/httpjson.yml.hbs"
  [ -f "$hbs" ] || { echo "missing $hbs (needed to assemble the httpjson config)"; return 1; }
  echo ">> [$stream] assembling config (request/pagination/split/cursor from $(basename "$hbs")) ..." >&2
  # Extract the ship "behaviour" region: from `request.transforms:` up to `tags:`. These
  # are column-0 keys in the .hbs; the second awk re-indents them by 4 to sit under
  # inputs[].streams[]. batch_size is neutralised to a huge sentinel so the real
  # gt/$skip=0 pagination guard is false and the input halts after one page (single-page
  # decode = the peak).
  local batch_sentinel=2000000000
  awk '
    /^request\.transforms:/ { f=1 }
    /^tags:/                { f=0 }
    f { print }
  ' "$hbs" \
  | awk -v batch="$batch_sentinel" -v initint="24h" '
      /^[[:space:]]*\{\{#if include_alerts\}\}[[:space:]]*$/               { next }
      /^[[:space:]]*\{\{#if include_unknown_enum_members\}\}[[:space:]]*$/ { next }
      /^[[:space:]]*\{\{\/if\}\}[[:space:]]*$/                             { next }
      {
        gsub(/\{\{batch_size\}\}/, batch)
        gsub(/\{\{initial_interval\}\}/, initint)
        if ($0 ~ /^[[:space:]]*$/) print ""; else print "    " $0
      }
    ' > "$work/behavior.rendered"
  [ -s "$work/behavior.rendered" ] || { echo "failed to extract behaviour block from $hbs"; return 1; }
  if grep -n '{{' "$work/behavior.rendered" >/dev/null 2>&1; then
    echo "ERROR: unresolved Handlebars token(s) in the spliced block from $hbs:"
    grep -n '{{' "$work/behavior.rendered"
    echo "Update harness_render_config in lib.sh to handle them."
    return 1
  fi
  awk 'FNR==NR { body[++n]=$0; next }
       /^[[:space:]]*#__STREAM_BEHAVIOR__[[:space:]]*$/ { for (i=1;i<=n;i++) print body[i]; next }
       { print }' "$work/behavior.rendered" "$tmpl" > "$out"
}

# --------------------------- did the page actually get served? ---------------------------
#
# Match the mock's access-log line, not the endpoint path on its own: at startup the mock
# logs `Setting up rule #N for path "<path>"` for every rule, so a bare path grep reports
# a hit before any request has been made and would happily "confirm" a page that was
# never fetched. The access log is emitted once per served request, so counting it gives
# the true fetch count.
harness_served_pattern() {
  case "$1" in
    alert)         echo '] "GET /v1.0/security/alerts_v2' ;;
    incident)      echo '] "GET /v1.0/security/incidents' ;;
    vulnerability) echo '] "GET /api/machines/SoftwareVulnerabilityChangesByMachine' ;;
  esac
}

# Fetches served for one stream. Counted host-side from the mock's logs so it costs no
# exec into the agent's cgroup (which would ratchet memory.peak).
harness_served_count() {
  local svc="$1" stream="$2"
  docker logs "$svc" 2>&1 | grep -cF "$(harness_served_pattern "$stream")" || true
}

# --------------------------- memory accounting ---------------------------
#
# Reports the cgroup memory breakdown in ONE docker exec. Never call this inside a poll
# loop: each exec joins the container cgroup and ratchets memory.peak up.
#
# Why the breakdown matters. `memory.peak` and `docker stats` count anonymous memory
# (the Go heap - what a leak or a big decode actually costs) AND the page cache the
# container charged while reading files, which for the elastic-agent image is hundreds of
# MB of binaries. Kubernetes reports something different again:
#
#   container_memory_working_set_bytes = memory.current - inactive_file
#
# so it drops reclaimable cache but keeps active cache. Production ORR telemetry uses the
# working-set metric, so comparing it against a raw memory.peak from this harness would
# compare two different quantities. This prints all of them: peak, current, anon, file,
# and a working-set figure computed the way kubelet computes it.
#
# Sets: MEM_PEAK MEM_CURRENT MEM_ANON MEM_FILE MEM_INACTIVE_FILE MEM_WORKINGSET (bytes).
harness_read_memory() {
  local agent="$1" raw
  raw=$(docker exec "$agent" sh -c '
    if [ -f /sys/fs/cgroup/memory.peak ]; then
      echo "peak $(cat /sys/fs/cgroup/memory.peak)"
      echo "current $(cat /sys/fs/cgroup/memory.current)"
      cat /sys/fs/cgroup/memory.stat
    else
      echo "peak $(cat /sys/fs/cgroup/memory/memory.max_usage_in_bytes)"
      echo "current $(cat /sys/fs/cgroup/memory/memory.usage_in_bytes)"
      cat /sys/fs/cgroup/memory/memory.stat
    fi' 2>/dev/null || true)

  MEM_PEAK=$(printf '%s\n' "$raw"  | awk '$1=="peak"{print $2; exit}')
  MEM_CURRENT=$(printf '%s\n' "$raw" | awk '$1=="current"{print $2; exit}')
  MEM_ANON=$(printf '%s\n' "$raw" | awk '$1=="anon"||$1=="total_rss"{print $2; exit}')
  MEM_FILE=$(printf '%s\n' "$raw" | awk '$1=="file"||$1=="total_cache"{print $2; exit}')
  MEM_INACTIVE_FILE=$(printf '%s\n' "$raw" | awk '$1=="inactive_file"||$1=="total_inactive_file"{print $2; exit}')
  MEM_PEAK=${MEM_PEAK:-0}; MEM_CURRENT=${MEM_CURRENT:-0}
  MEM_ANON=${MEM_ANON:-0}; MEM_FILE=${MEM_FILE:-0}; MEM_INACTIVE_FILE=${MEM_INACTIVE_FILE:-0}
  MEM_WORKINGSET=$((MEM_CURRENT - MEM_INACTIVE_FILE))
  if [ "$MEM_WORKINGSET" -lt 0 ]; then MEM_WORKINGSET=0; fi
  return 0
}

# --------------------------- the results CSV ---------------------------
#
# Every run appends one row here, not just the sweeps, because a number that only ever
# existed in a terminal cannot be re-checked later. The published tables in README.md and
# in the ORR are rendered from these files by the agentless-orr skill's harness_autofill.sh,
# so the schema below is a contract shared with that renderer - adding a column is safe,
# renaming or reordering one is not.
#
#   axis          what was varied across the rows of this file: scale | alerts_per_incident
#                 | knob | stream. One file per axis; the renderer fits or tabulates it.
#   point         the x value. Numeric for a fitted axis; a slug for `knob`/`stream`.
#   label         human-readable row name, used verbatim as the first column of knob tables.
#   streams       which agentless streams ran in the agent, `+`-separated.
#   params        free-form `k=v` pairs (page size per stream, alerts_per_incident, ...).
#                 Space-separated so the field stays comma-free and needs no quoting.
#   mode          cold (one page per input) | sustained (back-to-back fetching, drained).
#   *_bytes       as measured; MB conversion is the renderer's job, so no precision is
#                 lost in the file and the tables stay consistent.
#   peak          cgroup memory.peak: a true kernel high-water mark, but of anon + page
#                 cache, so it is NOT the kubelet metric and must not be compared with
#                 kubernetes.container.memory.workingset.bytes. Its production counterpart
#                 is the cgroup usage figure (`usage.bytes`).
#   workingset    memory.current - inactive_file at the end of the run, i.e. the kubelet
#                 metric, but a single closing snapshot rather than a maximum.
#   workingset_peak
#                 the largest working set seen while the run was in progress, sampled every
#                 3s (docker stats already subtracts inactive_file on cgroup v2). This is
#                 the column to compare with the production workingset.bytes peak. A 3s
#                 sample can miss a shorter spike, so it is a lower bound. Empty on rows
#                 measured before this column existed.
#   run_log       the console log of this run, under logs/. A local breadcrumb only:
#                 logs/ is not committed, so this is blanked when a CSV is promoted into
#                 results/ rather than left pointing at a file no reviewer has. Provenance
#                 for a published file belongs in its `#` header comment instead.
HARNESS_CSV_HEADER='axis,point,label,streams,params,mode,mem_limit_bytes,gomemlimit,hold_s,total_raw_bytes,peak_bytes,workingset_bytes,workingset_peak_bytes,anon_bytes,oom,agent_image,run_log'

# harness_emit_result_row <csv> <axis> <point> <label> <params> <run_log>
# Reads the run's own state (STREAMS, MEM_*, oom, ...) from the caller's scope.
harness_emit_result_row() {
  local csv="$1" axis="$2" point="$3" label="$4" params="$5" run_log="$6"
  local mode limit_bytes
  mode=$([ "${HOLD_S:-0}" -gt 0 ] && echo sustained || echo cold)
  limit_bytes=$(awk -v s="${MEM_LIMIT:-0}" 'BEGIN{
    n=s; sub(/[A-Za-z]+$/,"",n); u=tolower(substr(s,length(n)+1))
    m=1; if(u=="k")m=1024; else if(u=="m")m=1048576; else if(u=="g")m=1073741824
    printf "%d", n*m
  }' </dev/null)
  mkdir -p "$(dirname "$csv")"
  [ -f "$csv" ] || printf '%s\n' "$HARNESS_CSV_HEADER" > "$csv"
  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$axis" "$point" "$label" "$(echo "${STREAMS:-}" | tr ' ' '+')" "$params" "$mode" \
    "$limit_bytes" "${GOMEMLIMIT:-}" "${HOLD_S:-0}" "${TOTAL_PAGE:-0}" \
    "${MEM_PEAK:-0}" "${MEM_WORKINGSET:-0}" "${MEM_WORKINGSET_PEAK:-}" "${MEM_ANON:-0}" \
    "${oom:-unknown}" "${AGENT_IMAGE:-}" "$(basename "${run_log:-}")" >> "$csv"
}

harness_print_memory() {
  local mb=1048576
  printf ' memory.peak     : %s (~%s MB)  [anon + page cache; NOT the k8s metric]\n' "$MEM_PEAK" "$((MEM_PEAK / mb))"
  printf ' memory.current  : %s (~%s MB)  at end of run\n' "$MEM_CURRENT" "$((MEM_CURRENT / mb))"
  printf '   anon (heap)   : ~%s MB   <- what the decode actually costs\n' "$((MEM_ANON / mb))"
  printf '   page cache    : ~%s MB (inactive ~%s MB)\n' "$((MEM_FILE / mb))" "$((MEM_INACTIVE_FILE / mb))"
  printf ' working set     : ~%s MB   at end of run\n' "$((MEM_WORKINGSET / mb))"
  if [ "${MEM_WORKINGSET_PEAK:-0}" -gt 0 ]; then
    printf ' working set peak: ~%s MB   <- compare with kubernetes.container.memory.workingset.bytes (3s samples)\n' \
      "$((MEM_WORKINGSET_PEAK / mb))"
  fi
}

# --------------------------- shared prerequisites ---------------------------
harness_require_docker() {
  command -v docker >/dev/null || { echo "docker not found"; return 1; }
  docker info >/dev/null 2>&1 || { echo "docker daemon not running"; return 1; }
}

# Locates the corpus generator, which every run needs to build its pages.
harness_find_eicgt() {
  local tool="${1:-$HOME/go/src/github.com/elastic/elastic-integration-corpus-generator-tool}"
  if [ -x "$tool/eicgt" ]; then
    HARNESS_EICGT="$tool/eicgt"
  elif [ -x "$tool/elastic-integration-corpus-generator-tool" ]; then
    HARNESS_EICGT="$tool/elastic-integration-corpus-generator-tool"
  else
    echo "corpus tool binary not found in $tool (build it first: cd $tool && go build -o eicgt .)"
    return 1
  fi
}
