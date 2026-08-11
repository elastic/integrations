# m365_defender agentless worst-case memory harness

Memory test for the three agentless m365_defender inputs, built for the agentless
Operational Readiness Review (ORR). It answers one question — **how much memory does an
agentless pod running this integration need, and what would it take to need less?**

A pod runs every enabled stream of the policy in a single `elastic-agent`, and every
httpjson/cel input lives in the same beat process and therefore the same Go heap. So the
harness is **concurrent by default**: one agent, one page per enabled stream. Measuring
streams separately and adding the results is wrong in both directions — the per-process
baseline is paid once rather than three times, but the decode peaks land on one heap with
one GC cycle and one shared publisher queue. Only a combined run measures the real number,
and only a *sustained* combined run reproduces the production peaks (see
[Reproducing the production peak](#reproducing-the-production-peak)).

Single-stream runs still exist, as `STREAMS=incident bin/run.sh`, because the ORR asks for
the memory driver **per stream** and because attributing a pod peak to the stream that
causes it is what justifies tuning one knob rather than another. They are attribution, not
addends.

This is a bespoke Docker + cgroup harness, **not** an `elastic-package` benchmark.
It runs the real `elastic-agent` image the way `agentless-controller` deploys it
against the `elastic/stream` mock serving one big API page, under a Docker
`--memory` cap, and reads both the cgroup `memory.peak` high-water mark and the
kubelet-comparable working set. Which of the two a given number is matters when it is held
against production telemetry, so every table below says which it is reporting.

Unlike o365 (one giant content blob fetched by a CEL input), the m365_defender
memory driver is a single **API page**, and the shape differs per stream:

| stream          | input    | endpoint                                   | page driver |
| --------------- | -------- | ------------------------------------------ | ----------- |
| `alert`         | httpjson | `/v1.0/security/alerts_v2`                 | records × per-alert size; server caps `$top` at 1000 |
| `incident`      | httpjson | `/v1.0/security/incidents` (`$expand=alerts`) | incidents × alerts-per-incident × per-alert size (nested split, `keep_parent`) |
| `vulnerability` | cel      | `/api/machines/SoftwareVulnerabilityChangesByMachine` | records × per-record size; `pageSize=10000` hard-coded; CEL re-encodes each record |

Scope: the three streams agentless runs. The `event` data stream is deliberately
absent — its input is `azure-eventhub`, which agentless does not support, so it never
contributes to an agentless pod.

## Layout

```
memcap-agent/
├── bin/                    # everything that runs
│   ├── run.sh              # ONE agent, one page per stream in STREAMS (default: all three)
│   ├── sweep.sh            # repeat run.sh along one axis: scale | alerts_per_incident | knob
│   ├── lib.sh              # corpus build, config splice, memory accounting, the results CSV
│   └── fake-es.py          # draining sink, optionally rate-limited (sustained mode)
├── streams/                # everything a run reads, per stream
│   ├── alert/
│   │   ├── elastic-agent.yml.tmpl # request/pagination/split/cursor spliced from httpjson.yml.hbs
│   │   ├── mock-config.yml        # token + alerts_v2 page serving the corpus
│   │   └── corpus/                # template.ndjson, config.yml, fields.yml
│   ├── incident/                  # as above; include_alerts=true, nested split
│   └── vulnerability/             # as above; CEL program spliced from cel.yml.hbs at run time
└── results/                # the measurements the documents publish (committed)
    ├── scale.csv                  # cold, all page sizes scaled together
    ├── alerts-per-incident.csv    # cold, shipped page sizes, alerts[] swept
    ├── sustained.csv              # back-to-back fetching - the production-comparable mode
    ├── knobs.csv                  # the same worst case with one thing changed per row
    └── per-stream.csv             # one stream at a time: the per-stream driver
```

Runs also write `work/` (the generated corpora) and `logs/` (console output and the CSV of
every run). Neither is committed — see `.gitignore`; `work/` alone can hold a
multi-hundred-MB corpus. Re-run the harness to reproduce them.

A run needs nothing but this directory, Docker and the corpus generator: no tenant
access, no sample file, no network beyond the image pulls.

## Record shapes

Go's JSON decode cost tracks the **number of keys and containers** it allocates, not just
the byte count, so a template that hits the right size with the wrong shape gets the
memory wrong: nested object counts move the peak independently of page bytes.

So the templates in `streams/<stream>/corpus/` are calibrated against a real tenant response
on four axes at once. The flow was one-way and ended outside the repo: the response was
sanitised offline (deny-by-default value replacement, preserving lengths and array
cardinalities), its statistics were read off, and **only those statistics** crossed into the
repo — as the key set and the `repeat`/`until` counts in `template.ndjson`. The sanitiser and
its output stayed with the response, outside any repo, and are not part of this harness. **No
customer payload is stored here, and no runner reads one:** what is committed is Microsoft's
documented schema with generated values. The odd-looking `repeat 69` counts are that
calibration — the generator emits short random words, so `repeat` is its only lever on string
length.

Target (real response, compact wire bytes, mean per record) against what the templates
now generate:

| axis | real `alert` | generated | why it matters |
| --- | --- | --- | --- |
| bytes per record | 5,729 | 5,739 (+0.2%) | page size, and the raw-page term in the fit |
| keys per record | 120.8 | 123.0 (+1.8%) | map allocations during decode |
| containers per record | 28.2 | 28.0 (−0.7%) | map/slice headers |
| string bytes per record | 3,426 | 3,371 (−1.6%) | the cheap part per byte |
| `evidence[]` items | 3.48 (p50 3, max 11) | 4 | fixed: the generator cannot vary array length per record |

`incident` is calibrated the same way: a 21-key base record (real mean 987 B) plus an
`alerts[]` array whose members are the alert shape above, which is what `$expand=alerts`
returns. A page of 50 incidents at 100 alerts each comes out within 0.4% of the same page
built directly from the real records.

Two deliberate deviations:

- **Uniform records.** Every generated record is the mean; a real page has a spread. For
  memory that is fine — the whole page is decoded at once, so only the page totals matter.
- **`alerts[]` per incident is a parameter, not a measured value.** The sample tenant was
  quiet (p50 0 alerts per incident, max 1). It is swept instead, because it is the one
  page-size input nothing bounds.

`vulnerability` has no tenant response to calibrate against, so its ~1 KB record is
modelled on the package's own pipeline test data — **the one page input still uncalibrated**.

## Keeping the configs in sync with the shipping inputs

The numbers are only meaningful if the harness runs what the package ships, so **no
stream stores a hand-maintained copy of its config** — each one splices the ship
logic out of its `.hbs` at run time and errors if it can't. There is nothing to
re-sync by hand.

- **vulnerability (cel):** the `program:` block is extracted verbatim from
  `data_stream/vulnerability/agent/stream/cel.yml.hbs`, re-indented, and spliced into
  `streams/vulnerability/elastic-agent.yml.tmpl` in place of the `#__CEL_PROGRAM__`
  placeholder.
- **alert / incident (httpjson):** the ship **behaviour block** — `request.transforms` +
  `response.pagination` + `response.split` + `cursor` — is extracted from
  `data_stream/<stream>/agent/stream/httpjson.yml.hbs`, the few Handlebars tokens the
  harness needs are resolved (`batch_size`, `initial_interval`, and the `include_*`
  conditionals — keeping the `include_alerts` bodies so `$expand=alerts` and the nested
  `body.alerts` split with `keep_parent` are exercised for incidents), and the result is
  spliced into `streams/<stream>/elastic-agent.yml.tmpl` in place of the
  `#__STREAM_BEHAVIOR__` placeholder. Only connection/scaffolding (auth + URL → mock,
  `interval`, output, `tags`) lives in the `.tmpl`, because those are harness environment
  values, not ship logic.

This lives in one place (`harness_render_config` in `bin/lib.sh`), so every run — whatever
streams are enabled — is produced from the same splice.

**Drift guard:** the splice only understands the tokens listed above. If a `.hbs`
grows a new `{{...}}` token in the spliced region (a new `{{#if}}`, a new variable),
the run aborts with the offending line instead of silently mis-rendering — so
staleness becomes a one-line fix in `harness_render_config`, not a wrong ORR number.
`bin/run.sh` also asserts that the merge produced one input per enabled stream and that
each mock config still has exactly its token rule plus one data rule, so a config that
grows a rule fails loudly instead of quietly losing an endpoint.

Both httpjson configs neutralise `batch_size` to a huge sentinel (`2000000000`) in
the spliced block, so the **real** time-boundary pagination (`$filter … gt`,
`$skip=0`) evaluates its full-page guard to false and halts after one page: the whole
page is decoded and held in memory. That isolates the **per-page** peak, which is what
OOMs an agentless pod, while still running the exact request shape 5.15.1 ships (see
the pagination discussion in the ORR; the old `$skip`-cap bug was
elastic/integrations#20234, fixed by elastic/integrations#20348).

## Prerequisites

- Docker running (pulls `elastic-agent`, `observability/stream`, `curlimages/curl`, and
  `python:3.12-alpine` when `DRAIN=1`). Check free memory in the Docker VM first: a run
  that needs more than the VM has left is reclaimed by the host and the numbers are
  meaningless. Stop other stacks (e.g. `elastic-package stack down`) before large caps.
- The corpus generator built once (every run builds its pages with it):
  ```
  cd elastic-integration-corpus-generator-tool && go build -o eicgt .
  ```
  Point `TOOL=` at that repo if it is not at the default path.

## Usage

```
# cold: one page per stream at the shipped production page sizes
bin/run.sh

# sustained: inputs keep fetching and the output drains - compare with production telemetry
DRAIN=1 INTERVAL=10s HOLD_S=300 MEM_LIMIT=3g bin/run.sh

# fit the pod curve, two axes
AXIS=scale               SWEEP_CAP=3g POINTS="0.25 0.5 1 2 3 4 5" bin/sweep.sh
AXIS=alerts_per_incident SWEEP_CAP=3g POINTS="25 50 100 200 400"  bin/sweep.sh

# what is each mitigation worth against the sustained worst case?
AXIS=knob DRAIN=1 INTERVAL=10s HOLD_S=300 ALERTS_PER_INCIDENT=400 bin/sweep.sh

# attribution: what does one stream cost on its own?
STREAMS=incident ALERTS_PER_INCIDENT=400 bin/run.sh

# does a candidate configuration survive a smaller cap?
DRAIN=1 INTERVAL=10s HOLD_S=300 MEM_LIMIT=1g \
  ALERTS_PER_INCIDENT=400 INCIDENT_EVENTS=10 VULN_EVENTS=1000 bin/run.sh
```

Key env: `STREAMS` (which streams the agent runs; default all three), `ALERT_EVENTS` /
`INCIDENT_EVENTS` / `VULN_EVENTS` (records per page, default = the shipped production page
sizes), `ALERTS_PER_INCIDENT`, `MEM_LIMIT`, `DRAIN=1` (drain through `fake-es.py`),
`INTERVAL` + `HOLD_S` (sustained mode), `GOMEMLIMIT` (soft heap ceiling; agentless sets
none), `STACK_VERSION` / `AGENT_IMAGE` (which build to profile), `KEEP=1` (leave containers
up), `TOOL` (corpus generator path). Sweeps add `AXIS`, `POINTS`, `SWEEP_CAP` and, for the
knob ladder, `KNOB_ROWS`.

Sustained mode needs `DRAIN=1`. With an unreachable output the queue fills, the input
blocks on publish and no second page is ever decoded — the opposite of a catching-up pod.

### Publishing a number

Every run appends a row to a CSV (`logs/runs.csv` for a bare run, one file per sweep
otherwise); the schema is documented at the top of `bin/lib.sh`. Nothing in this README or
in the ORR is typed in by hand — the tables and fits below sit between
`<!-- AUTOFILL:...:START -->` / `:END` markers and are rendered from `results/*.csv`.

The renderer, `harness_autofill.sh`, ships with the `agentless-orr` skill in
[elastic/sit-llm](https://github.com/elastic/sit-llm), under
`local/cursor/skills/agentless-orr/scripts/`, rather than living here, because every
package's ORR shares it. It is a standalone Python script with no dependencies beyond the
standard library, so a checkout of that repository is all it needs:

```
export ORR_RENDERER=/path/to/agentless-orr/scripts/harness_autofill.sh

# promote the sweep you want to publish, then re-render every document that quotes it
cp logs/sweep-alerts_per_incident-<ts>.csv results/alerts-per-incident.csv
# then: blank the run_log column (it names a file under logs/, which is not committed)
# and lead the file with a `#` comment saying when and how it was measured
HARNESS_DIR=$PWD $ORR_RENDERER \
  README.md ~/ingest-dev/docs/agentless-orr/reviews/m365_defender.md

# is anything stale? (no writes; non-zero exit if a block is out of date)
HARNESS_DIR=$PWD $ORR_RENDERER --check README.md
```

`bin/sweep.sh` reads the same `ORR_RENDERER` variable to print the fit at the end of a
sweep. Without it the sweep still writes its CSV, which is the part the documents are
rendered from; only the convenience fit on the terminal is skipped.

So a re-run cannot leave a document behind, and two documents cannot disagree about the
same measurement. The marker itself says which CSV and which view it wants, so the numbers
in a table, the fit derived from that table and the budget derived from that fit are always
the same measurement.

`results/` is committed for the same reason: a number whose provenance is a terminal that
has since been closed cannot be re-checked. Each file carries a header comment saying when
and how it was produced.

### Which agent version to profile

Serverless agentless runs **elastic-agent `main`**, shipped as the
`docker.elastic.co/observability-ci/ecp-elastic-agent-service:git-<sha>` image,
which rotates every ~1-2 days as `main` advances. The pod's `agent.version` metric
field is stale metadata (it can read e.g. `9.4.2` while the binary is a `main`
build). `main` currently declares **9.6.0**, so the default `STACK_VERSION` is
`9.6.0-SNAPSHOT` (the standard, publicly pullable proxy for the same code line) -
**not** a `cloud-release` GA tag like `9.4.x`, which is the stateful/ESH fleet, not
serverless agentless. For maximum fidelity, set
`AGENT_IMAGE=docker.elastic.co/observability-ci/ecp-elastic-agent-service:git-<sha>`
to the exact serverless build (requires registry access; re-pin as it rotates).
Record the exact build measured in the ORR, and lean on the memory *driver*
(`page_size x record_size x multiplier`) as the version-independent quantity.

## Output and analysis

`bin/run.sh` prints a `RESULT` block and appends the same numbers to the results CSV:

- `raw page bytes` — the served page size.
- `memory.peak` — cgroup high-water mark (a true maximum, not sampled; on an OOM run it is
  pinned at the cap and is *not* the true peak — use a bigger cap to measure it). It counts
  page cache as well as anonymous memory, so its production counterpart is the cgroup usage
  metric, **not** `kubernetes.container.memory.workingset.bytes`.
- `working set` — `memory.current - inactive_file`, the way kubelet computes it, read once
  when the run finishes. A closing snapshot, so on a sustained run it sits below the maximum.
- `working set peak` — the largest working set seen during the run, sampled every 3s
  (`docker stats` already does the `inactive_file` subtraction on cgroup v2). **This is the
  column to hold against the `workingset.bytes` telemetry the ORR quotes.** A spike shorter
  than the sampling interval can be missed, so treat it as a lower bound.
- `OOM killed` — whether the cgroup killed the beat at that cap.
- `page fetches` — should be `>= 1` per enabled stream, confirming the mock served the page.

`bin/sweep.sh` repeats that at several points and prints the table plus the fit. To
interpret:

- **`k`** is the memory multiplier per raw page byte; a high `k` reflects that the
  raw body, decoded objects, split events, and `event.original` copies coexist.
- **OOM boundary** = the raw page size where `base + k × page` reaches the cap.
  Convert to records by dividing by the per-record size the harness reports.
- For **incident**, `AXIS=alerts_per_incident` is the important one: nested `keep_parent`
  split can make memory grow super-linearly with alerts-per-incident, which is the real
  risk (a single incident with a large `alerts[]` array).
- Any run that OOM'd is excluded from the fit; if that happens, raise `SWEEP_CAP`.

## Result: per pod (all three agentless streams in one agent)

Measured with generated pages calibrated to a real response (see **Record shapes**), agent
`9.6.0-SNAPSHOT`, 2026-08-04. `working set` is the kubelet-comparable figure described
above, read at the end of the run. In a cold run memory climbs to a plateau and stays
there, so the closing snapshot is at the maximum; in a sustained run it is not, which is
why the sustained section below is careful about which metric it compares. Page cache was
negligible in most runs (≤7 MB), so peak ≈ anonymous memory.

**Cold, one page per stream, page sizes scaled together** (alerts-per-incident 100; the
bold row is the shipped configuration):

<!-- AUTOFILL:POD-SCALE:START csv=scale.csv view=table bold=1
     columns=point:scale|params.alert:alert|params.incident:incident|params.vulnerability:vuln|mb1(total_raw_bytes):raw pages|mb(workingset_bytes):working set -->
| scale | alert | incident | vuln | raw pages | working set |
| --- | --- | --- | --- | --- | --- |
| 0.25 | 250 | 12 | 2,500 | 10.2 MB | 214 MB |
| 0.5 | 500 | 25 | 5,000 | 20.8 MB | 286 MB |
| **1** | **1,000** | **50** | **10,000** | **41.6 MB** | **400 MB** |
| 2 | 2,000 | 100 | 20,000 | 83.1 MB | 720 MB |
| 3 | 3,000 | 150 | 30,000 | 124.9 MB | 938 MB |
| 4 | 4,000 | 200 | 40,000 | 166.5 MB | 1,175 MB |
| 5 | 5,000 | 250 | 50,000 | 208.0 MB | 1,529 MB |
<!-- AUTOFILL:POD-SCALE:END -->

<!-- AUTOFILL:POD-SCALE-FIT:START csv=scale.csv view=fit x=total_raw_bytes y=workingset_bytes -->
```
working_set ≈ 146 MB + 6.47 × raw_page_bytes        (R² = 0.996, 7 points)
```
<!-- AUTOFILL:POD-SCALE-FIT:END -->

Raw page budget per cap, shared across all three streams:
<!-- AUTOFILL:POD-BUDGET:START csv=scale.csv view=budget caps=512Mi,1Gi,2Gi,4Gi -->
**512Mi ≈ 57 MB** · **1Gi ≈ 136 MB** · **2Gi ≈ 294 MB** · **4Gi ≈ 610 MB**
<!-- AUTOFILL:POD-BUDGET:END -->

The intercept is the whole-container floor and matches the fleet-median steady state in the
ORR telemetry (~195 MB) once a small real page is added.

A cold single page is the noisiest measurement here: repeat runs at the shipped page sizes
landed between 368 and 448 MB (±10%), because where the plateau detector stops depends on
GC timing. The sustained numbers below are steadier and are what the sizing rests on.

Scales above 1 measure `k`; they are **not** tenants that can exist. `alert` cannot exceed
1,000 records (Graph clamps `$top`) and `vulnerability` is fixed at 10,000
(`pageSize` is hard-coded in the CEL program). Which leaves one uncapped input:

**Cold, alerts-per-incident swept with every page size at its shipped value:**

<!-- AUTOFILL:APC:START csv=alerts-per-incident.csv view=table
     columns=point:alerts/incident|mb1(total_raw_bytes):raw pages|mb(workingset_bytes):working set -->
| alerts/incident | raw pages | working set |
| --- | --- | --- |
| 25 | 21.0 MB | 329 MB |
| 50 | 27.8 MB | 360 MB |
| 100 | 41.6 MB | 368 MB |
| 200 | 69.0 MB | 505 MB |
| 400 | 123.8 MB | 780 MB |
<!-- AUTOFILL:APC:END -->

<!-- AUTOFILL:APC-FIT:START csv=alerts-per-incident.csv view=fit x=point y=workingset_bytes
     xlabel=alerts_per_incident -->
```
working_set ≈ 280 MB + 1.22 MB × alerts_per_incident        (R² = 0.983, 5 points)
```
<!-- AUTOFILL:APC-FIT:END -->

`alerts[]` on one incident costs ~1.2 MB of pod memory per alert, because `$expand=alerts`
plus the nested split with `keep_parent` turns each embedded alert into an event that also
carries its parent. Nothing in the package or the API bounds it.

### Reproducing the production peak

A cold page does not explain the telemetry: even 400 alerts per incident only reaches
780 MB, while production working set peaks at 1,377–1,507 MB and production cgroup usage
peaks at ~1,515 MB (p95) to ~1,578 MB (max). The missing factor is that production
pods fetch **back-to-back**, not once — `alert` polls every 5m and `incident` every 1m
against a 24h initial lookback, and the CEL stream re-enters immediately while
`want_more` is true against a 336h lookback. A page is decoded while the previous one is
still garbage the collector has not returned, and `GODEBUG=madvdontneed=1` keeps freed
pages charged to the cgroup. The ORR telemetry says so directly: the hottest pods are the
*backfilling* ones.

`DRAIN=1` plus a short `INTERVAL` reproduces it:

<!-- AUTOFILL:SUSTAINED:START csv=sustained.csv view=table
     columns=params.alerts_per_incident:alerts/incident|mb1(total_raw_bytes):raw pages|mb(peak_bytes):peak|mb(workingset_bytes):working set -->
| alerts/incident | raw pages | peak | working set |
| --- | --- | --- | --- |
| 100 | 41.6 MB | 690 MB | 543 MB |
| 400 | 123.8 MB | 1,516 MB | 1,132 MB |
<!-- AUTOFILL:SUSTAINED:END -->

Against the cold runs at the same page sizes (400 MB and 780 MB working set), sustained
fetching costs **~1.35–1.45× the cold single-page working set**, and its `memory.peak` is
~1.7–1.9× the cold peak.

The second row reaches the production peak, but the comparison has to be made metric for
metric. `memory.peak` is cgroup usage including page cache, so its counterpart is
production's cgroup usage peak (p95 ~1,515 MB, max ~1,578 MB) — 1,516 MB lands on the p95
and 4% under the max. It is **not** the counterpart of the 1,507 MB `workingset.bytes`
peak, and the two matching to within 0.6% is a coincidence of this dataset. The working-set
column in the table above is the closing snapshot (1,132 MB), and these runs predate the
`working set peak` column, so a like-for-like working-set comparison is not available from
them; re-running the sweep produces one.

Either way the conclusion is the same: production peaks are explained by shipped page sizes
+ a fat `alerts[]` array + back-to-back fetching, and no unaccounted mechanism is needed.

Interpolating the two sustained points:

<!-- AUTOFILL:SUSTAINED-FIT:START csv=sustained.csv view=fit x=point y=peak_bytes
     label=sustained_peak xlabel=alerts_per_incident -->
```
sustained_peak ≈ 415 MB + 2.75 MB × alerts_per_incident        (2 points - an interpolation, not a fit)
```
<!-- AUTOFILL:SUSTAINED-FIT:END -->

which puts the OOM boundary at roughly **220 alerts/incident for 1Gi** and **590 for 2Gi**.
Two points is a thin basis for a line — each sustained run costs ~8 minutes — so treat those
boundaries as the right order of magnitude rather than precise thresholds, and note that the
cold curve (`1.22 MB × alerts_per_incident`) is the better-conditioned fit if you need one.

### What each knob is worth

Every row is the same worst case tested above — shipped page sizes, 400 alerts per
incident, sustained with a draining output — changing one thing:

<!-- AUTOFILL:KNOBS:START csv=knobs.csv view=table
     columns=label:configuration|gi(mem_limit_bytes):cap|mb(peak_bytes):peak|mb(workingset_bytes):working set -->
| configuration | cap | peak | working set |
| --- | --- | --- | --- |
| baseline (nothing changed) | 3Gi | 1,516 MB | 1,132 MB |
| GOMEMLIMIT=850MiB (nothing else) | 1Gi | 1,024 MB | 917 MB |
| incident batch_size 50->10 + vulnerability pageSize 10000->1000 | 1Gi | 656 MB | 516 MB |
<!-- AUTOFILL:KNOBS:END -->

- **`GOMEMLIMIT`** is the only lever that needs no package change, and it does work on this
  peak — the pod survived 5 minutes of back-to-back fetching at 400 alerts per incident
  inside 1Gi, where the baseline needs 2Gi, and throughput was identical (both drained
  1,280,000 docs in 300 s). It works because the peak is *garbage*: a soft ceiling makes Go
  collect it sooner instead of letting the cgroup absorb it. But `memory.peak` pinned at
  exactly 1,024 MB, i.e. the run consumed the entire cgroup and stayed alive only because
  reclaim kept up. That is not a margin anyone should ship on. It is also no fix for a large
  *live* set: if one page's live data alone exceeded the ceiling, Go would GC continuously
  and the pod would degrade instead of recovering. Treat the mechanism as proven and the
  value as unset.
- **Bounding the page sizes** is the durable fix: 2.3× off the peak with 36% headroom left,
  and it removes the unbounded term rather than absorbing it. `incident.batch_size` is
  already a package variable (default 50); `vulnerability`'s `pageSize=10000` is hard-coded
  in the CEL program and would need a code change to expose.
- **`include_alerts=false`** is not in the table because it removes the driver outright
  (incident pages become ~0.05 MB) rather than scaling it. The alerts it drops are largely
  the same documents the `alert` data stream already collects, so it is worth considering
  on cost grounds independent of memory.
- **`preserve_original_event`** stays off in all of these; turning it on retains the raw
  JSON alongside the decoded event and would roughly double the per-event cost.

## Result: per stream (attribution, not sizing)

One stream enabled at a time, page size swept, output held, cap 6Gi. This establishes the
memory **driver** per stream, which is what the ORR asks for, and says which stream a pod
peak should be attributed to.

**These do not add up to a pod.** Each run pays the whole-container baseline once, so
summing the three bases triple-counts it; the per-pod numbers above are the sizing basis.

<!-- AUTOFILL:PER-STREAM:START csv=per-stream.csv view=fits group=streams
     x=total_raw_bytes y=peak_bytes caps=1Gi,512Mi header=stream -->
| stream | fit (base + k·page) | 1Gi boundary | 512Mi boundary |
| --- | --- | --- | --- |
| `alert` | ≈126 MB + 11.43·page | ~79 MB / ~14,343 recs | ~34 MB / ~6,170 recs |
| `incident` | ≈170 MB + 7.27·page | ~117 MB / ~213 recs | ~47 MB / ~85 recs |
| `vulnerability` | ≈146 MB + 10.14·page | ~87 MB / ~100,489 recs | ~36 MB / ~41,884 recs |
<!-- AUTOFILL:PER-STREAM:END -->

`incident` counts are incidents **at 100 alerts each** (~576 KB per incident). These are
`memory.peak` (page cache included) rather than working set, because this sweep predates
the working-set accounting; `alert` and `incident` were re-measured after the record-shape
calibration, `vulnerability` was not because its template did not change.

**Agent build measured:** `9.6.0-SNAPSHOT` — record the exact serverless build the numbers
came from, since serverless agentless tracks `main` (a moving target). Capture all three:
version string (`docker exec m365-agent elastic-agent version --binary-only`), image or
commit (the `RESULT` block prints `agent image`), and the date, because the serverless image
rotates every ~1-2 days. These runs: `docker.elastic.co/elastic-agent/elastic-agent:9.6.0-SNAPSHOT`,
2026-08-03/04.

## Notes / deviations from a live agentless pod

- By default the output points at an unreachable Elasticsearch: events are held (not
  drained), so the decoded page stays resident (conservative worst case) and drained
  events do not add page cache to the cgroup. This measures memory *capacity*
  (records per page at the OOM ceiling), **not** throughput / EPS. `DRAIN=1` replaces it
  with a local sink, which is what sustained mode needs — with an unreachable output the
  queue fills, the input blocks on publish and only one page is ever decoded.
- The sink drains as fast as the agent can push. Agentless applies a ratelimit processor
  (rate 300, burst 3000, `throttle_behavior: delay`) on the export path, and that
  backpressure keeps events resident for longer, so the sustained numbers here are if
  anything an underestimate of a rate-limited pod. `fake-es.py --max-eps` exists to model
  that and was not used for the recorded results.
- The working-set peak is sampled every 3s, so a spike shorter than that can be missed;
  it is a lower bound. `memory.peak` is a true kernel high-water mark and is not sampled,
  but it counts page cache, so it is an upper bound on the same quantity. The two are
  reported side by side and the recorded peaks are the cgroup ones, which is the
  conservative choice for sizing but is not the metric kubelet reports.
- httpjson `batch_size` is neutralised to a huge sentinel (in the spliced block) to
  force a single page; production defaults differ (`alert` ships `batch_size=1000` =
  the Graph `$top` cap since 5.15.1, `incident` ships `batch_size=50`). The harness
  measures the *decode* cost of whatever page it is handed, independent of how
  production paginates; the spliced pagination is the real 5.15.1 time-boundary shape
  (`$filter … gt`, `$skip=0`), just held to one page.
- State store is local disk here (agentless uses Elasticsearch); the cursor is a few
  KB and irrelevant to the decode peak.
- APM is off.
- `alert` and `incident` pages are calibrated against a real response; `vulnerability` is
  not (no response was available). Its 10,000-record page contributes only ~8 MB of the
  123 MB worst case, so a wrong per-record size there moves the total little — but it is
  the one input whose realism is unverified.
- Records within a page are uniform rather than spread across a size distribution. The page
  totals match, which is what the decode peak depends on.
- Agentless sets no `GOMEMLIMIT`; runs that pass one are exploring a mitigation, not
  measuring the shipped configuration.
- If the cel input ever adopts the CEL `emit` macro / streaming decode
  (elastic/beats#51279), the vulnerability memory profile changes fundamentally and
  this harness plus the ORR numbers must be re-run. `emit` is tracked separately and
  is not available for integrations yet.
