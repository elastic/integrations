# m365_defender agentless worst-case memory harness

Memory test for the three agentless m365_defender inputs, built for the agentless
Operational Readiness Review (ORR). It answers two questions:

- **per stream** (`run.sh`, `sweep.sh`) — how much memory does one worst-case API
  page cost, and where does that stream OOM at the pod limit?
- **per pod** (`run-concurrent.sh`, `sweep-concurrent.sh`) — what does the whole
  agentless deployment need, running all three streams in one agent the way a pod
  actually does?

The per-pod runs are the ones an agentless memory request should be derived from.
Summing the per-stream numbers is wrong in both directions: every input shares one
beat process, so the per-process baseline is paid once rather than three times, but
the decode peaks land on one heap with one GC cycle and one shared publisher queue.
Only a combined run measures the real number, and only a *sustained* combined run
reproduces the production working-set peaks (see
[Reproducing the production peak](#reproducing-the-production-peak)).

This is a bespoke Docker + cgroup harness, **not** an `elastic-package` benchmark.
It runs the real `elastic-agent` image the way `agentless-controller` deploys it
against the `elastic/stream` mock serving one big API page, under a Docker
`--memory` cap, and reads the cgroup `memory.peak` high-water mark.

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
├── run.sh                    # one run for STREAM={alert,incident,vulnerability}
├── sweep.sh                  # several page sizes at a big cap; fits + OOM boundary
├── run-concurrent.sh         # all three streams in ONE agent (what a pod runs)
├── sweep-concurrent.sh       # fits the pod-level curve: page scale, or alerts-per-incident
├── lib.sh                    # shared corpus build, config splice, memory accounting
├── fake-es.py                # draining sink, optionally rate-limited (sustained mode)
├── alert/
│   ├── elastic-agent.yml.tmpl # request/pagination/split/cursor spliced from httpjson.yml.hbs
│   ├── mock-config.yml        # token + alerts_v2 page serving the corpus
│   └── corpus/                # template.ndjson, config.yml, fields.yml
├── incident/
│   ├── elastic-agent.yml.tmpl # spliced from httpjson.yml.hbs (include_alerts=true, nested split)
│   ├── mock-config.yml        # token + incidents page (each incident has alerts[])
│   └── corpus/
└── vulnerability/
    ├── elastic-agent.yml.tmpl # CEL program spliced from cel.yml.hbs at run time
    ├── mock-config.yml        # token + vuln page (no @odata.nextLink = one page)
    └── corpus/
```

Each run writes scratch (`<stream>/work/`, `work-all/`) and the sweeps write `logs/`.
None of that is committed — see `.gitignore`; `work/` alone can hold a multi-hundred-MB
corpus. Re-run the harness to reproduce them.

A run needs nothing but this directory, Docker and the corpus generator: no tenant
access, no sample file, no network beyond the image pulls.

## Record shapes

Go's JSON decode cost tracks the **number of keys and containers** it allocates, not just
the byte count, so a template that hits the right size with the wrong shape gets the
memory wrong. Measured here: holding page bytes constant and changing only the evidence
array from 6 items to the real average of 3.5 moved the sustained peak by 4%, and an
earlier template with 6 items over-stated it by 9%.

So the templates in `<stream>/corpus/` are calibrated against a real tenant response on
four axes at once. The flow was one-way and ended outside the repo: the response was
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

- **vulnerability (cel):** `run.sh` extracts the `program:` block verbatim from
  `../../../data_stream/vulnerability/agent/stream/cel.yml.hbs`, re-indents it, and
  splices it into `vulnerability/elastic-agent.yml.tmpl` in place of the
  `#__CEL_PROGRAM__` placeholder.
- **alert / incident (httpjson):** `run.sh` extracts the ship **behaviour block** —
  `request.transforms` + `response.pagination` + `response.split` + `cursor` — from
  `../../../data_stream/<stream>/agent/stream/httpjson.yml.hbs`, resolves the few
  Handlebars tokens the harness needs (`batch_size`, `initial_interval`, and the
  `include_*` conditionals — keeping the `include_alerts` bodies so `$expand=alerts`
  and the nested `body.alerts` split with `keep_parent` are exercised for incidents),
  re-indents it, and splices it into `<stream>/elastic-agent.yml.tmpl` in place of the
  `#__STREAM_BEHAVIOR__` placeholder. Only connection/scaffolding (auth + URL → mock,
  `interval`, output, `tags`) lives in the `.tmpl`, because those are harness
  environment values, not ship logic.

Both runners share one implementation of this (`harness_render_config` in `lib.sh`), so
the per-stream and per-pod numbers are produced from the same splice.

**Drift guard:** the splice only understands the tokens listed above. If a `.hbs`
grows a new `{{...}}` token in the spliced region (a new `{{#if}}`, a new variable),
the run aborts with the offending line instead of silently mis-rendering — so
staleness becomes a one-line fix in `harness_render_config`, not a wrong ORR number.
`run-concurrent.sh` also asserts that the merge produced one input per stream and that
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

### Per pod (all three streams in one agent)

```
# cold: one page per stream at the shipped production page sizes
./run-concurrent.sh

# sustained: inputs keep fetching and the output drains - compare with production telemetry
DRAIN=1 INTERVAL=10s HOLD_S=300 MEM_LIMIT=3g ./run-concurrent.sh

# fit the pod curve two ways
SWEEP_CAP=3g SCALES="0.25 0.5 1 2 3 4 5" ./sweep-concurrent.sh
SWEEP_CAP=3g SWEEP_APC="25 50 100 200 400" ./sweep-concurrent.sh

# does a candidate configuration survive a smaller cap?
DRAIN=1 INTERVAL=10s HOLD_S=300 MEM_LIMIT=1g \
  ALERTS_PER_INCIDENT=400 INCIDENT_EVENTS=10 VULN_EVENTS=1000 ./run-concurrent.sh
```

Key env: `ALERT_EVENTS` / `INCIDENT_EVENTS` / `VULN_EVENTS` (records per page, default =
the shipped production page sizes), `ALERTS_PER_INCIDENT`, `MEM_LIMIT`,
`DRAIN=1` (drain through `fake-es.py`), `INTERVAL` + `HOLD_S` (sustained mode),
`GOMEMLIMIT` (soft heap ceiling; agentless sets none), `STREAMS` (subset to run).

Sustained mode needs `DRAIN=1`. With an unreachable output the queue fills, the input
blocks on publish and no second page is ever decoded — the opposite of a catching-up pod.

### Per stream

```
# one run at the enforced pod limit
STREAM=alert         MEM_LIMIT=1g   TOTAL_EVENTS=1000  ./run.sh
STREAM=incident      MEM_LIMIT=1g   TOTAL_EVENTS=50 ALERTS_PER_INCIDENT=100 ./run.sh
STREAM=vulnerability MEM_LIMIT=512m TOTAL_EVENTS=10000 ./run.sh

# fit the multiplier + derive the OOM boundary (recommended)
STREAM=alert    SWEEP_CAP=6g SWEEP_EVENTS="250 500 1000 2000" ./sweep.sh
STREAM=incident SWEEP_CAP=6g SWEEP_EVENTS="10 25 50 100" ALERTS_PER_INCIDENT=100 ./sweep.sh
STREAM=vulnerability SWEEP_CAP=6g SWEEP_EVENTS="2500 5000 10000 20000" ./sweep.sh

# one-shot: sweep all three streams, fill the Result table below + emit an ORR snippet
./autofill.sh
SKIP_SWEEP=1 ./autofill.sh                                  # reuse existing logs/*.csv, just refill
ORR_DOC=/path/to/ingest-dev/docs/agentless-orr/reviews/m365_defender.md ./autofill.sh   # also inject into the ORR
```

`autofill.sh` runs `sweep.sh` for each stream, recomputes the fit + 1Gi/512Mi
boundaries from `logs/*.csv`, writes them into the **Result** table and the **Agent
build measured** provenance below, and writes a paste-ready block to
`logs/orr-snippet-*.md`. If `ORR_DOC` is set and the target contains
`<!-- AUTOFILL:START -->` / `<!-- AUTOFILL:END -->` markers, it injects the block
between them (otherwise it only writes the snippet). Same host caveats as the sweep
(Docker cgroup ≥ `SWEEP_CAP`, image pull, corpus tool, ~tens of minutes).

Key env: `STREAM` (required), `STACK_VERSION` (default `9.6.0-SNAPSHOT`),
`AGENT_IMAGE` (override to pin an exact serverless build), `MEM_LIMIT`,
`TOTAL_EVENTS` (records per page), `ALERTS_PER_INCIDENT` (incident only),
`SWEEP_CAP`, `SWEEP_EVENTS`, `KEEP=1` (leave containers up), `TOOL`.

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

`run.sh` prints a `RESULT` block:

- `raw page bytes` — the served page size.
- `memory.peak` — cgroup high-water mark (authoritative; on an OOM run it is pinned
  at the cap and is *not* the true peak — use a bigger cap to measure it).
- `OOM killed` — whether the cgroup killed the beat at that cap.
- `page fetches` — should be `>= 1`, confirming the mock served the page.

`sweep.sh` runs several page sizes at a non-OOM cap and writes, under `logs/`:

- `sweep-<stream>-<ts>.log` — full console output (every run + the summary).
- `sweep-<stream>-<ts>.csv` — `records,raw_page_bytes,memory_peak_bytes,oom`.
- `run-<stream>-<ts>-<N>.log` — the individual `run.sh` output for each count `N`.

The summary fits `memory.peak ≈ base + k × raw_page` over the non-OOM points and
prints the derived largest raw page that fits at 1Gi and 512Mi. To interpret:

- **`k`** is the memory multiplier per raw page byte; a high `k` reflects that the
  raw body, decoded objects, split events, and `event.original` copies coexist.
- **OOM boundary** = the raw page size where `base + k × page` reaches the cap.
  Convert to records by dividing by the per-record size the harness reports.
- For **incident**, sweep `ALERTS_PER_INCIDENT` too: nested `keep_parent` split can
  make memory grow super-linearly with alerts-per-incident, which is the real risk
  (a single incident with a large `alerts[]` array).
- Any run that OOM'd is excluded from the fit; if that happens, raise `SWEEP_CAP`.

Copy the summary numbers into the ORR load-test / memory-profile sections; the raw
`logs/` are scratch and should not be committed.

## Result: per pod (all three agentless streams in one agent)

Measured with generated pages calibrated to a real response (see **Record shapes**), agent
`9.6.0-SNAPSHOT`, 2026-08-04. `ws` is the working-set figure computed the way kubelet
computes it (`memory.current - inactive_file`), so it is directly comparable with the
`kubernetes.container.memory.workingset.bytes` telemetry in the ORR. Page cache was
negligible in most runs (≤7 MB), so peak ≈ anonymous memory; where it was not, both are
reported.

**Cold, one page per stream, page sizes scaled together** (alerts-per-incident 100):

| scale | alert | incident | vuln | raw pages | working set |
| --- | --- | --- | --- | --- | --- |
| 0.25 | 250 | 12 | 2,500 | 10.2 MB | 214 MB |
| 0.5 | 500 | 25 | 5,000 | 20.8 MB | 286 MB |
| **1 (shipped)** | **1,000** | **50** | **10,000** | **41.6 MB** | **400 MB** |
| 2 | 2,000 | 100 | 20,000 | 83.1 MB | 720 MB |
| 3 | 3,000 | 150 | 30,000 | 124.9 MB | 938 MB |
| 4 | 4,000 | 200 | 40,000 | 166.5 MB | 1,175 MB |
| 5 | 5,000 | 250 | 50,000 | 208.0 MB | 1,529 MB |

```
working_set ≈ 147 MB + 6.47 × raw_page_bytes        (R² = 0.996, 7 points)
```

Raw page budget per cap: **512Mi ≈ 56 MB · 1Gi ≈ 136 MB · 2Gi ≈ 294 MB · 4Gi ≈ 610 MB**,
shared across all three streams. The 147 MB intercept is the whole-container floor and
matches the fleet-median steady state in the ORR telemetry (~195 MB) once a small real
page is added.

A cold single page is the noisiest measurement here: repeat runs at the shipped page sizes
landed between 368 and 448 MB (±10%), because where the plateau detector stops depends on
GC timing. The sustained numbers below are steadier and are what the sizing rests on.

Scales above 1 measure `k`; they are **not** tenants that can exist. `alert` cannot exceed
1,000 records (Graph clamps `$top`) and `vulnerability` is fixed at 10,000
(`pageSize` is hard-coded in the CEL program). Which leaves one uncapped input:

**Cold, alerts-per-incident swept with every page size at its shipped value:**

| alerts/incident | raw pages | working set |
| --- | --- | --- |
| 25 | 21.0 MB | 329 MB |
| 50 | 27.8 MB | 360 MB |
| 100 | 41.6 MB | 368 MB |
| 200 | 69.0 MB | 505 MB |
| 400 | 123.8 MB | 780 MB |

```
working_set ≈ 280 MB + 1.22 MB × alerts_per_incident   (R² = 0.983, shipped page sizes)
```

`alerts[]` on one incident costs ~1.2 MB of pod memory per alert, because `$expand=alerts`
plus the nested split with `keep_parent` turns each embedded alert into an event that also
carries its parent. Nothing in the package or the API bounds it.

### Reproducing the production peak

A cold page does not explain the telemetry: even 400 alerts per incident only reaches
780 MB, while production peaks at 1,377–1,507 MB. The missing factor is that production
pods fetch **back-to-back**, not once — `alert` polls every 5m and `incident` every 1m
against a 24h initial lookback, and the CEL stream re-enters immediately while
`want_more` is true against a 336h lookback. A page is decoded while the previous one is
still garbage the collector has not returned, and `GODEBUG=madvdontneed=1` keeps freed
pages charged to the cgroup. The ORR telemetry says so directly: the hottest pods are the
*backfilling* ones.

`DRAIN=1` plus a short `INTERVAL` reproduces it:

| configuration | raw pages | cold | sustained peak | sustained steady |
| --- | --- | --- | --- | --- |
| shipped pages, 100 alerts/incident | 41.6 MB | 400 MB | **690 MB** | 543 MB |
| shipped pages, 400 alerts/incident | 123.8 MB | 780 MB | **1,516 MB** | 1,132 MB |

Sustained fetching costs **~1.7–1.9× the cold single-page peak** (1.73× and 1.94×
measured). The second row lands within **0.6%** of the worst working set ever observed in
production (1,507 MB), so the production peaks are fully explained by shipped page sizes +
a fat `alerts[]` array + back-to-back fetching. No unaccounted mechanism is needed.

Interpolating the two sustained points:

```
sustained_peak ≈ 415 MB + 2.75 MB × alerts_per_incident
```

which puts the OOM boundary at roughly **220 alerts/incident for 1Gi** and **590 for 2Gi**.
Two points is a thin basis for a line — each sustained run costs ~8 minutes — so treat those
boundaries as the right order of magnitude rather than precise thresholds, and note that the
cold curve (`1.22 MB × alerts_per_incident`) is the better-conditioned fit if you need one.

### What each knob is worth

Every row is the same worst case tested above — shipped page sizes, 400 alerts per
incident, sustained with a draining output — changing one thing:

| configuration | cap | peak | working set | outcome |
| --- | --- | --- | --- | --- |
| baseline (nothing changed) | 3Gi | 1,516 MB | 1,132 MB | needs 2Gi |
| `GOMEMLIMIT=850MiB`, nothing else | **1Gi** | 1,024 MB = the cap | 917 MB | survived 5 min, but **no headroom** |
| `incident` batch_size 50→10 + `vulnerability` pageSize 10000→1000 | **1Gi** | **656 MB** | 516 MB | no OOM, 36% headroom |

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

## Result: per stream (single page, one stream at a time)

**Agent build measured:** 9.6.0-SNAPSHOT — record the exact serverless build the numbers
came from, since serverless agentless tracks `main` (a moving target). Capture all
three:
- version string: `9.6.0-SNAPSHOT` (e.g. `9.6.0-SNAPSHOT`; from
  `docker exec m365-agent elastic-agent version --binary-only`)
- image / commit: `docker.elastic.co/elastic-agent/elastic-agent:9.6.0-SNAPSHOT` (e.g. `ecp-elastic-agent-service:git-893784d73b64`, i.e.
  elastic-agent commit `893784d`; the `run.sh` RESULT block prints `agent image`)
- date measured: 2026-08-03 (the serverless image rotates every ~1-2 days)

| stream          | fit (base + k·page)      | 1Gi boundary | 512Mi boundary |
| --------------- | ------------------------ | ------------ | -------------- |
| `alert`        | ≈126 MB + 11.43·page     | ~79 MB / ~14,400 recs | ~34 MB / ~6,200 recs |
| `incident`     | ≈170 MB + 7.27·page      | ~118 MB / ~210 incidents | ~47 MB / ~85 incidents |
| `vulnerability`| ≈146 MB + 10.14·page     | ~87 MB / ~100,489 recs | ~36 MB / ~41,884 recs |

`incident` counts are incidents **at 100 alerts each** (~576 KB per incident). `vulnerability`
was not re-measured after the record-shape calibration because its template did not change.
These are `memory.peak` (page cache included) with the output held, so they are not additive —
the per-pod numbers above supersede them for sizing.

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
- Sustained runs report the working set at a 3s sampling interval, so a peak shorter than
  3s can be missed. `memory.peak` is a true kernel high-water mark and is not sampled, so
  the two are reported side by side; the recorded peaks are the cgroup ones.
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
