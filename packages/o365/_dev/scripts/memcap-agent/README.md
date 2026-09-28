# o365 agentless worst-case memory harness

Synthetic single-blob memory test for the o365 `audit` CEL input, built for the
agentless Operational Readiness Review (ORR). It answers "how much memory does one
large Office 365 content blob cost, and where does it OOM at the agentless pod
limit?".

This is a bespoke Docker + cgroup harness, **not** an `elastic-package` benchmark.
It runs the real `elastic-agent` image the way `agentless-controller` deploys it
against the `elastic/stream` mock serving one big content blob, under a Docker
`--memory` cap, and reads the cgroup `memory.peak` high-water mark.

## Layout

- `elastic-agent.yml.tmpl` — standalone Elastic Agent config template, tuned for a
  single-blob worst case. Its `program:` block is a `#__CEL_PROGRAM__` placeholder that
  `run.sh` fills in from the shipping data stream at run time (see [Keep the CEL program
  in sync](#keep-the-cel-program-in-sync-with-the-shipping-input)), writing the runnable
  config to `work/elastic-agent.yml`.
- `run.sh` — one run: generate corpus → start mock → run capped agent → report
  `memory.peak` / OOM. Sweep with `TOTAL_EVENTS` and `MEM_LIMIT`.
- `sweep.sh` — several blob sizes at a big cap, fits `memory.peak = base + k·blob`,
  and derives the OOM boundary for 1Gi / 512Mi.
- `corpus/` — generator inputs for the worst-case blob (`template.ndjson`,
  `config.yml`, `fields.yml`).
- `mock-config.yml` — elastic/stream mock config (OAuth token, subscriptions,
  content listing/fetch serving the generated blob).

This harness is self-contained: everything it needs lives in this folder (plus the
external corpus-generator binary and Docker). It does not depend on the o365
`_dev/benchmark/` tree.

### Keep the CEL program in sync with the shipping input

The memory numbers are only meaningful if the harness runs the exact CEL program o365
ships, so the program is **not** stored in this folder. On every run, `run.sh` extracts
the `program:` block verbatim from `../../../data_stream/audit/agent/stream/cel.yml.hbs`
(that block is pure CEL, no Handlebars), re-indents it, and splices it into
`elastic-agent.yml.tmpl` in place of the `#__CEL_PROGRAM__` placeholder, writing the
result to `work/elastic-agent.yml`. There is nothing to copy or verify by hand: change
`cel.yml.hbs` and the next run picks it up. Only the surrounding config lives in the
template (the harness tunes `state.base` for a single-blob worst case and points at the
mock).

Note: if `cel.yml.hbs` ever adopts the CEL `emit` macro / streaming decode
(elastic/beats#51279), the memory profile changes fundamentally and this harness plus
the ORR numbers must be re-run.

`run.sh` and `sweep.sh` write runtime artifacts (`work/`, `logs/`) into this folder.
These are scratch — do not commit them (avoid a blind `git add -A` here, as `work/`
can hold a multi-hundred-MB corpus). Re-run the harness to reproduce them (see
[Output and analysis](#output-and-analysis) below).

## Prerequisites

- Docker running (pulls `elastic-agent`, `observability/stream`, `curlimages/curl`).
- The corpus generator built once:
  ```
  cd elastic-integration-corpus-generator-tool && go build -o eicgt .
  ```
  Point `TOOL=` at that repo if it is not at the default path in `run.sh`.

## Usage

```
# one run at the enforced pod limit
MEM_LIMIT=1g TOTAL_EVENTS=100000 ./run.sh

# fit the multiplier + derive the OOM boundary (recommended)
SWEEP_CAP=6g SWEEP_EVENTS="2000 5000 10000 20000" ./sweep.sh
```

Key env: `STACK_VERSION` (match the shipped agent, default 9.4.2), `MEM_LIMIT`,
`TOTAL_EVENTS`, `SWEEP_CAP`, `SWEEP_EVENTS`, `KEEP=1` (leave containers up), `TOOL`.

## Output and analysis

`run.sh` prints a `RESULT` block to stdout with the numbers that matter:

- `raw blob bytes` — the single content blob's size.
- `memory.peak` — cgroup high-water mark (the authoritative figure; on an OOM run it
  is pinned at the cap and is *not* the true peak — use a bigger cap to measure it).
- `OOM killed` — whether the cgroup killed the beat at that cap.
- `content fetches` — should be `>= 1`, confirming the mock served the blob.

`sweep.sh` runs several blob sizes at a non-OOM cap and writes, under `logs/`:

- `sweep-<ts>.log` — full console output of the whole sweep (every run + the summary).
- `sweep-<ts>.csv` — one row per run: `events,raw_blob_bytes,memory_peak_bytes,oom`.
- `run-<ts>-<N>.log` — the individual `run.sh` output for each event count `N`.

The summary at the end of `sweep-<ts>.log` is what you read: it fits
`memory.peak ≈ base + k × raw_blob` over the non-OOM points and prints the derived
largest raw blob that fits at 1Gi and 512Mi. To interpret:

- **`k`** is the memory multiplier per raw blob byte; a high `k` reflects that the raw
  body, decoded CEL objects, and mapped events coexist in one evaluation.
- **OOM boundary** = the raw blob size where `base + k × blob` reaches the cap. Convert
  to events by dividing by the event size (e.g. ~10 KB worst-case, ~3 KB average).
- Any run that itself OOM'd is excluded from the fit (its `memory.peak` is just the
  cap); if that happens, raise `SWEEP_CAP` and re-run.

Copy the summary numbers into the ORR load-test section; the raw `logs/` are scratch
and should not be committed.

## Result (recorded for the ORR)

Fit `memory.peak ≈ 204 MB baseline + ~12.1 × raw blob size` (elastic-agent 9.4.2).
Single-blob OOM boundary: **~68 MB raw blob @ 1Gi**, **~25 MB @ 512Mi**. Expressed as
**events per blob** (a memory *capacity* at the ceiling, not a throughput rate):
~6,900 worst-case (10 KB) / ~23,000 average (3 KB) events per blob at 1Gi. The peak is
high because the raw body, the decoded CEL objects, and the mapped events all coexist
in one evaluation — see the ORR memory profile / load-test sections for full context
and caveats.

## Notes / deviations from a live agentless pod

- Output points at an unreachable Elasticsearch on purpose: events are held (not
  drained), so the decoded blob stays resident (conservative worst case) and drained
  events do not add page cache to the cgroup. As a result this harness measures memory
  *capacity* (events per blob at the OOM ceiling), **not throughput / EPS**. EPS is a
  delivered-events-per-second rate under sustained load and needs a real ES output.
- CEL state store is local disk here (agentless uses Elasticsearch); the cursor is a
  few KB and irrelevant to the decode peak.
- APM is off.
