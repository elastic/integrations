# m365_defender agentless worst-case memory harness

Synthetic single-page memory test for the three agentless m365_defender inputs,
built for the agentless Operational Readiness Review (ORR). It answers "how much
memory does one worst-case API page cost per stream, and where does it OOM at the
agentless pod limit?".

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

## Layout

```
memcap-agent/
├── run.sh                    # one run for STREAM={alert,incident,vulnerability}
├── sweep.sh                  # several page sizes at a big cap; fits + OOM boundary
├── alert/
│   ├── elastic-agent.yml     # rendered copy of the shipping httpjson.yml.hbs
│   ├── mock-config.yml       # token + alerts_v2 page serving the corpus
│   └── corpus/               # template.ndjson, config.yml, fields.yml
├── incident/
│   ├── elastic-agent.yml     # rendered copy (include_alerts=true, nested split)
│   ├── mock-config.yml       # token + incidents page (each incident has alerts[])
│   └── corpus/
└── vulnerability/
    ├── elastic-agent.yml.tmpl # CEL program spliced from cel.yml.hbs at run time
    ├── mock-config.yml        # token + vuln page (no @odata.nextLink = one page)
    └── corpus/
```

Each run writes scratch (`<stream>/work/`) and the sweep writes `logs/`. Do **not**
commit those (avoid a blind `git add -A` here — `work/` can hold a multi-hundred-MB
corpus). Re-run the harness to reproduce them.

## Keeping the configs in sync with the shipping inputs

The numbers are only meaningful if the harness runs what the package ships.

- **vulnerability (cel):** the CEL program is **not** stored here. On every run,
  `run.sh` extracts the `program:` block verbatim from
  `../../../data_stream/vulnerability/agent/stream/cel.yml.hbs`, re-indents it, and
  splices it into `vulnerability/elastic-agent.yml.tmpl` in place of the
  `#__CEL_PROGRAM__` placeholder. Change the `.hbs` and the next run picks it up.
- **alert / incident (httpjson):** httpjson stream templates are Handlebars, not
  cleanly extractable, so `alert/elastic-agent.yml` and `incident/elastic-agent.yml`
  are **hand-maintained rendered copies** of the shipping `httpjson.yml.hbs`. If you
  change `request.transforms`, `response.split`, or `tags` in the `.hbs`, re-sync
  these two files. The memory-relevant parts to keep faithful are `response.split`
  (and the nested `body.alerts` split with `keep_parent` for incidents) and the
  `preserve_original_event` tag.

Both httpjson configs set `$top`/`batch_size` absurdly large so the single page the
mock returns is smaller than `batch_size`: httpjson does not request a second page,
and the whole page is decoded and held in memory. That isolates the **per-page**
peak, which is what OOMs an agentless pod (see the pagination discussion in the ORR
and elastic/integrations#20234).

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

## Result (recorded for the ORR)

_TODO: fill in after the first full sweep._

**Agent build measured:** _TODO_ — record the exact serverless build the numbers
came from, since serverless agentless tracks `main` (a moving target). Capture all
three:
- version string: _TODO_ (e.g. `9.6.0-SNAPSHOT`; from
  `docker exec m365-agent elastic-agent version --binary-only`)
- image / commit: _TODO_ (e.g. `ecp-elastic-agent-service:git-893784d73b64`, i.e.
  elastic-agent commit `893784d`; the `run.sh` RESULT block prints `agent image`)
- date measured: _TODO_ (the serverless image rotates every ~1-2 days)

| stream          | fit (base + k·page)      | 1Gi boundary | 512Mi boundary |
| --------------- | ------------------------ | ------------ | -------------- |
| `alert`         | _TODO_                   | _TODO_       | _TODO_         |
| `incident`      | _TODO_                   | _TODO_       | _TODO_         |
| `vulnerability` | _TODO_                   | _TODO_       | _TODO_         |

## Notes / deviations from a live agentless pod

- Output points at an unreachable Elasticsearch on purpose: events are held (not
  drained), so the decoded page stays resident (conservative worst case) and drained
  events do not add page cache to the cgroup. This measures memory *capacity*
  (records per page at the OOM ceiling), **not** throughput / EPS.
- httpjson `batch_size` is set huge to force a single page; production caps differ
  (`alert` `$top` is server-clamped to 1000, `incident` ships `batch_size=50`). The
  harness measures the *decode* cost of whatever page it is handed, independent of
  how production paginates.
- State store is local disk here (agentless uses Elasticsearch); the cursor is a few
  KB and irrelevant to the decode peak.
- APM is off.
- If the cel input ever adopts the CEL `emit` macro / streaming decode
  (elastic/beats#51279), the vulnerability memory profile changes fundamentally and
  this harness plus the ORR numbers must be re-run. `emit` is tracked separately and
  is not available for integrations yet.
