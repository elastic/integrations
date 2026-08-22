# Package capability — detection and evidence tiers

Use this checklist **before Pass 2–4** (and document in Pass 1) so sub-agents do not treat dashboards-only integrations like agent-backed packages.

## How to detect package type

Run this check under `packages/{integration}/`:

| Signal | Agent-backed | Assets-only (dashboards / content) |
| --- | --- | --- |
| `manifest.yml` has `policy_templates:` | yes | **no** |
| `data_stream/` directory exists | yes | **no** |
| `data_stream/*/sample_event.json` | usually yes | **no** |
| `data_stream/*/_dev/test/pipeline/*-expected.json` | usually yes | **no** |
| `kibana/dashboard/` or `kibana/search/` only | optional | **yes** (primary deliverable) |
| Collection described in README | Elastic Agent / API / syslog | External export (Corelight → ES, OTel collector, etc.) |

**Assets-only examples in this repo:** `corelight`, `aws_vpcflow_otel`, `aws_cloudtrail_otel` (and similar content integrations).

**Assets-with-sibling:** dashboards-only package whose README explicitly references another package for ingest semantics (e.g. classic `packages/aws/data_stream/vpcflow/` for `aws_vpcflow_otel`). Sibling package paths may be read for field layout only — never sibling domain docs.

## Evidence tiers (use in Pass 2–4)

| Tier | Source | What you may claim |
| --- | --- | --- |
| **A — Package fixture** | `sample_event.json`, `*-expected.json`, ingest pipeline in package | Field populated, mapping correct, Pass 3 example values (id, ip, email, …) |
| **B — Dashboard / search asset** | `kibana/dashboard/*.json`, `kibana/search/*.json`, `_dev/shared/kibana/*.yaml` | Field **names** and filter **literals** used in ES\|QL; aggregate patterns — **not** a single indexed document |
| **C — External** | Vendor GitHub templates, product docs, web | Schema intent only; mark **unverifiable in repo** |

**Never label Tier B or C sources as `Fixture:`** in Pass 3. Use **`Evidence:`** with path and tier.

## Pass-specific rules

| Pass | Agent-backed | Assets-only |
| --- | --- | --- |
| **1** | List data streams from manifest | State **Package type: assets-only**; list dashboards / expected index patterns (`logs-corelight-*`, `aws.vpcflow.otel`, …); no Agent data streams |
| **2** | Fixture + pipeline evidence | Tier B/C only; `Mapping correct?` often **unverifiable**; no fixture proof claims |
| **3** | 1–3 fixture-grounded examples | **Illustrative patterns only** (see `event-graph-example.md`) — no fabricated entity values |
| **4** | `data_stream.dataset` router from manifest | Router on `event.dataset` / index pattern per dashboard ES\|QL; note fields not verified by package fixtures |

## Anti-patterns (assets-only)

- Calling a dashboard JSON file a **fixture** or **sample event**
- Filling Actor/Target tables with **invented** id, name, ip, geo when dashboards only show field names
- Claiming **`data_stream.dataset`** values from this integration's manifest when the package defines none
- Building Pass 3 examples that read like **one real audit event** when only filter literals exist in dashboards
- Pass 4 `CASE` branches presented as package-verified when only dashboard ES\|QL references exist
