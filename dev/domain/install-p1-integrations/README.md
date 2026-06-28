# P1 integration install & fixture ingest

Install all 47 [P1 domain integrations](../p1/) via Kibana Fleet, ingest pipeline test fixtures into Elasticsearch, and report how many events were saved per integration.

## Prerequisites

- Kibana with Fleet enabled and packages available in the registry (local `elastic-package stack` or remote deployment).
- Elasticsearch reachable from the machine running the script.
- Python 3.9+ (stdlib only — no extra packages).

## Environment variables

| Variable | Default | Description |
| --- | --- | --- |
| `KIBANA_URL` | `http://localhost:5601/ftw` | Kibana base URL, including path prefix if used (e.g. `/ftw`) |
| `ES_URL` | `http://localhost:9200` | Elasticsearch URL |
| `ELASTIC_API_KEY` | — | Encoded API key for Kibana and Elasticsearch (serverless / Elastic Cloud) |
| `KIBANA_API_KEY` | — | Kibana-only API key (overrides `ELASTIC_API_KEY` for Fleet install) |
| `ES_API_KEY` | — | Elasticsearch-only API key (overrides `ELASTIC_API_KEY` for ingest/count) |
| `ELASTIC_API_KEY_ID` | — | Raw API key id (use with `ELASTIC_API_KEY_SECRET` instead of `ELASTIC_API_KEY`) |
| `ELASTIC_API_KEY_SECRET` | — | Raw API key secret |
| `ELASTIC_USER` | `elastic` | Username for basic auth |
| `ELASTIC_PASSWORD` | `changeme` | Password for basic auth |

### Authentication

Use **one** of these methods (API key is checked first):

**API key (recommended for serverless):**

```bash
export KIBANA_URL="https://<deployment>.kb.<region>.elastic.cloud"
export ES_URL="https://<deployment>.es.<region>.elastic.cloud"
export ELASTIC_API_KEY="<encoded-api-key>"
```

The encoded key is what Elastic returns when you create an API key (base64 of `id:api_key`). You can also pass the raw pair:

```bash
export ELASTIC_API_KEY_ID="<id>"
export ELASTIC_API_KEY_SECRET="<api_key>"
```

**Basic auth (local stack):**

```bash
export KIBANA_URL="http://elastic:changeme@localhost:5601/ftw"
export ES_URL="http://elastic:changeme@localhost:9200"
```

Or:

```bash
export ELASTIC_USER="elastic"
export ELASTIC_PASSWORD="changeme"
```

## Quick start (install + ingest + report)

**Serverless / API key:**

```bash
export KIBANA_URL="https://<deployment>.kb.<region>.elastic.cloud"
export ES_URL="https://<deployment>.es.<region>.elastic.cloud"
export ELASTIC_API_KEY="<your-encoded-api-key>"

python3 dev/domain/install-p1-integrations/install_and_ingest.py
```

**Local stack (basic auth):**

```bash
export KIBANA_URL="http://localhost:5601/ftw"
export ES_URL="http://localhost:9200"
export ELASTIC_USER="elastic"
export ELASTIC_PASSWORD="changeme"

python3 dev/domain/install-p1-integrations/install_and_ingest.py
```

Reports are written to `out/ingest_report_<run_id>.{json,md,csv}`.

## Dry run (fixture discovery only)

Discover pipeline test files and count events **without** calling Kibana or Elasticsearch:

```bash
python3 dev/domain/install-p1-integrations/install_and_ingest.py --dry-run --ingest-only
```

Example output:

```
Run ID: 20260623T144137
Kibana: http://localhost:5601/ftw
Elasticsearch: http://localhost:9200
Packages: 47

=== slack ===
  fixtures: 1, submitted: 6, bulk errors: 0

=== snyk ===
  fixtures: 2, submitted: 27, bulk errors: 0

...

=== zscaler_zia ===
  fixtures: 15, submitted: 62, bulk errors: 0
Wrote out/ingest_report_20260623T144137.json
Wrote out/ingest_report_20260623T144137.md
Wrote out/ingest_report_20260623T144137.csv
```

In dry-run mode, `submitted` is the number of documents that **would** be ingested; `saved` stays `0` because nothing is sent to Elasticsearch.

## Install only (shell template)

`install_packages.sh.template` installs all 47 packages via the Fleet API:

```bash
# API key (serverless)
export KIBANA_URL="https://<deployment>.kb.<region>.elastic.cloud"
export ELASTIC_API_KEY="<encoded-api-key>"
bash dev/domain/install-p1-integrations/install_packages.sh.template

# Basic auth (local)
export KIBANA_URL="http://localhost:5601/ftw"
export ELASTIC_USER="elastic"
export ELASTIC_PASSWORD="changeme"
bash dev/domain/install-p1-integrations/install_packages.sh.template
```

Single-package curl examples:

```bash
# API key
curl "${KIBANA_URL}/api/fleet/epm/packages/github" \
  -X POST \
  -H "kbn-xsrf: true" \
  -H "Authorization: ApiKey ${ELASTIC_API_KEY}"

# Basic auth
curl "${KIBANA_URL}/api/fleet/epm/packages/github" \
  -X POST \
  -H "kbn-xsrf: true" \
  -u "${ELASTIC_USER}:${ELASTIC_PASSWORD}"
```

## Python script options

```bash
# Install Fleet packages only (no ingest)
python3 install_and_ingest.py --install-only

# Ingest fixtures only (packages must already be installed)
python3 install_and_ingest.py --ingest-only

# Subset of packages
python3 install_and_ingest.py --packages slack,snyk,github

# Custom run ID (used in tags and report filenames)
python3 install_and_ingest.py --run-id my-test-run
```

## What gets ingested

For each package under `packages/<name>/`, the script scans:

```
packages/<name>/data_stream/*/_dev/test/pipeline/
```

| File type | Handling |
| --- | --- |
| `*.log` | One document per non-empty line, wrapped as `{"message": "<line>"}` (same as pipeline tests) |
| `*.json` | Uses the `events` array when present; otherwise a single object or top-level array |

**Skipped files:**

- `*-expected.json`
- `*-config.yml`
- `test-common-config.yml`

Documents are bulk-indexed to `logs-<dataset>-default` using ingest pipeline `logs-<dataset>`.

Each document is tagged for validation:

- `p1-domain-fixture-ingest`
- `p1-ingest-<package>`
- `p1-run-<run_id>`

## Validating ingestion (no time range)

Fixture events often carry historical `@timestamp` values (not “now”). The report queries `logs-*` **without a time filter** and reports min/max `@timestamp` per integration.

Example ES\|QL for a specific run:

```esql
FROM logs-*
| WHERE tags == "p1-ingest-slack"
  AND tags == "p1-run-20260623T144137"
| STATS count = COUNT(*), min_ts = MIN(@timestamp), max_ts = MAX(@timestamp)
```

## Packages without pipeline fixtures

These P1 integrations have no `_dev/test/pipeline` input files (install still works; ingest is skipped):

- `aws_cloudtrail_otel`
- `aws_vpcflow_otel`
- `corelight`
- `linux`
- `openai`

## Report output

| File | Contents |
| --- | --- |
| `out/ingest_report_<run_id>.md` | Summary table + per-integration ES\|QL queries |
| `out/ingest_report_<run_id>.json` | Full structured results |
| `out/ingest_report_<run_id>.csv` | Spreadsheet-friendly summary |

Columns: package, installed, fixture file count, events submitted, bulk errors, events saved, `@timestamp` range, datasets.
