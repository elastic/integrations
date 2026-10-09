# FDR ingest pipeline generators

Go generators for the CrowdStrike FDR data stream ingest pipelines. Edit these sources and regenerate YAML instead of hand-editing pipeline files.

## What it generates

Ten ingest pipelines under `data_stream/fdr/elasticsearch/ingest_pipeline/`:

| Generator | Output |
|-----------|--------|
| `default.go` | `default.yml` |
| `categorize.go` (+ `categorize.json`) | `categorize.yml` |
| `network.go -dir inbound` | `inbound_network.yml` |
| `network.go -dir outbound` | `outbound_network.yml` |
| `automated_lead_summary.go` | `automated_lead_summary.yml` |
| `epp_detection_summary.go` | `epp_detection_summary.yml` |
| `data_protection.go` | `data_protection_detection_summary.yml` |
| `fim_rule_matched.go` | `fim_rule_matched.yml` |
| `cspm_iom.go` | `cspm_iom.yml` |
| `cspm_ioa.go` | `cspm_ioa.yml` |

## Prerequisites

- [Go](https://go.dev/dl/) on `PATH` (see `go` version in `go.mod`)
- Network access on first run to download module dependencies (`github.com/efd6/dispear`)

## Run

From this directory:

```bash
cd packages/crowdstrike/_dev/scripts/fdr-gen
./generate.sh
```

The script checks for Go, runs `go mod download`, regenerates all pipelines, and inserts a short “do not edit by hand” header after the leading `---` in each YAML file.

## Edit workflow

1. Change the relevant `.go` file (and `categorize.json` / `long_fields.json` when needed).
2. Run `./generate.sh`.
3. Review the diff under `data_stream/fdr/elasticsearch/ingest_pipeline/`.
4. Run FDR pipeline tests, for example:

```bash
cd packages/crowdstrike
elastic-package test pipeline -v --data-streams fdr
```
