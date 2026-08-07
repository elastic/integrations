# Local Development & Testing Guide

This guide covers how to manually test the `cloud_defend_otel` integration locally against a running Elastic Stack.

## Prerequisites

- Go (version from `.go-version` in the repo root)
- Docker and Docker Compose v2
- `jq` and `yq`

Install `elastic-package` from the repo root:

```bash
cd /path/to/elastic/integrations
go build -o build/elastic-package github.com/elastic/elastic-package
export PATH="$PWD/build:$PATH"
```

## 1. Start the Elastic Stack

From within the package directory, start Elasticsearch, Kibana, and Fleet Server:

```bash
cd packages/cloud_defend_otel

elastic-package stack up -v
```

> **Note**: The package requires Kibana `^8.19.0 || ^9.3.0` and an `enterprise` subscription — both flags above are required.

Check the stack is ready:

```bash
elastic-package stack status
```

Kibana will be available at **https://localhost:5601** (`elastic` / `changeme`).

## 2. Install the Integration

Build and upload the integration from your local branch into Fleet:

```bash
elastic-package install -v
```

This registers the package so it's available to create policies in Kibana.

## 3. Enroll an Elastic Agent

Go to **Kibana → Fleet → Agents → Add agent**, create an agent policy using the `cloud_defend_otel` integration, then enroll a local agent using the enrollment token shown in the UI:

```bash
docker run \
  --network elastic-package-stack_default \
  --env FLEET_ENROLL=1  --env FLEET_INSECURE=true \
  --env FLEET_URL=https://fleet-server:8220 \
  --env FLEET_ENROLLMENT_TOKEN="${FLEET_ENROLLMENT_TOKEN}" \
  -p 4317:4317 \
  docker.elastic.co/elastic-agent/elastic-agent:9.4.2
```

Tunnel

```bash
gcloud compute ssh --zone "us-east1-d" "biscout42-d4c-build" --tunnel-through-iap --project "elastic-security-dev" -- -NR 4317:localhost:4317  -o ServerAliveInterval=30 -o ServerAliveCountMax=3
```

### Using a custom Elastic Agent image

To completely replace the agent image used by the stack (e.g. a locally built or unreleased image), set the `ELASTIC_AGENT_IMAGE_REF_OVERRIDE` environment variable before starting the stack:

```bash
export ELASTIC_AGENT_IMAGE_REF_OVERRIDE=docker.elastic.co/elastic-agent/elastic-agent:my-custom-tag
elastic-package stack up -v
```

This overrides the agent image entirely, regardless of the `--version` flag.

The integration listens for OTLP telemetry on:
- **gRPC**: `:4317`
- **HTTP**: `:4318`

The default dataset is `cloud_defend.logs`; set `data_stream.dataset` in the policy to `cloud_defend.file` for the file dataset.

## 4. Run System Tests (automated end-to-end)

`elastic-package test system` handles agent enrollment automatically via Docker, sends test data through the OTLP endpoints, and asserts that documents land in Elasticsearch:

```bash
elastic-package test system -v
```

Test configs are in `_dev/test/system/`. Each expects a minimum of 50 documents. Tests run sequentially (`parallel: false`).

To run all test types (system, policy, pipeline, asset):

```bash
elastic-package test -v
```

## 5. View Data in Kibana

After data is flowing:
- **Discover**: query index pattern `logs-cloud_defend.*`
- **Dashboards**: any dashboards bundled with the integration appear under Kibana → Dashboards

## 6. Teardown

```bash
# Optional: dump stack logs before stopping (useful for debugging failures)
elastic-package stack dump -v --output ../../build/elastic-stack-dump/cloud_defend_otel

elastic-package stack down -v
```
