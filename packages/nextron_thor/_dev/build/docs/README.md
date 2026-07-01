# Nextron THOR Cloud

[Nextron THOR Cloud](https://www.nextron-systems.com/thor-cloud/) is a cloud-based compromise assessment platform that runs the THOR forensic scanner on endpoints through the THOR Cloud Launcher. This integration polls the THOR Cloud API and ingests scan findings into Elastic Security for centralized threat hunting and incident response.

## Agentless Enabled Integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).
Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

## Data streams

The Nextron THOR Cloud integration collects one type of data:

- **Thor Forwarding** — Scan results and findings from the THOR Cloud API, including detected threats, malware signatures, suspicious files, and security events identified during endpoint scans.

## Requirements

### THOR Cloud

- A [THOR Cloud](https://www.nextron-systems.com/thor-cloud/) or [THOR Cloud Lite](https://www.nextron-systems.com/thor-cloud/) account with API access.
- **THOR Cloud Launcher** deployed on at least one endpoint and at least one completed scan before data appears in Elastic.
- Scan reports must be **unencrypted** (`logs_encrypted` must be `false`). This integration does not ingest encrypted THOR reports.
- Scans must include `thor.json` in `available_logs`.
- Supported endpoint platforms: **Windows**, **Linux**, and **macOS**.

### Compatibility

This integration has been tested with:

| Component | Minimum tested version |
| --- | --- |
| THOR Cloud API | v1 (`https://thor-cloud.nextron-services.com/ui/api-documentation`) |
| THOR scanner | 10.7.x |
| THOR JSON log format | v2 (`log_version: v2.0.0`) |

THOR Cloud Lite is supported when scans produce unencrypted `thor.json` logs through the same API.

### Elastic Stack

This integration supports Agentless and Elastic Agent-based data collection.

For agent-based collection, install Elastic Agent using the [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

## How it works

Data flows from endpoints to Elastic as follows:

1. **Endpoint** — THOR Cloud Launcher runs a THOR scan on the endpoint.
2. **THOR Cloud** — Scan results and `thor.json` logs are uploaded and stored.
3. **THOR Cloud API** — The integration polls `/v1/scan/search` and `/v1/scan/log` for new scans.
4. **Elastic Agent (CEL input)** — Retrieves logs over HTTPS and ships raw events.
5. **Elasticsearch data stream** — The `nextron_thor_apt_scanner.thor_forwarding` ingest pipeline normalizes events to ECS.

The integration uses a CEL input to poll the THOR Cloud REST API. It does not require syslog or log file receivers on the Elastic Agent host.

## Setup

### Step 1: Prepare THOR Cloud

1. Log into your [THOR Cloud dashboard](https://thor-cloud.nextron-services.com/).
2. Deploy the **THOR Cloud Launcher** on at least one endpoint (Windows, Linux, or macOS).
3. Run a scan and confirm it completes successfully.
4. In the THOR Cloud dashboard, verify the scan report is **not encrypted** and that `thor.json` is listed in the scan's available logs.
5. Navigate to **General Settings** → **API Key**, click **Generate**, and copy the API key. You will not be able to copy it after this step.
6. Note the **API Endpoint URL** (default: `https://thor-cloud.nextron-services.com/api`).

### Step 2: Add the integration in Elastic

1. In Kibana, navigate to **Management** → **Integrations**.
2. Search for **Nextron THOR Cloud** and add the integration.
3. Configure the required parameters:
   - **API URL**: THOR Cloud API endpoint URL from Step 1
   - **API Key**: API key from Step 1
   - **Initial Interval**: How far back to pull scan logs on first run (default: `24h`)
   - **Interval**: Duration between API requests (default: `5m`)
4. Save and deploy the integration.

### Step 3: Verify data collection

1. In **Discover**, open the `logs-*` data view.
2. Filter documents by `data_stream.dataset : "nextron_thor_apt_scanner.thor_forwarding"`.
3. Confirm events from your completed scan appear within the configured polling interval.
4. If no data appears, check the following:
   - The scan completed with status `successful` or `failed` in THOR Cloud.
   - **`logs_encrypted` is `false`** for the scan. Encrypted reports are skipped by this integration and will not produce events in Elastic.
   - `thor.json` is listed in `available_logs` for the scan.
   - The API key is valid and the **Initial Interval** covers the scan completion time.

**Note:**
- Scan data is fetched incrementally based on `last_launcher_update` and the configured initial interval.
- The integration supports batch processing with configurable batch sizes for optimal performance.

## Exported fields
{{fields "thor_forwarding"}}

## Example Event

{{event "thor_forwarding"}}
