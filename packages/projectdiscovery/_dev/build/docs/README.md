{{- generatedHeader }}
# ProjectDiscovery Integration for Elastic

## Overview

The ProjectDiscovery integration for Elastic collects vulnerability findings and asset inventory from [ProjectDiscovery Cloud Platform](https://cloud.projectdiscovery.io) (PDCP). PDCP runs [Nuclei](https://github.com/projectdiscovery/nuclei) scans against your external attack surface and keeps an inventory of the assets it discovers.

### Compatibility

This integration supports the ProjectDiscovery Cloud Platform REST API (`https://api.projectdiscovery.io`, `v1` endpoints). It requires Kibana 9.4.0 or later.

### How it works

The integration uses the [CEL input](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel) to poll the PDCP API on a schedule.

- The `vulnerability` data stream pages through scan results that are sorted by `updated_at` and stores the newest timestamp it has seen as its cursor.
- The `asset` data stream pages through the asset enumeration contents in the same way.

Each data stream saves its cursor only after a full pass has finished. If a pass is interrupted, it starts again from the previous cursor, so no data is lost, but some events can be duplicated.

Two transforms keep the latest state of each finding and each asset in lookup mode indices. You can enrich findings with asset context by using an ES|QL `LOOKUP JOIN`.

## What data does this integration collect?

The ProjectDiscovery integration collects the following types of data:

* `vulnerability`: Nuclei findings from `GET /v1/scans/results`, including the template metadata, classification (CVE, CWE, CVSS, EPSS), the vulnerability status and the metadata of the affected asset.
* `asset`: Discovered assets from `GET /v1/asset/enumerate/contents`, including hosts, IPs, ports, technologies, TLS certificates and cloud provider. Assets are ingested as entities (`event.kind: asset`, `entity.*`).

### Supported use cases

- Track exposed vulnerabilities in your external attack surface alongside your other security data.
- Find vulnerabilities in the Elastic Security Findings page by using the `security_solution-projectdiscovery.vulnerability_latest` index.
- Enrich findings with asset context (host, IP, technologies, TLS, cloud provider) by using ES|QL `LOOKUP JOIN`.
- Monitor remediation progress through the ProjectDiscovery vulnerability status (`open`, `fixed`, `false_positive`, and others).

## What do I need to use this integration?

- A ProjectDiscovery Cloud Platform account with access to the team whose data you want to collect.
- A ProjectDiscovery API key and the Team ID.
- An Elastic deployment with Kibana 9.4.0 or later.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

Elastic Agent is required to poll the ProjectDiscovery API and ship the data to Elastic, where the events are processed by the integration's ingest pipelines.

### Agentless deployment

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. Agentless deployments provide a means to ingest data while avoiding the orchestration, management, and maintenance needs associated with standard ingest infrastructure. Using an agentless deployment makes manual agent deployment unnecessary, allowing you to focus on your data instead of the agent that collects it.

For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

### Set up steps in ProjectDiscovery

1. Recommended: an Owner or Admin of the team invites a dedicated integration user with the **Viewer** role under **Settings → Team**. The Viewer role can read every endpoint this integration uses.
2. Sign in as that user and go to **Settings → API Key** (<https://cloud.projectdiscovery.io/settings/api-key>). Copy the API key.
3. In **Settings → Team** (<https://cloud.projectdiscovery.io/settings/team>), copy the **Team ID** of the team workspace.

API keys have no scopes. A key acts with the team role of the user who owns it.

#### Vendor resources

- [ProjectDiscovery API introduction](https://docs.projectdiscovery.io/api-reference/introduction)
- [Team administration and roles](https://docs.projectdiscovery.io/cloud/admin)

### Set up steps in Kibana

1. In Kibana, go to **Management → Integrations** and search for **ProjectDiscovery**.
2. Click **Add ProjectDiscovery**.
3. Configure the integration settings:
   - **API URL**: The ProjectDiscovery API base URL. The default is `https://api.projectdiscovery.io`.
   - **API Key**: The API key copied from ProjectDiscovery. It is sent in the `X-API-Key` header.
   - **Team ID**: The Team ID copied from ProjectDiscovery. It is sent in the `X-Team-Id` header and is normally required to collect team data.
   - **HTTP Client Timeout**, **Proxy URL** and **SSL Configuration**: Optional HTTP client settings.
4. Configure each data stream:
   - **Interval**: How often to poll the API. The defaults are `15m` for vulnerabilities and `1h` for assets.
   - **Initial Interval**: How far back to collect data on the first run, based on `updated_at`. The default is `720h` (30 days). If your tenant has not been scanned recently, increase this value. Otherwise, the first run collects nothing.
   - **Batch Size**: The number of records to request per page (maximum 100).
   - **Severity** (vulnerability only): The severities to collect. The default includes `info`. Remove `info` to reduce the volume by about 90%.
5. Click **Save and continue**.

### Validation

1. In Kibana, go to **Discover** and select the `logs-*` data view.
2. Filter on `data_stream.dataset : "projectdiscovery.vulnerability"` or `data_stream.dataset : "projectdiscovery.asset"`.
3. Confirm that events appear. Events with `error.message` indicate API or decoding errors.
4. Go to **Stack Management → Transforms** and check that the `logs-projectdiscovery.latest_vulnerability-*` and `logs-projectdiscovery.latest_asset-*` transforms are started and healthy.

## Troubleshooting

- No data is collected on the first run: The default `720h` initial interval only covers findings and assets updated in the last 30 days. Increase **Initial Interval** if your last scan is older.
- No vulnerabilities in the latest index or the Findings page: The `latest_vulnerability` transform only keeps findings that have `package.name`. The integration sets `package.name` from the template metadata product or the CPE product, and most Nuclei findings (misconfiguration, TLS and header checks) have neither. All findings are still available in `logs-projectdiscovery.vulnerability-*`.
- Assets disappear from the latest index: The `latest_asset` transform removes assets that have not been seen for 3 days (based on `entity.last_seen_timestamp`). This matches the asset expiry rules of ProjectDiscovery.
- HTTP 401 or 403 errors: Check the API key, and check that its user is a member of the team in **Team ID**.
- HTTP 429 errors: ProjectDiscovery limits requests per minute. The integration throttles requests and retries with backoff. If errors persist, increase **Interval** or check whether other API clients share the same key.
- Missing team data: Check that **Team ID** is set to the team workspace that holds your scans and assets.

## Performance and scaling

- Every ProjectDiscovery rescan updates `updated_at` on every finding it detects again, so each scan cycle re-sends the whole active set of findings. With `info` severity, a large tenant can take several hours to collect a full cycle at the vulnerability API limit of 60 requests per minute. Removing `info` from **Severity** reduces this to minutes.
- The asset API is limited to 30 requests per minute. The integration requests at most one page every two seconds.
- Run only one integration policy per ProjectDiscovery team. Multiple policies share the same rate limit.

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Inputs used

{{ inputDocs }}

### API usage

These APIs are used with this integration:

* [Get all results](https://docs.projectdiscovery.io/api-reference/results/get-all-results) (`GET /v1/scans/results`): Vulnerability findings.
* [Get all enumeration contents](https://docs.projectdiscovery.io/api-reference/enumerations/get-all-enumeration-contents) (`GET /v1/asset/enumerate/contents`): Asset inventory.

### Vendor documentation links

- [ProjectDiscovery Cloud Platform](https://docs.projectdiscovery.io/cloud/introduction)
- [Asset discovery overview](https://docs.projectdiscovery.io/cloud/assets/overview)
- [Nuclei](https://docs.projectdiscovery.io/opensource/nuclei/running)

### Latest indices and asset enrichment

The integration installs two transforms:

| Transform | Destination alias | Unique key | Retention |
|---|---|---|---|
| `latest_vulnerability` | `security_solution-projectdiscovery.vulnerability_latest` | `event.id`, `data_stream.namespace` | 90 days on `@timestamp` |
| `latest_asset` | `logs-projectdiscovery_latest.asset` | `event.dataset`, `entity.id` | 3 days on `entity.last_seen_timestamp` |

Both destination indices use lookup mode, so you can join them in ES|QL. Findings reference their asset through `projectdiscovery.vulnerability.asset_metadata.id`, which matches `entity.id` in the asset index.

`LOOKUP JOIN` replaces every column that also exists in the lookup index, including `@timestamp`, `event.*`, `host.*`, `url.*`, `tls.*` and `cloud.*`. When no asset matches, these columns become `null`. Copy the finding columns you need under new names and keep only those before the join:

```esql
FROM logs-projectdiscovery.vulnerability-*
| WHERE projectdiscovery.vulnerability.asset_metadata.id IS NOT NULL
| EVAL finding.timestamp = @timestamp, finding.id = event.id, entity.id = projectdiscovery.vulnerability.asset_metadata.id
| KEEP finding.timestamp, finding.id, entity.id, vulnerability.id, vulnerability.severity, projectdiscovery.vulnerability.vuln_status
| LOOKUP JOIN logs-projectdiscovery_latest.asset ON entity.id
| KEEP finding.timestamp, finding.id, vulnerability.id, vulnerability.severity, projectdiscovery.vulnerability.vuln_status, entity.id, entity.name, entity.type, host.ip
```

### Data streams

#### vulnerability

The `vulnerability` data stream provides Nuclei vulnerability findings from ProjectDiscovery Cloud Platform.

##### vulnerability fields

{{ fields "vulnerability" }}

##### vulnerability sample event

{{ event "vulnerability" }}

#### asset

The `asset` data stream provides the asset inventory discovered by ProjectDiscovery Cloud Platform, ingested as entities.

##### asset fields

{{ fields "asset" }}

##### asset sample event

{{ event "asset" }}

{{ ilm }}

{{ transform }}
