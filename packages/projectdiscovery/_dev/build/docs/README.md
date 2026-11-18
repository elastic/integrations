{{- generatedHeader }}
# ProjectDiscovery Integration for Elastic

## Overview

The ProjectDiscovery integration for Elastic collects vulnerability findings from [ProjectDiscovery Cloud Platform](https://cloud.projectdiscovery.io) (PDCP). PDCP runs [Nuclei](https://github.com/projectdiscovery/nuclei) scans against your external attack surface.

### Compatibility

This integration supports the ProjectDiscovery Cloud Platform REST API (`https://api.projectdiscovery.io`, `v1` endpoints). It requires Kibana 9.4.0 or later.

### How it works

The integration uses the [CEL input](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel) to poll the PDCP API on a schedule.

The `vulnerability` data stream pages through scan results that are sorted by `updated_at` and stores the newest timestamp it has seen as its cursor. It saves the cursor only after a full pass has finished. If a pass is interrupted, it starts again from the previous cursor, so no data is lost, but some events can be duplicated.

A transform keeps the latest state of each finding in a lookup mode index. The latest vulnerability index keeps findings of every status, so a finding that changes from `open` to `fixed` is updated in place. Filter on `projectdiscovery.vulnerability.vuln_status` to select current open findings.

## What data does this integration collect?

The ProjectDiscovery integration collects the following types of data:

* `vulnerability`: Nuclei findings from `GET /v1/scans/results`, including the template metadata, classification (CVE, CWE, CVSS, EPSS), the vulnerability status and the metadata of the affected asset.

### Supported use cases

- Track exposed vulnerabilities in your external attack surface alongside your other security data.
- Find vulnerabilities in the Elastic Security Findings page by using the `security_solution-projectdiscovery.vulnerability_latest` index. The **Data source** field of the findings flyout links to the Nuclei template that detected the finding (`vulnerability.data_source.*`).
- Monitor remediation progress through the ProjectDiscovery vulnerability status (`open`, `fixed`, `false_positive`, and others) in `logs-projectdiscovery.vulnerability-*`. The latest vulnerability index keeps the latest status of every finding, so filter on `projectdiscovery.vulnerability.vuln_status: open` to list current open findings.
- Group findings by root domain with `server.registered_domain`. For example, `codebox.example.co.uk` results in `example.co.uk`.
- Group findings by network owner with `server.as.number` and `server.as.organization.name`.

### Dashboards

The integration includes a dashboard built with ES|QL. Its controls filter every panel, including the raw data panel:

- **[Logs ProjectDiscovery] Vulnerabilities**: Current open findings by severity, status, host, category, and protocol type; trends of findings seen, newly discovered, and fixed; CVE details with CVSS and EPSS scores; and the raw findings. Controls filter on severity, status, protocol type, and host. Panels that read the latest vulnerability index show open findings unless you select another status in the **Status** control.

![ProjectDiscovery vulnerabilities dashboard](../img/projectdiscovery-vulnerabilities.png)

Trend panels count distinct findings per time bucket on `@timestamp`, which ProjectDiscovery updates on every rescan. A finding therefore appears in each bucket in which it was seen, not only when it was first discovered.

### Root domain fields

The `vulnerability` data stream splits the host name (`host.name`, or `url.domain` when the host name is missing or is not a domain name) into `server.domain`, `server.registered_domain`, `server.subdomain` and `server.top_level_domain`. The split uses the public suffix list, so multi-part suffixes such as `co.uk` are handled correctly. IP addresses and names without a public suffix do not populate these fields.

## What do I need to use this integration?

- A ProjectDiscovery Cloud Platform account with access to the team whose data you want to collect.
- A ProjectDiscovery API key and the Team ID.
- An Elastic deployment with Kibana 9.4.0 or later.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

Elastic Agent is required to poll the ProjectDiscovery API and ship the data to Elastic, where the events are processed by the integration's ingest pipelines.

### Elastic Managed deployment

Elastic Managed deployments are only supported in Elastic Serverless and Elastic Cloud environments. Elastic Managed deployments provide a means to ingest data while avoiding the orchestration, management, and maintenance needs associated with standard ingest infrastructure. Using an Elastic Managed deployment makes manual agent deployment unnecessary, allowing you to focus on your data instead of the agent that collects it.

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
4. Configure the data stream:
   - **Interval**: How often to poll the API. The default is `15m`.
   - **Initial Interval**: How far back to collect data on the first run, based on `updated_at`. The default is `720h` (30 days). If your tenant has not been scanned recently, increase this value. Otherwise, the first run collects nothing.
   - **Batch Size**: The number of records to request per page (maximum 100).
   - **Severity**: The severities to collect. The default includes `info`. Remove `info` to reduce the volume by about 90%.
5. Click **Save and continue**.

### Validation

1. In Kibana, go to **Discover** and select the `logs-*` data view.
2. Filter on `data_stream.dataset : "projectdiscovery.vulnerability"`.
3. Confirm that events appear. Events with `error.message` indicate API or decoding errors.
4. Go to **Stack Management → Transforms** and check that the `logs-projectdiscovery.latest_cdr_vulnerabilities-*` transform is started and healthy.
5. Go to **Dashboards** and open **[Logs ProjectDiscovery] Vulnerabilities**. Trend panels need data in more than one time bucket. Right after setup, select a shorter time range, such as the last 24 hours, if they show no results.

## Troubleshooting

- No data is collected on the first run: The default `720h` initial interval only covers findings updated in the last 30 days. Increase **Initial Interval** if your last scan is older.
- Empty **Package** column in the Findings page: The integration sets `package.name` from the template metadata product or the CPE product. Most Nuclei findings (misconfiguration, TLS and header checks) have neither.
- A finding is missing from the latest index or the Findings page: The `latest_cdr_vulnerabilities` transform only reads documents from the last 90 days and removes findings that have no new document for 90 days (based on `@timestamp`). Check that the finding is present in `logs-projectdiscovery.vulnerability-*` and that its `projectdiscovery.vulnerability.vuln_status` is not what you filter out.
- Fixed or dismissed findings appear in the latest index or the Findings page: The latest index keeps the latest state of every finding, including `fixed`, `false_positive`, `duplicate` and `accepted_risk`. Filter on `projectdiscovery.vulnerability.vuln_status: open` to see only current open findings.
- The Findings flyout has an empty **Vulnerability Score** section: This section only displays CVSS vectors attributed to NVD, Red Hat or GHSA (`vulnerability.cvss.*`). Nuclei templates don't state the source of their CVSS data, so the integration doesn't populate these fields. The **CVSS** badge in the flyout header shows the template score from `vulnerability.score.base` and `vulnerability.score.version`.
- HTTP 401 or 403 errors: Check the API key, and check that its user is a member of the team in **Team ID**.
- HTTP 429 errors: ProjectDiscovery limits requests per minute. The integration throttles requests and retries with backoff. If errors persist, increase **Interval** or check whether other API clients share the same key.
- Missing team data: Check that **Team ID** is set to the team workspace that holds your scans.

## Performance and scaling

- Every ProjectDiscovery rescan updates `updated_at` on every finding it detects again, so each scan cycle re-sends the whole active set of findings. With `info` severity, a large tenant can take several hours to collect a full cycle at the vulnerability API limit of 60 requests per minute. Removing `info` from **Severity** reduces this to minutes.
- Run only one integration policy per ProjectDiscovery team. Multiple policies share the same rate limit.

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Inputs used

{{ inputDocs }}

### API usage

These APIs are used with this integration:

* [Get all results](https://docs.projectdiscovery.io/api-reference/results/get-all-results) (`GET /v1/scans/results`): Vulnerability findings.

### Vendor documentation links

- [ProjectDiscovery Cloud Platform](https://docs.projectdiscovery.io/cloud/introduction)
- [Nuclei](https://docs.projectdiscovery.io/opensource/nuclei/running)

### Latest index

The integration installs one transform:

| Transform | Destination alias | Unique key | Retention |
|---|---|---|---|
| `latest_cdr_vulnerabilities` | `security_solution-projectdiscovery.vulnerability_latest` | `event.id`, `data_stream.namespace` | 90 days on `@timestamp`. Findings of every status are kept. |

### Data streams

#### vulnerability

The `vulnerability` data stream provides Nuclei vulnerability findings from ProjectDiscovery Cloud Platform.

##### vulnerability fields

{{ fields "vulnerability" }}

##### vulnerability sample event

{{ event "vulnerability" }}

{{ ilm }}

{{ transform }}
