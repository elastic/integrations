{{- generatedHeader }}
# Upwind Integration for Elastic

## Overview

The Upwind integration for Elastic collects runtime threat detections, vulnerability findings, and cloud configuration findings from the [Upwind](https://www.upwind.io/) Cloud Security Platform via the Management REST API.

## Elastic Managed Enabled Integration

Elastic Managed integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Elastic Managed integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Elastic Managed integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).
Elastic Managed deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Compatibility

This integration is compatible with the Upwind Management REST API v1 list endpoints for threat detections, vulnerability findings, and configuration findings.

### How it works

This integration periodically queries the Upwind Management API using OAuth2 client credentials. Each data stream polls its own list endpoint. Threat detections use a time bookmark on `last_seen_time` and page through each window with `page` and `per-page`. Vulnerability findings and configuration findings page through the full current list with a page token. Configuration findings run on a fixed 24-hour interval and collect the complete posture, including passed and failed checks.

## What data does this integration collect?

The Upwind integration collects log messages of the following types:

* `Threat detections`: Runtime, API security, and CloudTrail-correlated detections.
* `Vulnerability findings`: CVE findings with runtime reachability and exploitability context.
* `Configuration findings`: Full cloud security posture findings (CSPM), including passed and failed checks and compliance framework context. Each run lists all current findings.

### Supported use cases

Use threat detections to investigate runtime and cloud-control-plane alerts in Elastic Security. Use vulnerability findings to prioritize CVEs that are present on running workloads. Use configuration findings to review the current cloud configuration posture, including passed and failed checks and the frameworks they map to.

Vulnerability findings appear on the Elastic Security [Vulnerabilities Findings page](https://www.elastic.co/docs/solutions/security/cloud/findings-page-3) and in vulnerability Insights on the Alert and Entity details flyouts. Configuration findings appear on the [Misconfigurations Findings page](https://www.elastic.co/docs/solutions/security/cloud/findings-page) and in misconfiguration Insights.

### Transforms

The Upwind integration creates latest transforms that copy current findings into destination indexes used by Elastic Security CDR workflows:

| Data stream | Transform destination alias |
| --- | --- |
| `logs-upwind.vulnerability_findings-*` | `security_solution-upwind.vulnerability_latest` |
| `logs-upwind.configuration_findings-*` | `security_solution-upwind.misconfiguration_latest` |

The source data streams keep historical events. The aliased transform destinations hold the latest finding per unique key so the Findings pages and flyouts show current posture. Vulnerability findings are retained for 90 days. Configuration findings are a full 24-hour posture sync and are retained for 26 hours.

The transforms sync on `event.ingested`. Elasticsearch sets this field on ingest through the Fleet final pipeline, including Elastic Managed deployments.

Using these transforms requires:

- [Elastic Security](https://www.elastic.co/docs/solutions/security)
- at least one [transform node](https://www.elastic.co/docs/deploy-manage/distributed-architecture/clusters-nodes-shards/node-roles#transform-node-role)
- privileges to use transforms and to read the source and destination indexes

See [Transform setup](https://www.elastic.co/docs/explore-analyze/transforms/transform-setup) for details. Because the latest copy of each finding is stored in both the source data stream and the destination index, plan storage accordingly.

## What do I need to use this integration?

### From Upwind

You need an Upwind organization and an API credential that can read threats, vulnerabilities, and configuration findings. To create the credential and collect the required values:

1. Sign in to the Upwind console for your region.
2. Open **Settings → Credentials → Generate Credential**.
3. Choose credential type **API**.
4. Grant read access to threat detections, vulnerability findings, and configuration findings.
5. Copy the **Client ID** and **Client Secret**. The secret is shown only once.
6. Copy the **Organization ID** from organization settings.
7. Note the regional API URL: `https://api.upwind.io` (US), `https://api.eu.upwind.io` (EU), `https://api.me.upwind.io` (ME), or `https://api.au.upwind.io` (AU).

#### Vendor resources

- [Upwind credentials](https://docs.upwind.io/settings/credentials)
- [Upwind Management API v1](https://docs.upwind.io/restapi/v1/introduction)
- [Upwind Management API v1 OpenAPI](https://docs.upwind.io/restapi/management/v1/openapi.yaml)

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the Upwind API and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Set up steps in Kibana

Use the values collected in [From Upwind](#from-upwind).

1. In Kibana, go to **Management > Integrations**.
2. Search for **Upwind**.
3. Click **Add Upwind**.
4. Enter the **API URL** for your region. The OAuth audience uses this same URL.
5. Leave **Token URL** as `https://auth.upwind.io/oauth/token` unless Upwind provides a different token endpoint.
6. Enter the **Client ID**, **Client Secret**, and **Organization ID**.
7. Enable **Threat detections**, **Vulnerability findings**, and/or **Configuration findings**. Set the interval for threat detections and vulnerability findings. Configuration findings synchronize the full posture every 24 hours.
8. Click **Save and continue**.

### Validation

1. In the Upwind console, confirm the API credential can read threats, vulnerabilities, and configuration findings, and that the organization has recent detections or findings.
2. In Kibana Discover, search `data_stream.dataset: "upwind.threat_detections"`, `data_stream.dataset: "upwind.vulnerability_findings"`, and `data_stream.dataset: "upwind.configuration_findings"`.

## Troubleshooting

- 401 Unauthorized: The client ID, client secret, or token URL is wrong, or the token audience does not match the API URL region. US credentials cannot call the EU, ME, or AU API.
- 403 Forbidden: The API credential does not have read access to that finding type. Update the credential roles in Settings → Credentials.
- 429 Rate limit exceeded: Upwind returned HTTP 429. Increase the polling interval for the affected data stream.
- No threat detections: Confirm detections exist in the lookback window (Initial interval). The list is filtered by last seen time.
- No vulnerability findings: Each page is a JSON array and can be HTTP 200 or HTTP 206. Pages continue while the Link header advertises a next page. Confirm the credential can read vulnerabilities and that findings exist in the organization.
- No configuration findings: Each page is a JSON array paged by the Link header. An envelope with resourceFindings and pagination is also accepted. Pages can be HTTP 200 or HTTP 206. Confirm the credential can read configuration findings and that posture checks exist in the organization. Each run lists all current PASS and FAIL findings.

## Performance and scaling

Threat detections are collected with a time window and page-based pagination (`page`, `per-page`, default 100). Vulnerability findings and configuration findings page with `per-page` (default 100). Configuration findings re-list the full posture every 24 hours. Prefer a shorter interval for threat detections than for a full vulnerability or configuration posture sync. Tokens last 24 hours and are refreshed on each poll.

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

#### Data retention

The `configuration_findings` and `vulnerability_findings` data streams re-list the current posture on every polling interval (default 24 hours). Configuration findings index a new document for every finding on each run. Vulnerability findings set the document ID from a fingerprint of the finding, which drops an unchanged finding only while the same backing index is being written to. With the daily rollover of the ILM policy, an unchanged finding is indexed again about once a day.

The package bounds that growth with a 30-day retention that depends on the deployment type:

| Data stream | Self-managed and Elastic Cloud Hosted (ILM policy) | Serverless (data stream lifecycle) |
|---|---|---|
| `logs-upwind.configuration_findings-*` | `logs-upwind.configuration_findings-default_policy`: roll over after 1d, delete 29d after rollover | delete 30d after rollover |
| `logs-upwind.vulnerability_findings-*` | `logs-upwind.vulnerability_findings-default_policy`: roll over after 1d, delete 29d after rollover | delete 30d after rollover |

On self-managed and Elastic Cloud Hosted deployments the ILM policy applies. The data stream lifecycle shipped with the package is not used there. ILM counts the delete age from the rollover of a backing index, so a document can remain for up to the rollover age plus the delete age. On Serverless, ILM is not available and the data stream lifecycle applies instead. It also works per backing index: Elasticsearch [rolls the write index over automatically](https://www.elastic.co/docs/reference/elasticsearch/configuration-reference/data-stream-lifecycle-settings#cluster-lifecycle-default-rollover) on age, size, or document count, and [deletes a backing index once the retention has passed since it rolled over](https://www.elastic.co/docs/manage-data/lifecycle/data-stream#data-streams-lifecycle-how-it-works). A document therefore stays for the retention plus up to one rollover interval. The rollover age is derived from the retention and is an implementation detail that Elasticsearch may change.

To keep data for a different period:

- Self-managed and Elastic Cloud Hosted: edit the ILM policy in Kibana under **Stack Management → Index Lifecycle Policies**, or with `PUT _ilm/policy/<policy name>`. A package upgrade reinstalls the package's ILM policies, so check your change after upgrading.
- Serverless: set the retention on the data stream, for example `PUT _data_stream/logs-upwind.configuration_findings-default/_lifecycle` with the body `{"data_retention": "90d"}`. Replace `default` with your namespace.

## Reference

### Inputs used

{{ inputDocs }}

### API usage

These APIs are used with this integration:

* [List threat detections](https://docs.upwind.io/restapi/v1/introduction) — `GET /v1/organizations/{organization-id}/threat-detections`
* [List vulnerability findings](https://docs.upwind.io/restapi/v1/introduction) — `GET /v1/organizations/{organization-id}/vulnerability-findings`
* [List configuration findings](https://docs.upwind.io/restapi/v1/introduction) — `GET /v1/organizations/{organization-id}/configuration-findings`
* [OAuth token](https://docs.upwind.io/settings/credentials) — `POST https://auth.upwind.io/oauth/token` (`grant_type=client_credentials`, `audience` equal to the API URL)

### Vendor documentation links

- [Upwind documentation](https://docs.upwind.io/)
- [Management API v1 introduction](https://docs.upwind.io/restapi/v1/introduction)
- [Credentials](https://docs.upwind.io/settings/credentials)

### Data streams

#### Threat detections

The `threat_detections` data stream collects runtime threat detections from `GET /v1/organizations/{organization-id}/threat-detections`.

##### Threat detections fields

{{ fields "threat_detections" }}

##### Threat detections sample event

{{ event "threat_detections" }}

#### Vulnerability findings

The `vulnerability_findings` data stream collects CVE findings from `GET /v1/organizations/{organization-id}/vulnerability-findings`.

##### Vulnerability findings fields

{{ fields "vulnerability_findings" }}

##### Vulnerability findings sample event

{{ event "vulnerability_findings" }}

#### Configuration findings

The `configuration_findings` data stream collects the current CSPM posture from `GET /v1/organizations/{organization-id}/configuration-findings`. Each run lists all current passed and failed findings.

##### Configuration findings fields

{{ fields "configuration_findings" }}

##### Configuration findings sample event

{{ event "configuration_findings" }}
