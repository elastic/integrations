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

This integration periodically queries the Upwind Management API using OAuth2 client credentials. Each data stream polls its own list endpoint. Threat detections use a time bookmark on `last_seen_time`. Vulnerability findings and configuration findings page through the full current list with a page token. Configuration findings run on a fixed 24-hour interval and collect the complete posture, including passed and failed checks.

## What data does this integration collect?

The Upwind integration collects log messages of the following types:

* `Threat detections`: Runtime, API security, and CloudTrail-correlated detections.
* `Vulnerability findings`: CVE findings with runtime reachability and exploitability context.
* `Configuration findings`: Full cloud security posture findings (CSPM), including passed and failed checks and compliance framework context. Each run lists all current findings.

### Supported use cases

Use threat detections to investigate runtime and cloud-control-plane alerts in Elastic Security. Use vulnerability findings to prioritize CVEs that are present on running workloads. Use configuration findings to review the current cloud configuration posture, including passed and failed checks and the frameworks they map to.

## What do I need to use this integration?

### From Upwind

You need an Upwind organization and an API credential that can read threats, vulnerabilities, and configuration findings. To create the credential and collect the required values:

1. Sign in to the Upwind console for your region.
2. Open **Settings → Credentials → Generate Credential**.
3. Choose credential type **API**.
4. Grant read access to threat detections, vulnerability findings, and configuration findings.
5. Copy the **Client ID** and **Client Secret**. The secret is shown only once.
6. Copy the **Organization ID** from organization settings.
7. Note the regional API URL: `https://api.upwind.io` (US), `https://api.eu.upwind.io` (EU), or `https://api.me.upwind.io` (ME).

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

- 401 Unauthorized: The client ID, client secret, or token URL is wrong, or the token audience does not match the API URL region. US credentials cannot call the EU or ME API.
- 403 Forbidden: The API credential does not have read access to that finding type. Update the credential roles in Settings → Credentials.
- 429 Rate limit exceeded: Upwind returned HTTP 429. Increase the polling interval for the affected data stream.
- No threat detections: Confirm detections exist in the lookback window (Initial interval). The list is filtered by last seen time.
- No vulnerability findings: The vulnerability list has no documented time filter and returns pages until the Link header has no rel="next". Confirm the credential can read vulnerabilities and that findings exist in the organization.
- No configuration findings: Confirm the credential can read configuration findings and that posture checks exist in the organization. Each run lists all current PASS and FAIL findings.

## Performance and scaling

Threat detections are collected with a time window rather than page tokens. Vulnerability findings and configuration findings page with `per-page` (default 100). Configuration findings re-list the full posture every 24 hours. Prefer a shorter interval for threat detections than for a full vulnerability or configuration posture sync. Tokens last 24 hours and are refreshed on each poll.

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

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
