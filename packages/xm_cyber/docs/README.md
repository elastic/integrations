# XM Cyber Integration

## Overview

[XM Cyber](https://www.xmcyber.com) is a **Continuous Threat Exposure Management (CTEM)** and attack path management platform. It continuously simulates attacker movement across hybrid environments including on-premises, cloud, and identity infrastructure — combining vulnerabilities, misconfigurations, and overly permissive access into prioritized attack paths that lead to **critical assets**.

This integration collects data from the XM Cyber REST API using scheduled polling. It provides visibility into your organization's security posture across your environment.

### Compatibility

The XM Cyber integration is compatible with the API version **1.0.0**.

### How it works

The integration uses the Elastic Agent CEL (Common Expression Language) input to poll the XM Cyber REST API on a configurable schedule. Each poll:

1. Authenticates with a two-step flow: exchanges the API key for a short-lived Bearer access token via `POST /api/auth`
2. Fetches data from the configured endpoint.
3. Emits each record as an individual event for ingestion and enrichment via the built-in ingest pipeline

## What data does this integration collect?

The XM Cyber integration collects the following types of data:

| Data stream | Description | Endpoint |
|---|---|---|
| `vulnerability` | CVE records from XM Cyber's Vulnerability Risk Management (VRM) feed, including CVSS v2/v3/v4 scores, EPSS metrics, CISA KEV / in-the-wild exploitation flags, and per-CVE counts of devices, products, and critical assets at risk | `/api/v2/vrm/public/vulnerabilities` |

### Supported use cases

- **Risk-based vulnerability prioritization**: Rank CVEs by CVSS impact, EPSS exploit probability, and CISA KEV / in-the-wild exploitation flags to focus remediation effort where it actually reduces business risk.
- **Attack-path-aware exposure analysis**: Correlate detected CVEs with XM Cyber's attack-technique simulations to identify which vulnerabilities act as choke points or stepping stones to crown-jewel assets.

## What do I need to use this integration?

- **XM Cyber tenant**: An active XM Cyber deployment with access to `https://<your-org>.clients.xmcyber.com`
- **API key**: An XM Cyber API key associated with a user holding at minimum the **Security Analyst** role. Create one in **Settings → API / Integrations** in your XM Cyber admin console (refer to the XM Cyber customer portal at https://customers.xmcyber.com for current navigation steps)
- **Elastic Agent**: Version 8.18+ or 9.0+ with Fleet enrollment

## How do I deploy this integration?

This integration supports both Elastic Agentless-based and Agent-based installations.

### Agentless-based installation

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

### Configure

1. In Kibana, navigate to **Fleet → Integrations** and search for **XM Cyber**
2. Click **Add XM Cyber**
3. Configure the integration settings:
   - **URL**: Your XM Cyber base URL, for example `https://your-org.clients.xmcyber.com`
   - **API Key**: Your XM Cyber API key.
   - **Interval**: How often to poll for new data (default: `24h`).
4. Select **Save and continue** to save the integration.

### Validation

#### Dashboard populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **XM Cyber**, and verify the dashboard information is populated.

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Troubleshooting

- **Authentication failures**: Verify the API key is valid and the URL includes the full `https://` prefix with no trailing slash
- **No data collected**: Check the Elastic Agent logs for CEL program errors. Ensure your XM Cyber user has the Security Analyst role and API access is enabled in your tenant settings
- **Rate limiting**: XM Cyber API rate limits are not publicly documented. If you observe HTTP 429 responses in agent logs, increase the collection interval

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

## Reference

### Vulnerability

#### Vulnerability fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |
| vulnerability.scanner.vendor | The name of the vulnerability scanner vendor. | constant_keyword |
| xm_cyber.vulnerability.choke_point_found_on | Number of choke-point devices where the CVE was detected. | long |
| xm_cyber.vulnerability.critical_assets_at_risk | Number of critical assets reachable via attack paths that include this CVE. | long |
| xm_cyber.vulnerability.critical_assets_found_on | Number of critical-asset devices where the CVE was detected. | long |
| xm_cyber.vulnerability.cve | The CVE ID assigned by NVD (e.g. CVE-2009-0316). | keyword |
| xm_cyber.vulnerability.cvss2 | CVSS v2 base score. Null when the CVE has no v2 score. | double |
| xm_cyber.vulnerability.cvss2vector | CVSS v2 vector string. | keyword |
| xm_cyber.vulnerability.cvss30 | CVSS v3.0 base score. Null when the CVE has no v3.0 score. | double |
| xm_cyber.vulnerability.cvss31 | CVSS v3.1 base score. Null when the CVE has no v3.1 score. | double |
| xm_cyber.vulnerability.cvss31vector | CVSS v3.1 vector string. | keyword |
| xm_cyber.vulnerability.cvss3vector | CVSS v3.0 vector string. | keyword |
| xm_cyber.vulnerability.cvss4 | CVSS v4 base score. Null when the CVE has no v4 score. | double |
| xm_cyber.vulnerability.cvss4vector | CVSS v4 vector string. | keyword |
| xm_cyber.vulnerability.description | The official catalog description of the CVE. | match_only_text |
| xm_cyber.vulnerability.device_found_on | Number of devices on which the CVE was detected in the environment. | long |
| xm_cyber.vulnerability.epss_percentile | Percentile of the current EPSS score — the proportion of all scored vulnerabilities at or below this score. | double |
| xm_cyber.vulnerability.epss_probability | Probability of exploitation in the wild within 30 days, in the range 0..1. | double |
| xm_cyber.vulnerability.epss_score | Raw EPSS exploitation likelihood score, in the range 0..1. | double |
| xm_cyber.vulnerability.exploit_kit_exist | Whether an exploit kit is known to target this CVE. | boolean |
| xm_cyber.vulnerability.first_detected | First time the CVE was observed in the environment. | date |
| xm_cyber.vulnerability.has_attack_technique | Whether XM Cyber has built an attack-technique simulation for this vulnerability. | boolean |
| xm_cyber.vulnerability.in_cisa_kev | Whether the vulnerability appears in CISA's Known Exploited Vulnerabilities (KEV) catalog. | boolean |
| xm_cyber.vulnerability.in_exploit_db | Whether public exploit code exists in the Exploit-DB database. | boolean |
| xm_cyber.vulnerability.is_exploited_in_the_wild | Whether real-world exploitation by attackers has been observed. | boolean |
| xm_cyber.vulnerability.products | Number of products affected by the CVE. | long |
| xm_cyber.vulnerability.published_date | Date the CVE was first published in NVD. | date |
| xm_cyber.vulnerability.severity | Numeric severity score returned by the XM Cyber VRM API. | long |
| xm_cyber.vulnerability.severity_level | Qualitative severity level — one of Unknown, Low, Medium, High, or Critical. | keyword |
| xm_cyber.vulnerability.status | Current state of the vulnerability in the environment — "Active" or "Remediated". | keyword |
| xm_cyber.vulnerability.technique_id | XM Cyber attack-technique identifier; populated only when has_attack_technique is true. | keyword |


### Example event

#### Vulnerability

An example event for `vulnerability` looks as following:

```json
{
    "@timestamp": "2025-04-03T00:00:00.000Z",
    "agent": {
        "ephemeral_id": "88f07f8d-4aeb-4b73-ba5e-850b690ee6fd",
        "id": "5af01e0c-8792-477e-803d-05713ecaec17",
        "name": "elastic-agent-17144",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "xm_cyber.vulnerability",
        "namespace": "59616",
        "type": "logs"
    },
    "ecs": {
        "version": "9.3.0"
    },
    "elastic_agent": {
        "id": "5af01e0c-8792-477e-803d-05713ecaec17",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "vulnerability"
        ],
        "dataset": "xm_cyber.vulnerability",
        "ingested": "2026-05-12T11:52:59Z",
        "kind": "event",
        "original": "{\"chokePointFoundOn\":4,\"criticalAssetsAtRisk\":33,\"criticalAssetsFoundOn\":17,\"cve\":\"CVE-2016-0185\",\"cvss2\":9.3,\"cvss2Vector\":\"AV:N/AC:M/Au:N/C:C/I:C/A:C\",\"cvss30\":null,\"cvss31\":7.8,\"cvss31Vector\":\"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H\",\"cvss3Vector\":null,\"cvss4\":null,\"cvss4Vector\":null,\"description\":\"Media Center in Microsoft Windows Vista SP2, Windows 7 SP1, and Windows 8.1 allows remote attackers to execute arbitrary code via a crafted Media Center link (aka .mcl) file, aka 'Windows Media Center Remote Code Execution Vulnerability.'\",\"deviceFoundOn\":17,\"epssPercentile\":0.99132,\"epssProbability\":0.80235,\"epssScore\":0.80235,\"exploitKitExist\":true,\"firstDetected\":\"2025-04-03T00:00:00.000Z\",\"hasAttackTechnique\":false,\"inCisaKev\":true,\"inExploitDb\":true,\"isExploitedInTheWild\":true,\"products\":1,\"publishedDate\":\"2016-05-11T00:00:00.000Z\",\"severity\":30,\"severityLevel\":\"High\",\"status\":\"Active\",\"techniqueId\":null}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "cel"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "xm_cyber-vulnerability"
    ],
    "vulnerability": {
        "classification": "CVSS",
        "description": "Media Center in Microsoft Windows Vista SP2, Windows 7 SP1, and Windows 8.1 allows remote attackers to execute arbitrary code via a crafted Media Center link (aka .mcl) file, aka 'Windows Media Center Remote Code Execution Vulnerability.'",
        "enumeration": "CVE",
        "id": "CVE-2016-0185",
        "score": {
            "base": 7.8,
            "version": "3.1"
        },
        "severity": "high"
    },
    "xm_cyber": {
        "vulnerability": {
            "choke_point_found_on": 4,
            "critical_assets_at_risk": 33,
            "critical_assets_found_on": 17,
            "cve": "CVE-2016-0185",
            "cvss2": 9.3,
            "cvss2vector": "AV:N/AC:M/Au:N/C:C/I:C/A:C",
            "cvss31": 7.8,
            "cvss31vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            "description": "Media Center in Microsoft Windows Vista SP2, Windows 7 SP1, and Windows 8.1 allows remote attackers to execute arbitrary code via a crafted Media Center link (aka .mcl) file, aka 'Windows Media Center Remote Code Execution Vulnerability.'",
            "device_found_on": 17,
            "epss_percentile": 0.99132,
            "epss_probability": 0.80235,
            "epss_score": 0.80235,
            "exploit_kit_exist": true,
            "first_detected": "2025-04-03T00:00:00.000Z",
            "has_attack_technique": false,
            "in_cisa_kev": true,
            "in_exploit_db": true,
            "is_exploited_in_the_wild": true,
            "products": 1,
            "published_date": "2016-05-11T00:00:00.000Z",
            "severity": 30,
            "severity_level": "High",
            "status": "Active"
        }
    }
}
```

### Inputs used

These inputs can be used with this integration:
<details>
<summary>cel</summary>

## Setup

For more details about the CEL input settings, check the [Filebeat documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-cel.html).

Before configuring the CEL input, make sure you have:
- Network connectivity to the target API endpoint
- Valid authentication credentials (API keys, tokens, or certificates as required)
- Appropriate permissions to read from the target data source

### Collecting logs from CEL

To configure the CEL input, you must specify the `request.url` value pointing to the API endpoint. The interval parameter controls how frequently requests are made and is the primary way to balance data freshness with API rate limits and costs. Authentication is often configured through the `request.headers` section using the appropriate method for the service.

NOTE: To access the API service, make sure you have the necessary API credentials and that the Filebeat instance can reach the endpoint URL. Some services may require IP whitelisting or VPN access.

To collect logs via API endpoint, configure the following parameters:

- API Endpoint URL
- API credentials (tokens, keys, or username/password)
- Request interval (how often to fetch data)
</details>


### API usage

These XM Cyber REST API endpoints are used by this integration:

| Endpoint | Method | Data stream | Description |
|---|---|---|---|
| `/api/auth` | POST | all | Exchange API key for Bearer access token |
| `/api/refresh-token` | POST | all | Refresh an expired access token |
| `/api/v2/vrm/public/vulnerabilities` | GET | `vulnerabilities` | Paginated exposure rows (attack techniques / CVE context) |
