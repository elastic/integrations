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
| `device` | Device inventory from XM Cyber VRM: identity (device id, name, type), network and directory context (IP, subnet, FQDN, domain, OU, OS), choke-point and critical-asset flags, aggregate vulnerability counts and max CVSS scores, XM Cyber risk score, per-device installed applications with active CVEs and remediation hints | `/api/v2/vrm/public/devices` |

### Supported use cases

- **Hybrid device inventory**: Track which assets XM Cyber has discovered, how they are classified, and how they are labeled across on-premises and cloud footprints.
- **Exposure-aware asset triage**: Use choke-point and critical-asset signals together with per-device vulnerability counts and max CVSS to prioritize which hosts warrant review first.
- **Application-level context**: Inspect installed products under each device, including active CVEs, closed CVEs, and suggested safe versions where the API provides them.

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

### Device

#### Device fields

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
| xm_cyber.device.affected_entities | Number of related entities affected for this device context. | long |
| xm_cyber.device.apps.active_cves | CVE identifiers currently active for this application. | keyword |
| xm_cyber.device.apps.active_cves_safe_version.cve | CVE identifier. | keyword |
| xm_cyber.device.apps.active_cves_safe_version.safe_version | Vendor-recommended safe version for the CVE. | keyword |
| xm_cyber.device.apps.affected_critical_assets | Number of critical assets affected by this application exposure. | long |
| xm_cyber.device.apps.choke_point_found_on | Vendor count of choke-point occurrences for this app; may be sent as a numeric string (e.g. "4") from the API. | keyword |
| xm_cyber.device.apps.closed_cves | CVE identifiers remediated or closed for this application. | keyword |
| xm_cyber.device.apps.device_found_on | Number of devices where this application instance was observed. | long |
| xm_cyber.device.apps.name | Application or product display name. | keyword |
| xm_cyber.device.apps.product_operating_systems | Operating systems on which the product is reported. | keyword |
| xm_cyber.device.apps.product_vulnerabilities | Count of vulnerabilities associated with the product. | long |
| xm_cyber.device.apps.products_critical_assets_at_risk | Critical assets at risk attributed to this product context. | long |
| xm_cyber.device.apps.vendor | Application vendor. | keyword |
| xm_cyber.device.apps.version | Installed application version. | keyword |
| xm_cyber.device.choke_point_level | Qualitative choke-point level (e.g. text tier from the API). | keyword |
| xm_cyber.device.choke_point_score | Numeric choke-point score from XM Cyber. | long |
| xm_cyber.device.critical_assets_at_risk | Count of critical assets at risk in relation to this device. | long |
| xm_cyber.device.critical_vulnerabilities | Count of critical-severity vulnerabilities on the device. | long |
| xm_cyber.device.device_id | XM Cyber device identifier. | keyword |
| xm_cyber.device.device_name | Human-readable device name. | keyword |
| xm_cyber.device.device_type | XM Cyber device type classification. | keyword |
| xm_cyber.device.domain | Active Directory or DNS domain name. | keyword |
| xm_cyber.device.enitity_vulnerabilities | Entity vulnerability count as returned by the API (vendor field name retains the historical spelling "enitity"). | long |
| xm_cyber.device.enrichment_labels | Enrichment labels applied by XM Cyber. | keyword |
| xm_cyber.device.fqdn | Fully qualified domain name when present. | keyword |
| xm_cyber.device.high_vulnerabilities | Count of high-severity vulnerabilities on the device. | long |
| xm_cyber.device.ip_address | Primary IP address associated with the device. | ip |
| xm_cyber.device.is_choke_point | Whether the device is classified as a choke point. | boolean |
| xm_cyber.device.is_critical_asset | Whether the device is treated as a critical asset. | boolean |
| xm_cyber.device.labels | Vendor-supplied labels attached to the device. | keyword |
| xm_cyber.device.last_compromised | Timestamp of the last simulated or observed compromise when provided; may be absent. | date |
| xm_cyber.device.last_scan | Timestamp of the last vulnerability or inventory scan for the device. | date |
| xm_cyber.device.low_vulnerabilities | Count of low-severity vulnerabilities on the device. | long |
| xm_cyber.device.max_cvss_v2 | Maximum CVSS v2 base score observed on the device. | double |
| xm_cyber.device.max_cvss_v3 | Maximum CVSS v3.0 base score observed on the device. | double |
| xm_cyber.device.max_cvss_v31 | Maximum CVSS v3.1 base score observed on the device. | double |
| xm_cyber.device.max_cvss_v4 | Maximum CVSS v4 base score observed on the device. | double |
| xm_cyber.device.medium_vulnerabilities | Count of medium-severity vulnerabilities on the device. | long |
| xm_cyber.device.os | Operating system string reported for the device. | keyword |
| xm_cyber.device.ou | Organizational unit path or label. | keyword |
| xm_cyber.device.products | Number of distinct products detected on the device. | long |
| xm_cyber.device.risk_score | XM Cyber risk score for the device. | long |
| xm_cyber.device.subnet | Subnet associated with the device. | keyword |
| xm_cyber.device.type | Device type or category label from the vendor payload. | keyword |
| xm_cyber.device.unknown_vulnerabilities | Count of unknown-severity vulnerabilities on the device. | long |


### Example event

#### Device

An example event for `device` looks as following:

```json
{
    "@timestamp": "2026-05-12T21:54:01.641Z",
    "agent": {
        "ephemeral_id": "d88b8d75-6321-404c-92a8-1febc18a0613",
        "id": "24682501-b6a3-42b9-af38-a00183310701",
        "name": "elastic-agent-69008",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "xm_cyber.device",
        "namespace": "16844",
        "type": "logs"
    },
    "device": {
        "id": "1017176037145946592",
        "type": "Workstation"
    },
    "ecs": {
        "version": "9.3.0"
    },
    "elastic_agent": {
        "id": "24682501-b6a3-42b9-af38-a00183310701",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "host"
        ],
        "dataset": "xm_cyber.device",
        "ingested": "2026-05-13T10:12:50Z",
        "kind": "event",
        "original": "{\"affectedEntities\":4,\"apps\":[{\"activeCves\":[\"CVE-2023-0001\"],\"activeCvesSafeVersion\":[{\"cve\":\"CVE-2023-0001\",\"safeVersion\":\"2.0.0\"}],\"affectedCriticalAssets\":0,\"chokePointFoundOn\":\"1\",\"closedCves\":[],\"deviceFoundOn\":2,\"name\":\"Example Product\",\"productOperatingSystems\":[\"Windows\"],\"productVulnerabilities\":3,\"productsCriticalAssetsAtRisk\":1,\"vendor\":\"VendorCo\",\"version\":\"1.2.3\"}],\"chokePointLevel\":\"Critical\",\"chokePointScore\":100,\"criticalAssetsAtRisk\":2,\"criticalVulnerabilities\":2,\"deviceId\":\"1017176037145946592\",\"deviceName\":\"Hugh\",\"deviceType\":\"Workstation\",\"domain\":\"corp.example.com\",\"enitityVulnerabilities\":1,\"enrichmentLabels\":[\"enriched\"],\"fqdn\":\"hugh.corp.example.com\",\"highVulnerabilities\":5,\"ipAddress\":\"192.168.1.10\",\"isChokePoint\":true,\"isCriticalAsset\":true,\"labels\":[\"lab\",\"xm-cyber-test\"],\"lastCompromised\":null,\"lastScan\":\"2026-05-12T21:54:01.641Z\",\"lowVulnerabilities\":3,\"maxCvssV2\":8,\"maxCvssV3\":9.1,\"maxCvssV31\":8.8,\"maxCvssV4\":7.2,\"mediumVulnerabilities\":10,\"os\":\"Windows 11\",\"ou\":\"OU=Workstations,DC=corp,DC=example,DC=com\",\"products\":5,\"riskScore\":75,\"subnet\":\"192.168.1.0/24\",\"type\":\"Endpoint\",\"unknownVulnerabilities\":0}",
        "type": [
            "info"
        ]
    },
    "host": {
        "domain": "corp.example.com",
        "hostname": "Hugh",
        "id": "1017176037145946592",
        "ip": [
            "192.168.1.10"
        ],
        "name": "hugh.corp.example.com",
        "os": {
            "full": "Windows 11"
        },
        "type": "Workstation"
    },
    "input": {
        "type": "cel"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "xm_cyber-device"
    ],
    "vulnerability": {
        "classification": "CVSS",
        "score": {
            "base": 7.2,
            "version": "4.0"
        }
    },
    "xm_cyber": {
        "device": {
            "affected_entities": 4,
            "apps": [
                {
                    "active_cves": [
                        "CVE-2023-0001"
                    ],
                    "active_cves_safe_version": [
                        {
                            "cve": "CVE-2023-0001",
                            "safe_version": "2.0.0"
                        }
                    ],
                    "affected_critical_assets": 0,
                    "choke_point_found_on": "1",
                    "device_found_on": 2,
                    "name": "Example Product",
                    "product_operating_systems": [
                        "Windows"
                    ],
                    "product_vulnerabilities": 3,
                    "products_critical_assets_at_risk": 1,
                    "vendor": "VendorCo",
                    "version": "1.2.3"
                }
            ],
            "choke_point_level": "Critical",
            "choke_point_score": 100,
            "critical_assets_at_risk": 2,
            "critical_vulnerabilities": 2,
            "device_id": "1017176037145946592",
            "device_name": "Hugh",
            "device_type": "Workstation",
            "domain": "corp.example.com",
            "enitity_vulnerabilities": 1,
            "enrichment_labels": [
                "enriched"
            ],
            "fqdn": "hugh.corp.example.com",
            "high_vulnerabilities": 5,
            "ip_address": "192.168.1.10",
            "is_choke_point": true,
            "is_critical_asset": true,
            "labels": [
                "lab",
                "xm-cyber-test"
            ],
            "last_scan": "2026-05-12T21:54:01.641Z",
            "low_vulnerabilities": 3,
            "max_cvss_v2": 8,
            "max_cvss_v3": 9.1,
            "max_cvss_v31": 8.8,
            "max_cvss_v4": 7.2,
            "medium_vulnerabilities": 10,
            "os": "Windows 11",
            "ou": "OU=Workstations,DC=corp,DC=example,DC=com",
            "products": 5,
            "risk_score": 75,
            "subnet": "192.168.1.0/24",
            "type": "Endpoint",
            "unknown_vulnerabilities": 0
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
| `/api/v2/vrm/public/devices` | GET | `device` | Paginated device inventory with vulnerability aggregates and per-application CVE context |
