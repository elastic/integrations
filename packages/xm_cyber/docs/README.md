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
| `audit_trail` | Audit Records | `/api/audit-trail/auditRecords` |
| `vulnerability` | CVE records from XM Cyber's Vulnerability Risk Management (VRM) feed, including CVSS v2/v3/v4 scores, EPSS metrics, CISA KEV / in-the-wild exploitation flags, and per-CVE counts of devices, products, and critical assets at risk | `/api/v2/vrm/public/vulnerabilities` |

### Supported use cases

- **Audit and compliance monitoring**: Track administrative and user activity within your XM Cyber tenant — including console logins, sensor scan results, and configuration changes — and correlate it with the rest of your security telemetry to support compliance reviews and incident investigations.
- **Risk-based vulnerability prioritization**: Rank CVEs by CVSS impact, EPSS exploit probability, and CISA KEV / in-the-wild exploitation flags to focus remediation effort where it actually reduces business risk.
- **Attack-path-aware exposure analysis**: Correlate detected CVEs with XM Cyber's attack-technique simulations to identify which vulnerabilities act as choke points or stepping stones to crown-jewel assets.

## What do I need to use this integration?

### From Elastic

This integration installs [Elastic latest transforms](https://www.elastic.co/docs/explore-analyze/transforms/transform-overview#latest-transform-overview). For more details, check the [Transform](https://www.elastic.co/docs/explore-analyze/transforms/transform-setup) setup and requirements.

### From XM Cyber

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

#### Transforms healthy

1. In the top search bar in Kibana, search for **Transforms**.
2. Select the **Data / Transforms** from the search results.
3. In the search bar, type **XM Cyber**.
4. All transforms from the search results should indicate **Healthy** under the **Health** column.

An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created for each data stream, to provide a view of the most recent, active XM Cyber data. Use the relevant destination alias from the table below to access the latest data, whether for use in dashboards, rules, or elsewhere.
Destinations indices are aliased to `logs-xm_cyber_latest.<data_stream_name>`.

| Source Data stream                 | Destination Index Pattern                        | Destination Alias                       |
|:-----------------------------------|:-------------------------------------------------|-----------------------------------------|
| `logs-xm_cyber.vulnerability-*`           | `logs-xm_cyber_latest.dest_vulnerability-*`             | `logs-xm_cyber_latest.vulnerability`           |

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Troubleshooting

- **Authentication failures**: Verify the API key is valid and the URL includes the full `https://` prefix with no trailing slash
- **No data collected**: Check the Elastic Agent logs for CEL program errors. Ensure your XM Cyber user has the Security Analyst role and API access is enabled in your tenant settings
- **Rate limiting**: XM Cyber API rate limits are not publicly documented. If you observe HTTP 429 responses in agent logs, increase the collection interval

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

## Reference

### Audit Trail

#### Audit Trail fields

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
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |
| xm_cyber.audit_trail._id | XM Cyber's unique audit record identifier. Preserved when the `preserve_duplicate_custom_fields` tag is set; otherwise mapped to ECS `event.id` and removed from this namespace. | keyword |
| xm_cyber.audit_trail.details | Free-form details about the action. | keyword |
| xm_cyber.audit_trail.event_sub_type | Finer-grained action detail (for example, SettingsChanged, PasswordReset). | keyword |
| xm_cyber.audit_trail.event_type | High-level action performed (for example, Create, Update, Delete, Login). | keyword |
| xm_cyber.audit_trail.object_name | The name or identifier of the object affected. | keyword |
| xm_cyber.audit_trail.object_type | The type of object affected by the action (for example, Policy, User, Scenario). | keyword |
| xm_cyber.audit_trail.tenant | XM Cyber tenant identifier. | keyword |
| xm_cyber.audit_trail.terminal_id.hostname | Hostname of the terminal from which the action originated. | keyword |
| xm_cyber.audit_trail.terminal_id.ip | IP address of the terminal from which the action originated. | ip |
| xm_cyber.audit_trail.terminal_id.ip_string | IP address of the terminal from which the action originated as a string. | keyword |
| xm_cyber.audit_trail.timestamp | Vendor event timestamp. Preserved when the `preserve_duplicate_custom_fields` tag is set; otherwise mapped to ECS `@timestamp` and removed from this namespace. | date |
| xm_cyber.audit_trail.user_id.email | Email of the user who performed the action. | keyword |
| xm_cyber.audit_trail.user_id.name | Display name of the user who performed the action. | keyword |


### Example event

#### Audit Trail

An example event for `audit_trail` looks as following:

```json
{
    "@timestamp": "2023-01-03T19:13:54.358Z",
    "agent": {
        "ephemeral_id": "82c58df4-60d3-4f5e-acfc-8487938b89be",
        "id": "60d4174b-a8ab-4553-87d1-babcd72f3d97",
        "name": "elastic-agent-45805",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "xm_cyber.audit_trail",
        "namespace": "38562",
        "type": "logs"
    },
    "ecs": {
        "version": "9.3.0"
    },
    "elastic_agent": {
        "id": "60d4174b-a8ab-4553-87d1-babcd72f3d97",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "action": "xm-login",
        "agent_id_status": "verified",
        "dataset": "xm_cyber.audit_trail",
        "id": "63b47e72ee320700106d4381",
        "ingested": "2026-06-02T07:28:02Z",
        "kind": "event",
        "original": "{\"_id\":\"63b47e72ee320700106d4381\",\"details\":\"john.doe@example.com Logged in via user\",\"eventSubType\":\"XM_LOGIN\",\"eventType\":\"ACCESS\",\"objectName\":\"User\",\"objectType\":\"USER\",\"tenant\":\"acme\",\"terminalId\":{\"hostname\":\"acme.clients.xmcyber.com\",\"ip\":\"192.0.2.0\"},\"timestamp\":\"2023-01-03T19:13:54.358Z\",\"userId\":{\"email\":\"john.doe@example.com\",\"name\":\"John Doe\"}}",
        "type": [
            "access"
        ]
    },
    "input": {
        "type": "cel"
    },
    "message": "john.doe@example.com Logged in via user",
    "related": {
        "hosts": [
            "acme.clients.xmcyber.com"
        ],
        "ip": [
            "192.0.2.0"
        ],
        "user": [
            "John Doe",
            "john.doe@example.com"
        ]
    },
    "source": {
        "as": {
            "number": 64500,
            "organization": {
                "name": "Documentation ASN"
            }
        },
        "domain": "acme.clients.xmcyber.com",
        "geo": {
            "city_name": "Las Vegas",
            "continent_name": "North America",
            "country_iso_code": "US",
            "country_name": "United States",
            "location": {
                "lat": 36.17497,
                "lon": -115.13722
            },
            "region_iso_code": "US-NV",
            "region_name": "Nevada"
        },
        "ip": "192.0.2.0"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "xm_cyber-audit_trail"
    ],
    "user": {
        "domain": "example.com",
        "email": "john.doe@example.com",
        "name": "John Doe"
    },
    "xm_cyber": {
        "audit_trail": {
            "details": "john.doe@example.com Logged in via user",
            "event_type": "access",
            "object_name": "User",
            "object_type": "USER",
            "tenant": "acme"
        }
    }
}
```

### Vulnerability

#### Vulnerability fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |
| vulnerability.scanner.vendor | The name of the vulnerability scanner vendor. | constant_keyword |
| xm_cyber.vulnerability.choke_point_found_on | Number of choke-point devices where the CVE was detected. | long |
| xm_cyber.vulnerability.critical_assets_at_risk | Number of critical assets reachable via attack paths that include this CVE. | long |
| xm_cyber.vulnerability.critical_assets_found_on | Number of critical-asset devices where the CVE was detected. | long |
| xm_cyber.vulnerability.cvss2 | CVSS v2 base score. Null when the CVE has no v2 score. | double |
| xm_cyber.vulnerability.cvss2vector | CVSS v2 vector string. | keyword |
| xm_cyber.vulnerability.cvss30 | CVSS v3.0 base score. Null when the CVE has no v3.0 score. | double |
| xm_cyber.vulnerability.cvss31 | CVSS v3.1 base score. Null when the CVE has no v3.1 score. | double |
| xm_cyber.vulnerability.cvss31vector | CVSS v3.1 vector string. | keyword |
| xm_cyber.vulnerability.cvss3vector | CVSS v3.0 vector string. | keyword |
| xm_cyber.vulnerability.cvss4 | CVSS v4 base score. Null when the CVE has no v4 score. | double |
| xm_cyber.vulnerability.cvss4vector | CVSS v4 vector string. | keyword |
| xm_cyber.vulnerability.device_found_on | Number of devices on which the CVE was detected in the environment. | long |
| xm_cyber.vulnerability.epss_percentile | Percentile of the current EPSS score — the proportion of all scored vulnerabilities at or below this score. | double |
| xm_cyber.vulnerability.epss_probability | Probability of exploitation in the wild within 30 days, in the range 0..1. | double |
| xm_cyber.vulnerability.epss_score | Raw EPSS exploitation likelihood score, in the range 0..1. | double |
| xm_cyber.vulnerability.exploit_kit_exist | Whether an exploit kit is known to target this CVE. | boolean |
| xm_cyber.vulnerability.has_attack_technique | Whether XM Cyber has built an attack-technique simulation for this vulnerability. | boolean |
| xm_cyber.vulnerability.in_cisa_kev | Whether the vulnerability appears in CISA's Known Exploited Vulnerabilities (KEV) catalog. | boolean |
| xm_cyber.vulnerability.in_exploit_db | Whether public exploit code exists in the Exploit-DB database. | boolean |
| xm_cyber.vulnerability.is_exploited_in_the_wild | Whether real-world exploitation by attackers has been observed. | boolean |
| xm_cyber.vulnerability.products | Number of products affected by the CVE. | long |
| xm_cyber.vulnerability.published_date | Date the CVE was first published in NVD. | date |
| xm_cyber.vulnerability.severity | Numeric severity score returned by the XM Cyber VRM API. | long |
| xm_cyber.vulnerability.status | Current state of the vulnerability in the environment — "Active" or "Remediated". | keyword |
| xm_cyber.vulnerability.technique_id | XM Cyber attack-technique identifier; populated only when has_attack_technique is true. | keyword |


### Example event

#### Vulnerability

An example event for `vulnerability` looks as following:

```json
{
    "@timestamp": "2025-04-03T00:00:00.000Z",
    "agent": {
        "ephemeral_id": "7c001110-ee01-434f-8abf-9dc62adb91e4",
        "id": "51e7c693-87cb-4910-b6d3-23201c6c96c9",
        "name": "elastic-agent-15139",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "xm_cyber.vulnerability",
        "namespace": "40523",
        "type": "logs"
    },
    "ecs": {
        "version": "9.3.0"
    },
    "elastic_agent": {
        "id": "51e7c693-87cb-4910-b6d3-23201c6c96c9",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "vulnerability"
        ],
        "dataset": "xm_cyber.vulnerability",
        "ingested": "2026-06-08T08:55:00Z",
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
            "cvss2": 9.3,
            "cvss2vector": "AV:N/AC:M/Au:N/C:C/I:C/A:C",
            "cvss31": 7.8,
            "cvss31vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            "device_found_on": 17,
            "epss_percentile": 0.99132,
            "epss_probability": 0.80235,
            "epss_score": 0.80235,
            "exploit_kit_exist": true,
            "has_attack_technique": false,
            "in_cisa_kev": true,
            "in_exploit_db": true,
            "is_exploited_in_the_wild": true,
            "products": 1,
            "published_date": "2016-05-11T00:00:00.000Z",
            "severity": 30,
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
| `/api/audit-trail/auditRecords` | GET | `audit_trail` | Audit Records |
| `/api/v2/vrm/public/vulnerabilities` | GET | `vulnerabilities` | Paginated exposure rows (attack techniques / CVE context) |

### ILM Policy

To facilitate vulnerability data stream-backed indices `.ds-logs-xm_cyber.vulnerability-*` is allowed to contain duplicates from each polling interval. ILM policies `logs-xm_cyber.vulnerability-default_policy` is added to these source indices, so it doesn't lead to unbounded growth. This means that in these source indices data will be deleted after `30 days` from ingested date.