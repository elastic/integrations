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

### Supported use cases

- **Audit and compliance monitoring**: Track administrative and user activity within your XM Cyber tenant — including console logins, sensor scan results, and configuration changes — and correlate it with the rest of your security telemetry to support compliance reviews and incident investigations.

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
        "ephemeral_id": "48f59320-c66c-49c4-a540-f8703d0e615f",
        "id": "f0870565-78f4-4a45-98ca-9bb1b9619124",
        "name": "elastic-agent-38790",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "xm_cyber.audit_trail",
        "namespace": "60192",
        "type": "logs"
    },
    "ecs": {
        "version": "9.3.0"
    },
    "elastic_agent": {
        "id": "f0870565-78f4-4a45-98ca-9bb1b9619124",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "action": "xm-login",
        "agent_id_status": "verified",
        "dataset": "xm_cyber.audit_trail",
        "id": "63b47e72ee320700106d4381",
        "ingested": "2026-05-05T12:29:18Z",
        "kind": "event",
        "original": "{\"_id\":\"63b47e72ee320700106d4381\",\"details\":\"john.doe@example.com Logged in via user\",\"eventSubType\":\"XM_LOGIN\",\"eventType\":\"ACCESS\",\"objectName\":\"User\",\"objectType\":\"USER\",\"tenant\":\"acme\",\"terminalId\":{\"hostname\":\"acme.clients.xmcyber.com\",\"ip\":\"192.0.2.0\"},\"timestamp\":\"2023-01-03T19:13:54.358Z\",\"userId\":{\"email\":\"john.doe@example.com\",\"name\":\"John Doe\"}}"
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
            "event_sub_type": "XM_LOGIN",
            "event_type": "ACCESS",
            "object_name": "User",
            "object_type": "USER",
            "tenant": "acme"
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
