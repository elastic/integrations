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
| `risk_score` | Organization-level security grade (A–F), numeric risk score, trend data, and per-scenario breakdowns | `/api/scenarios/v2/scenarios/riskScore` |

### Supported use cases

- **Security posture tracking**: Monitor your organization's XM Cyber risk score over time and correlate score changes with security events.

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
   - **Resolution**: Number of days used to aggregate the risk score results.
   - **Interval**: How often to poll for new data (default: `24h`).
   - **Initial interval**: Time period to fetch risk score data for. Accepts a number of days (e.g. `30`) for a rolling window, or `YYYY_MM` (e.g. `2025_12`) for a specific month (default: `30`).
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

### Risk Score

#### Risk Score fields

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
| labels.risk_grade | The risk grade of the scenario. | keyword |
| labels.risk_score | The risk score of the scenario as a keyword label. | keyword |
| labels.scenario_name | The name of the scenario. | keyword |
| log.offset | Log offset. | long |
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |
| xm_cyber.risk_score.avg_graph_data.date |  | date |
| xm_cyber.risk_score.avg_graph_data.grade |  | keyword |
| xm_cyber.risk_score.avg_graph_data.score |  | float |
| xm_cyber.risk_score.resolution |  | integer |
| xm_cyber.risk_score.scenario.grade |  | keyword |
| xm_cyber.risk_score.scenario.graph_data.campaigns |  | flattened |
| xm_cyber.risk_score.scenario.graph_data.from_date |  | date |
| xm_cyber.risk_score.scenario.graph_data.grade |  | keyword |
| xm_cyber.risk_score.scenario.graph_data.score |  | float |
| xm_cyber.risk_score.scenario.graph_data.to_date |  | date |
| xm_cyber.risk_score.scenario.id |  | keyword |
| xm_cyber.risk_score.scenario.name |  | keyword |
| xm_cyber.risk_score.scenario.score |  | keyword |
| xm_cyber.risk_score.stats.grade |  | keyword |
| xm_cyber.risk_score.stats.score |  | float |
| xm_cyber.risk_score.stats.trend |  | long |
| xm_cyber.risk_score.time_id | The time window for the risk score report. | keyword |


### Example event

#### Risk Score

An example event for `risk_score` looks as following:

```json
{
    "@timestamp": "2026-04-30T19:04:31.382Z",
    "agent": {
        "ephemeral_id": "117b1793-d1a3-4a23-84a2-d5e2f048736b",
        "id": "22d5005f-3d7b-4c0a-abc1-1c4d5b4ed69f",
        "name": "elastic-agent-61174",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "xm_cyber.risk_score",
        "namespace": "66457",
        "type": "logs"
    },
    "ecs": {
        "version": "9.3.0"
    },
    "elastic_agent": {
        "id": "22d5005f-3d7b-4c0a-abc1-1c4d5b4ed69f",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "xm_cyber.risk_score",
        "ingested": "2026-04-30T19:04:34Z",
        "kind": "event",
        "original": "{\"avgGraphData\":[{\"date\":\"2025-12-03T00:00:00.000Z\",\"grade\":\"A\",\"score\":95}],\"scenario\":{\"grade\":\"B\",\"graphData\":[{\"campaigns\":null,\"fromDate\":\"2025-12-02T00:00:00.000Z\",\"grade\":\"A\",\"score\":95,\"toDate\":\"2025-12-03T00:00:00.000Z\"}],\"id\":\"02D8\",\"name\":\"(LG) Workstation to Servers\",\"score\":82},\"stats\":{\"grade\":\"A\",\"score\":90,\"trend\":1}}"
    },
    "input": {
        "type": "cel"
    },
    "labels": {
        "risk_grade": "B",
        "risk_score": "82",
        "scenario_name": "(LG) Workstation to Servers"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "xm_cyber-risk_score"
    ],
    "xm_cyber": {
        "risk_score": {
            "avg_graph_data": [
                {
                    "date": "2025-12-03T00:00:00.000Z",
                    "grade": "A",
                    "score": 95
                }
            ],
            "scenario": {
                "grade": "B",
                "graph_data": [
                    {
                        "from_date": "2025-12-02T00:00:00.000Z",
                        "grade": "A",
                        "score": 95,
                        "to_date": "2025-12-03T00:00:00.000Z"
                    }
                ],
                "id": "02D8",
                "name": "(LG) Workstation to Servers",
                "score": "82"
            },
            "stats": {
                "grade": "A",
                "score": 90,
                "trend": 1
            }
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
| `/api/scenarios/v2/scenarios/riskScore` | GET | `risk_score` | Organization risk score and grade |
