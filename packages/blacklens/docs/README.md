# blacklens.io

The [blacklens.io](https://blacklens.io) integration allows you to monitor alerts. blacklens.io is a comprehensive Attack Surface Management platform that helps businesses understand and secure their external attack surface. By combining automated security analysis, continuous monitoring, and penetration testing, it identifies and addresses vulnerabilities early. With features like Darknet Monitoring, Vulnerability Scanning, and XDR Response, blacklens.io provides a proactive defense strategy to protect companies from cyber threats while offering a clear view of their security posture at all times.

Use the blacklens.io integration to fetch all related alerts about your Attack Surface. Then visualize that data in Kibana and create further alerts or enrich the data with other security solutions.

## Data streams

The blacklens.io integration collects one type of data streams: logs

**Alerts** returns a list of blacklens.io alerts (The API Docs are referenced within the portal)
## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.
You will require the `alerts:read` permission in order to fetch the Alerts via the API.

You need an active blacklens.io subscription and a user with the `alerts:read` permission to retrieve alerts via the API.

## Setup

### Copy blacklens.io required configuration properties

1. Login to your blacklens.io Portal (This URL will be used for the Instance URL: 'https://portal-(ID).blacklens.io')
2. Go to **Profile → Generate API Key** and copy it. 
3. Go to **Settings → Company**.
4. Copy **ws_id** and **tenant_id**.

### Enable the blacklens.io Integration in Elastic

1. In Kibana go to Management > Integrations.
2. In "Search for integrations" search bar, type blacklens.io.
3. Click on the "blacklens.io" integration from the search results.
4. Click on the "Add blacklens.io" button to add the integration.
5. Configure all required integration parameters. 
    - Alert data requires following parameters:
        - `URL`
        - `Tenant ID (tenant_id)`
        - `Workspace ID (ws_id)`
        - `API Key`
6. Save the integration.

For detailed setup instructions, please refer to the blacklens.io Knowledge Base (The link is referenced within the portal).

## Logs reference

### alerts

This is the `alerts` dataset

#### Example

An example event for `alerts` looks as following:

```json
{
    "@timestamp": "2026-02-03T06:17:57.260Z",
    "agent": {
        "ephemeral_id": "23a29ca3-cffa-4f55-9ef4-536308f22c95",
        "id": "6bcec12d-6281-4434-99e0-eb2f7c014fbf",
        "name": "elastic-agent-84667",
        "type": "filebeat",
        "version": "8.19.10"
    },
    "blacklens": {
        "alert": {
            "activities": [
                {
                    "category": "threat",
                    "created_date": "2026-02-03T06:17:57.260Z",
                    "description": "A Critical severity external vulnerability 'Blind SQL Injection via HTTP Header' has been detected on asset 'demo.example.com'",
                    "id": "3fa85f64-5717-4562-b3fc-2c963f66afa5",
                    "trace_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                    "type": "ExternalVulnerabilityCreated",
                    "updated_date": "2026-02-03T06:17:57.260Z"
                }
            ],
            "analysis": "ongoing",
            "category": "vulnerability",
            "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
            "name": "External Vulnerability",
            "severity": "medium",
            "status": "new",
            "updated_date": "2026-02-03T06:17:57.260Z"
        }
    },
    "data_stream": {
        "dataset": "blacklens.alerts",
        "namespace": "43517",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "6bcec12d-6281-4434-99e0-eb2f7c014fbf",
        "snapshot": false,
        "version": "8.19.10"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2026-03-31T08:58:43.557Z",
        "dataset": "blacklens.alerts",
        "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
        "ingested": "2026-03-31T08:58:46Z",
        "kind": "alert",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "tags": [
        "forwarded",
        "blacklens-alert"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| blacklens.alert.activities.category |  | keyword |
| blacklens.alert.activities.created_date |  | date |
| blacklens.alert.activities.data |  | nested |
| blacklens.alert.activities.description |  | keyword |
| blacklens.alert.activities.id |  | keyword |
| blacklens.alert.activities.trace_id |  | keyword |
| blacklens.alert.activities.type |  | keyword |
| blacklens.alert.activities.updated_date |  | date |
| blacklens.alert.analysis | Determines whether the current alert triggers further events | keyword |
| blacklens.alert.category | Alert category | keyword |
| blacklens.alert.id | Unique Alert ID | keyword |
| blacklens.alert.name | Name of the given Alert | keyword |
| blacklens.alert.severity | Alert Severity | keyword |
| blacklens.alert.status | Current Status of the Alert | keyword |
| blacklens.alert.updated_date | Activity last updated time (UTC). | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| observer.product |  | constant_keyword |
| observer.vendor |  | constant_keyword |
