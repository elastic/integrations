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
    "@timestamp": "2024-11-12T09:39:58.489Z",
    "agent": {
        "ephemeral_id": "33939e93-54ef-4184-b92b-bc8f02e179a6",
        "id": "f98f4444-6fca-4500-83b6-a8c5e8f32bf1",
        "name": "elastic-agent-49577",
        "type": "filebeat",
        "version": "8.15.2"
    },
    "blacklens": {
        "alert": {
            "id": 1001,
            "outcome": "affected",
            "severity": "medium",
            "status": "resolved",
            "title": "New Open Port",
            "type": "Port Scanner",
            "type_id": 100,
            "updated_date": "2024-11-12T09:39:58.489Z"
        }
    },
    "data_stream": {
        "dataset": "blacklens.alerts",
        "namespace": "41265",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "f98f4444-6fca-4500-83b6-a8c5e8f32bf1",
        "snapshot": false,
        "version": "8.15.2"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2025-12-09T05:45:05.855Z",
        "dataset": "blacklens.alerts",
        "id": "1001",
        "ingested": "2025-12-09T05:45:08Z",
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
| blacklens.alert.details | Alert Details | nested |
| blacklens.alert.id | Unique Alert ID | integer |
| blacklens.alert.outcome | Determines whether the current alert triggers further events | keyword |
| blacklens.alert.severity | Alert Severity | keyword |
| blacklens.alert.status | Current Status of the Alert | keyword |
| blacklens.alert.title | Title/Description of the given Alert | keyword |
| blacklens.alert.type | Alert Type (Engine) | keyword |
| blacklens.alert.type_id | Alert Type ID (Engine) | integer |
| blacklens.alert.updated_date | Activity last updated time (UTC). | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.kind |  | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| observer.product |  | constant_keyword |
| observer.vendor |  | constant_keyword |
