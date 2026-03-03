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
    "input": {
        "type": "httpjson"
    },
    "agent": {
        "name": "example-agent",
        "id": "example-agent-id-12345",
        "type": "filebeat",
        "ephemeral_id": "ephemeral-id-12345",
        "version": "8.15.2"
    },
    "@timestamp": "2024-11-07T08:09:22.094Z",
    "ecs": {
        "version": "8.11.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "logs",
        "dataset": "blacklens.alerts"
    },
    "elastic_agent": {
        "id": "example-agent-id-12345",
        "version": "8.15.2",
        "snapshot": false
    },
    "host": {
        "name": "example-host"
    },
    "blacklens": {
        "alert": {
            "severity": "info",
            "type_id": 1001,
            "details": [],
            "updated_date": "2024-08-14T15:06:13.151Z",
            "id": 12345,
            "type": "Example Threat System (ETS)",
            "title": "Example Threat Scan Notification",
            "outcome": "undefined",
            "status": "resolved"
        }
    },
    "message": "{\"affected_entities\":null,\"alert_outcome\":\"undefined\",\"alert_payload\":[],\"reference\":\"https://example.com/reference123\"}],\"alert_status\":\"resolved\",\"created_date\":\"2024-11-07T08:09:22.094028Z\",\"customer_state\":\"open\",\"details\":{\"engine\":\"Example Threat System (ETS)\",\"id\":1001,\"title\":\"Example Threat Scan Notification\"},\"id\":12345,\"severity\":\"info\",\"type_id\":1001,\"updated_date\":\"2024-08-14T15:06:13.151728Z\"}",
    "event": {
        "id": 12345,
        "agent_id_status": "verified",
        "ingested": "2024-11-07T09:45:30Z",
        "created": "2024-11-07T09:45:29.354Z",
        "kind": "alert",
        "category": [
            "threat"
        ],
        "type": [
            "indicator"
        ],
        "dataset": "blacklens.alerts"
    },
    "tags": [
        "forwarded",
        "example-alert"
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
