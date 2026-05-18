# Doppel Integration for Elastic

## Overview
The Doppel integration for Elastic enables the automated collection of security alerts directly from the Doppel API. By ingesting these alerts into the Elastic Common Schema (ECS), security teams can centralize their threat monitoring, perform cross-source correlation, and visualize Doppel data within Kibana dashboards.

### Compatibility
This integration is compatible with the Doppel API v1 and Elastic Stack version 8.12.0 or higher.

### How it works
This integration uses the `httpjson` input to periodically poll the Doppel `/v1/alerts` endpoint. It uses a cursor-based polling mechanism (stateful) to ensure that only new or updated alerts are ingested, minimizing API overhead and preventing data gaps.

## What data does this integration collect?
The Doppel integration collects security alerts, including:
* **Alert Metadata:** IDs, creation timestamps, and last activity timestamps.
* **Threat Indicators:** Targeted entities, domains, and associated IP addresses.
* **Contextual Data:** Severity levels, brand information, and internal notes.

All data is mapped to the [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html) to ensure compatibility with Elastic Security apps.

### Supported use cases
* **Threat Detection:** Monitor for new brand-related threats detected by Doppel.
* **Incident Response:** Pivot from an Elastic Security alert directly to the Doppel dashboard using the provided reference links.
* **Historical Analysis:** Trend Doppel alert severity and volume over time to identify persistent threat patterns.

## What do I need to use this integration?
To use this integration, you will need:
* A valid Doppel **API Key**.
* An optional **Organization Code** (if required by your Doppel instance).

## How do I deploy this integration?

### Agent-based deployment
Elastic Agent must be installed on a host with outbound internet access to reach the Doppel API. For more details, refer to the [Elastic Agent installation guide](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

The agent will act as a centralized poller, fetching data from the API and shipping it to your Elastic cluster.

### Agentless deployment
This integration supports **Agentless (BETA)** deployment in Elastic Cloud environments. When using Agentless mode, Elastic manages the polling infrastructure for you, eliminating the need to install or maintain a local Elastic Agent.

## Onboard / configure
1. Navigate to **Management > Integrations** in Kibana.
2. Search for **Doppel** and click **Add Doppel**.
3. Enter your **API Key** and configure the **Polling Interval**.
4. Choose your deployment mode (Agent-based or Agentless).
5. Save the integration to begin ingesting data.

## Reference

### Alerts
The `alerts` data stream provides security events from the Doppel API.

#### Alerts fields
**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| doppel.app.bundle_id | The unique bundle identifier of the application. | keyword |
| doppel.app.developer_name | The listed developer name for the rogue application. | keyword |
| doppel.app.platform | The app store platform (e.g., iOS, Android) hosting the app. | keyword |
| doppel.app.title | The title of the rogue or impersonating application. | keyword |
| doppel.assignee | The analyst or user currently assigned to investigate the alert. | keyword |
| doppel.darkweb.cred_leaks_password | The exposed password associated with the credential leak. | keyword |
| doppel.darkweb.credential_url | The URL where the leaked credentials or data were found. | keyword |
| doppel.darkweb.leak_name | The name of the data breach or leak source. | keyword |
| doppel.domain.hosting_provider | The hosting provider for the malicious domain infrastructure. | keyword |
| doppel.domain.registrar | The domain registrar for the malicious or spoofed domain. | keyword |
| doppel.ecommerce.num_units | The number of units available in the fraudulent listing. | long |
| doppel.ecommerce.price | The listed price of the fraudulent item. | float |
| doppel.ecommerce.seller_name | The name of the seller offering the fraudulent item. | keyword |
| doppel.ecommerce.title | The title of the fraudulent or counterfeit e-commerce listing. | keyword |
| doppel.entity_state | The current status of the targeted entity (e.g., parked, active, offline). | keyword |
| doppel.notes | Internal notes, comments, or analyst observations added to the alert. | text |
| doppel.platform | The platform where the threat was detected. | keyword |
| doppel.product | The Doppel product category that generated the alert (e.g., domains, social). | keyword |
| doppel.queue_state | The current workflow queue state of the alert in Doppel (e.g., review, resolved). | keyword |
| doppel.social.num_followers | The number of followers the impersonating social media profile has. | long |
| doppel.social.profile_image_url | The URL of the malicious social media profile image. | keyword |
| doppel.social.profile_url | The URL of the malicious or impersonating social media profile. | keyword |
| doppel.tags | Custom tags associated with the alert for categorization. | keyword |
| doppel.telco.country_code | The country code associated with the telecommunications threat. | keyword |
| doppel.telco.provider | The telecommunications provider or carrier. | keyword |
| doppel.uploaded_by | The user or system account that uploaded the alert. | keyword |
| doppel_alert_updated_at | The timestamp when the alert was last updated. | date |
| event.created | The time the alert was created in the Doppel system. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| event.provider | The source or provider of the event (Doppel). | keyword |
| event.reference | A URL or link referencing the original alert in the Doppel dashboard. | keyword |
| event.risk_score | A normalized risk score for the alert. | float |
| event.severity | The numeric severity level of the alert. | long |
| event.url | The URL associated with the event or threat. | keyword |
| labels.audit_logs | Flattened object containing audit history and state changes for the alert. | flattened |
| labels.entity_content | Flattened object containing raw details about the targeted entity. | flattened |
| labels.severity | The string representation of the severity level (e.g., high, medium, low). | keyword |
| message | The original raw message or a brief summary of the alert. | text |
| organization.name | The name of the organization or brand targeted by the threat. | keyword |
| threat.indicator.ip | The IP address associated with the threat. | ip |
| threat.indicator.name | The name or value of the threat indicator. | keyword |
| threat.indicator.url.domain | The domain of the malicious or suspicious URL. | keyword |
| threat.indicator.url.full | The full malicious or suspicious URL. | keyword |
| url.domain | The parsed domain from the original URL. | keyword |
| url.original | The original URL string provided in the alert. | keyword |
| user.email | The email address of the user associated with the alert. | keyword |
| user.full_name | The full name of the user. | keyword |
| user.id | The unique identifier for the user. | keyword |
| user.name | The username or short name of the user. | keyword |


#### Alerts sample event
An example event for `alerts` looks as following:

```json
{
    "@timestamp": "2026-05-04T22:43:09.459Z",
    "agent": {
        "ephemeral_id": "8a4f500f-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "id": "11111111-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "name": "sample-host",
        "type": "filebeat",
        "version": "9.3.3"
    },
    "data_stream": {
        "dataset": "doppel.alerts",
        "namespace": "default",
        "type": "logs"
    },
    "doppel": {
        "entity_state": "active",
        "platform": "domains",
        "product": "domains",
        "queue_state": "doppel_review",
        "tags": [],
        "uploaded_by": "Doppel on behalf of Test Org"
    },
    "doppel_alert_updated_at": "2026-05-04T22:43:09.459Z",
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "11111111-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "snapshot": false,
        "version": "9.3.3"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2026-05-04T22:43:09.459Z",
        "dataset": "doppel.alerts",
        "id": "TET-2567200",
        "ingested": "2026-05-04T22:45:00Z",
        "kind": "alert",
        "module": "doppel",
        "original": "{\"assignee\":null,\"audit_logs\":[{\"changed_by\":\"Doppel\",\"metadata\":{},\"timestamp\":\"2026-05-04T22:43:09.396343\",\"type\":\"alert_create\",\"value\":\"needs_review\"}],\"brand\":\"sample_org\",\"created_at\":\"2026-05-04T22:43:09.459247\",\"doppel_link\":\"https://app.doppel.com/alerts/TET-2567200\",\"entity\":\"http://example.com/property/123\",\"entity_content\":{},\"entity_state\":\"active\",\"id\":\"TET-2567200\",\"last_activity_timestamp\":\"2026-05-04T22:43:09.459247\",\"message\":null,\"notes\":\"\",\"platform\":\"domains\",\"product\":\"domains\",\"queue_state\":\"doppel_review\",\"score\":null,\"screenshot_url\":null,\"severity\":\"medium\",\"source\":\"Manual Upload\",\"tags\":[],\"uploaded_by\":\"Doppel on behalf of Test Org\"}",
        "provider": "Manual Upload",
        "severity": 3,
        "type": [
            "indicator"
        ],
        "url": "https://app.doppel.com/alerts/TET-2567200"
    },
    "host": {
        "architecture": "x86_64",
        "hostname": "sample-host",
        "id": "B3D7AA91-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "ip": [
            "10.0.0.1"
        ],
        "mac": [
            "00-00-00-00-00-00"
        ],
        "name": "sample-host",
        "os": {
            "family": "darwin",
            "name": "macOS",
            "platform": "darwin",
            "type": "macos",
            "version": "26.4.1"
        }
    },
    "input": {
        "type": "httpjson"
    },
    "labels": {
        "audit_logs": [
            {
                "metadata": {},
                "type": "alert_create",
                "value": "needs_review",
                "changed_by": "Doppel",
                "timestamp": "2026-05-04T22:43:09.396343"
            }
        ],
        "severity": "Medium"
    },
    "organization": {
        "name": "sample_org"
    },
    "tags": [
        "preserve_original_event"
    ],
    "threat": {
        "indicator": {
            "url": {
                "full": "http://example.com/property/123"
            }
        }
    },
    "url": {
        "original": "http://example.com/property/123"
    }
}
```

### Inputs used
These inputs can be used with this integration:
<details>
<summary>httpjson</summary>

## Setup

For more details about the Http Json input settings, check the [Filebeat documentation](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-httpjson).

### Collecting logs from Http Json

To collect logs via http json, select **Collect logs via API** and configure the following parameter:

- API url: The API URL without the path.
</details>


### API usage
This integration interacts with the following Doppel API endpoints:
* `GET /v1/alerts`: Used to fetch the list of alerts based on activity timestamps.