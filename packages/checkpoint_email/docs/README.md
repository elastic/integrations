# Checkpoint Harmony Email & Collaboration

Check Point's [Harmony Email & Collaboration](https://www.checkpoint.com/harmony/email-security/) monitors traffic across email platforms (Office 365, Gmail), file sharing services (OneDrive, SharePoint, Google Drive, Dropbox, Box, and Citrix ShareFile), and messaging applications (Teams and Slack). It scans emails, files, and messages for malware, DLP, and phishing indicators, and intercepts & quarantines potentially malicious emails before they are delivered.

The Checkpoint Harmony Email & Collaboration integration collects security event logs using REST API.

## Data streams

This integration collects the following logs:

- **[Event](https://app.swaggerhub.com/apis-docs/Check-Point/harmony-email-collaboration-smart-api/1.50#/APIs/query_event_v1_0_event_query_post)** - Get security event logs.

## Requirements

Elastic Agent must be installed. For more details and installation instructions, please refer to the [Elastic Agent Installation Guide](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

### Installing and managing an Elastic Agent:

There are several options for installing and managing Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

Please note, there are minimum requirements for running Elastic Agent. For more information, refer to the  [Elastic Agent Minimum Requirements](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html#elastic-agent-installation-minimum-requirements).

## Setup

### To collect data from the Harmony Email & Collaboration Smart API:

- In the Infinity Portal, go to Account Settings and click **API Keys**.
- Click **New** > **New Account API key**.
- In the **Create a New API Key** window, select **Email & Collaboration** as the service.
- (Optional) In the **Expiration** field, select an expiration date and time for the API key. By default, the expiration date is three months after the creation date.
- (Optional) In the **Description** field, enter a description for the API key.
- Click **Create**.
- Copy the **Client ID** and **Secret Key**.
    - **Note**: You can always obtain the **Client ID** from the **API Keys** table, but you cannot retrieve the **Secret Key** after the **Create a New API Key** window is closed.
- Click **Close**.

For more details, see [Documentation](https://sc1.checkpoint.com/documents/Infinity_Portal/WebAdminGuides/EN/Infinity-Portal-Admin-Guide/Content/Topics-Infinity-Portal/API-Keys.htm?tocpath=Account%20Settings%7C_____7#API_Keys).

### Enabling the integration in Elastic:

1. In Kibana navigate to Management > Integrations.
2. In "Search for integrations" top bar, search for `Checkpoint Harmony Email & Collaboration`.
3. Select the "Checkpoint Harmony Email & Collaboration" integration from the search results.
4. Select "Add Checkpoint Harmony Email & Collaboration" to add the integration.
5. Add all the required integration configuration parameters, including the URL, Client ID, Client Secret, Interval, and Initial Interval, to enable data collection.
6. Select "Save and continue" to save the integration.

**Note**: The default URL is `https://cloudinfra-gw.portal.checkpoint.com`, but this may vary depending on your region. Please refer to the [Documentation](https://sc1.checkpoint.com/documents/Harmony_Email_and_Collaboration_API_Reference/Topics-HEC-Avanan-API-Reference-Guide/Overview/URLs-and-URL-Base.htm?tocpath=Executing%20API%20Calls%7C_____3) to find the correct URL for your region.

## Logs reference

### Event

This is the `event` dataset.

#### Example

An example event for `event` looks as following:

```json
{
    "@timestamp": "2024-10-15T09:47:06.592Z",
    "agent": {
        "ephemeral_id": "383c0b41-e3ee-4815-80ba-61c86f898a35",
        "id": "14d531c1-4237-458c-ae16-81de8a83f9df",
        "name": "elastic-agent-26267",
        "type": "filebeat",
        "version": "8.15.0"
    },
    "checkpoint_email": {
        "event": {
            "confidence_indicator": "malicious",
            "created": "2024-10-15T09:47:06.592Z",
            "customer_id": "elasticteam",
            "data": "#{\"entity_id\": \"ad6ada66e6fabcdefabcdefc240dd9d0\", \"entity_type\": \"avanan_ap_scan\", \"label\": \"Phishing\"} attempt detected in an email from #{\"entity_id\": null, \"entity_type\": \"google_user\", \"disable_link\": true, \"label\": \"google-support@webnotifications.net\"} - '#{\"entity_id\": \"ad6ada66e6fabcdefabcdefc240dd9d0\", \"entity_type\": \"google_mail_email\", \"label\": \"Office Holiday Party - Folder Share\"}' (#{\"entity_id\": \"113310123456789535444\", \"entity_type\": \"google_user\", \"label\": \"team@example.com\"}'s mailbox)",
            "description": "Phishing attempt detected in an email from google-support@webnotifications.net - 'Office Holiday Party - Folder Share' (team@example.com's mailbox)",
            "entity_id": "ad6ada66e6fabcdefabcdefc240dd9d0",
            "entity_link": "https://in.portal.checkpoint.com/dashboard/email&collaboration/CGS1?route=cHJvZmlsZsdverberGRTHTYJbgbrtHYNRTGbdfbtryrtM2YyNTlkYTY0MmMyNDBkZDlkMA==",
            "id": "13007abcdef01234567896d00f44a7dd4",
            "saas": "google_mail",
            "sender_address": "google-support@webnotifications.net",
            "severity": 4,
            "severity_enum": "High",
            "state": "new",
            "type": "phishing"
        }
    },
    "data_stream": {
        "dataset": "checkpoint_email.event",
        "namespace": "61276",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "14d531c1-4237-458c-ae16-81de8a83f9df",
        "snapshot": false,
        "version": "8.15.0"
    },
    "email": {
        "sender": {
            "address": "google-support@webnotifications.net"
        }
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "email"
        ],
        "created": "2024-10-15T09:47:06.592Z",
        "dataset": "checkpoint_email.event",
        "id": "13007abcdef01234567896d00f44a7dd4",
        "ingested": "2024-10-17T07:32:27Z",
        "kind": "alert",
        "original": "{\"actions\":[],\"additionalData\":null,\"availableEventActions\":null,\"confidenceIndicator\":\"malicious\",\"customerId\":\"elasticteam\",\"data\":\"#{\\\"entity_id\\\": \\\"ad6ada66e6fabcdefabcdefc240dd9d0\\\", \\\"entity_type\\\": \\\"avanan_ap_scan\\\", \\\"label\\\": \\\"Phishing\\\"} attempt detected in an email from #{\\\"entity_id\\\": null, \\\"entity_type\\\": \\\"google_user\\\", \\\"disable_link\\\": true, \\\"label\\\": \\\"google-support@webnotifications.net\\\"} - '#{\\\"entity_id\\\": \\\"ad6ada66e6fabcdefabcdefc240dd9d0\\\", \\\"entity_type\\\": \\\"google_mail_email\\\", \\\"label\\\": \\\"Office Holiday Party - Folder Share\\\"}' (#{\\\"entity_id\\\": \\\"113310123456789535444\\\", \\\"entity_type\\\": \\\"google_user\\\", \\\"label\\\": \\\"team@example.com\\\"}'s mailbox)\",\"description\":\"Phishing attempt detected in an email from google-support@webnotifications.net - 'Office Holiday Party - Folder Share' (team@example.com's mailbox)\",\"entityId\":\"ad6ada66e6fabcdefabcdefc240dd9d0\",\"entityLink\":\"https://in.portal.checkpoint.com/dashboard/email\\u0026collaboration/CGS1?route=cHJvZmlsZsdverberGRTHTYJbgbrtHYNRTGbdfbtryrtM2YyNTlkYTY0MmMyNDBkZDlkMA==\",\"eventCreated\":\"2024-10-15T09:47:06.592720+00:00\",\"eventId\":\"13007abcdef01234567896d00f44a7dd4\",\"saas\":\"google_mail\",\"senderAddress\":\"google-support@webnotifications.net\",\"severity\":\"4\",\"state\":\"new\",\"type\":\"phishing\"}",
        "severity": 4,
        "type": [
            "info"
        ],
        "url": "https://in.portal.checkpoint.com/dashboard/email&collaboration/CGS1?route=cHJvZmlsZsdverberGRTHTYJbgbrtHYNRTGbdfbtryrtM2YyNTlkYTY0MmMyNDBkZDlkMA=="
    },
    "input": {
        "type": "cel"
    },
    "message": "Phishing attempt detected in an email from google-support@webnotifications.net - 'Office Holiday Party - Folder Share' (team@example.com's mailbox)",
    "observer": {
        "product": "Harmony Email & Collaboration",
        "vendor": "Checkpoint"
    },
    "organization": {
        "name": "elasticteam"
    },
    "related": {
        "user": [
            "google-support@webnotifications.net"
        ]
    },
    "source": {
        "user": {
            "email": "google-support@webnotifications.net"
        }
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "checkpoint_email-event"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| checkpoint_email.event.actions.action_type | Name of performed action. | keyword |
| checkpoint_email.event.actions.create_time | Date when the action was performed. | date |
| checkpoint_email.event.actions.related_entity_id | Unique ID of the relevant SaaS entity. | keyword |
| checkpoint_email.event.available_event_actions.action_name | Name of available action. | keyword |
| checkpoint_email.event.available_event_actions.action_parameter.eventId |  | keyword |
| checkpoint_email.event.available_event_actions.action_parameter.newSeverity |  | keyword |
| checkpoint_email.event.confidence_indicator | Confidence Indicator. | keyword |
| checkpoint_email.event.created | Time the security event was created. | date |
| checkpoint_email.event.customer_id | Harmony Email & Collaboration customer ID. | keyword |
| checkpoint_email.event.data | Description in not resolved form. | keyword |
| checkpoint_email.event.description | Short explanation of the event. | keyword |
| checkpoint_email.event.entity_id | Unique ID of the relevant SaaS entity. | keyword |
| checkpoint_email.event.entity_link |  | keyword |
| checkpoint_email.event.id | A unique ID used for scrolling. | keyword |
| checkpoint_email.event.saas | Name of the relevant SaaS. | keyword |
| checkpoint_email.event.sender_address |  | keyword |
| checkpoint_email.event.severity |  | long |
| checkpoint_email.event.severity_enum | Lowest, Low, Medium, High, Critical. | keyword |
| checkpoint_email.event.state | Current state of the security event. | keyword |
| checkpoint_email.event.type | Security event type. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |

