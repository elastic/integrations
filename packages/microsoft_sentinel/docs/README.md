# Microsoft Sentinel

## Overview

[Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/overview?tabs=azure-portal) is a scalable, cloud-native security information and event management (SIEM) system that delivers an intelligent and comprehensive solution for SIEM and security orchestration, automation, and response (SOAR). Microsoft Sentinel provides cyberthreat detection, investigation, response, and proactive hunting, with a bird's-eye view across your enterprise.

Use the Microsoft Sentinel integration to collect and parse Alerts and Incidents from Microsoft Sentinel REST API and Events from the Microsoft Azure Event Hub, then visualise the data in Kibana.

## Data streams

The Microsoft Sentinel integration collects logs for three types of events: Alert, Event and Incident.

**Alert:** [Alert](https://learn.microsoft.com/en-us/rest/api/securityinsights/incidents/list-alerts?view=rest-securityinsights-2024-03-01&tabs=HTTP) allows collecting all alerts for an incident via API.

**Incident:** [Incident](https://learn.microsoft.com/en-us/rest/api/securityinsights/incidents/list?view=rest-securityinsights-2024-03-01&tabs=HTTP) allows collecting all incidents via API.

**Event:** [Event](https://learn.microsoft.com/en-us/azure/sentinel/security-alert-schema) allows collecting all alerts for an incident streamed to an Azure Event Hub.  

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

Please note, there are minimum requirements for running Elastic Agent. For more information, refer to the [Elastic Agent Minimum Requirements](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html#elastic-agent-installation-minimum-requirements).

## Compatibility

For Rest API, this module has been tested against the **2024-03-01** version.  

## Setup

### To collect data from Microsoft Azure Event Hub, follow the below steps:  

1. **Navigate to Log Analytics Workspace:** From the Azure Portal's navigation menu, locate and select **Log Analytics workspaces**.
2. **Select your Workspace:** Choose the Log Analytics workspace associated with your Azure Sentinel deployment.
3. **Navigate to Data Export:** Within the Log Analytics workspace, locate and select the `Data Export` option. This is usually found in the settings menu.
4. **New Export Rule:** Within Data export click on `New export rule` to create a new rule.
5. **Under Basic section:** Provide a rule name for the data export rule.
6. **Under Source section:** Select the tables you want to export data to storage account.
7. **Under Destination section:** Provide the destination details like the `Subscription` name and `Storage account` name to which you want to export data.
8. **Review + Create:** In the `review + create` section, select `Create`.

### To collect data from Microsoft Sentinel REST API, follow the below steps:

1. Open [Azure Portal](https://portal.azure.com/) and [Register a new Azure Application](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app?tabs=certificate).
2. After the application has been created, it will generate Client ID, Client Secret and Tenant ID values that are required for data collection.
3. To get **Workspace Name, Subscription ID, and Resource Group** navigate to **Microsoft Sentinel** and select desired workspace among the list.
4. Go to **Manage > API permissions** in your portal, then add the following permissions for **Microsoft Graph**:
    - **SecurityAlert.Read.All** with both **Application** and **Delegated** permission types.
    - **User.Read** with the **Delegated** permission type.

### Enabling the integration in Elastic:

1. In Kibana navigate to Management > Integrations.
2. In "Search for integrations" top bar, search for `Microsoft Sentinel`.
3. Select the "Microsoft Sentinel" integration from the search results.
4. Select "Add Microsoft Sentinel" to add the integration.
5. Add all the required integration configuration parameters, including the URL, Login URL, Client ID, Client Secret, Tenant Id, Resource Group Name, Subscription ID, Workspace Name, Interval, and Initial Interval, to enable data collection for REST API input type and Azure Event Hub, Consumer Group, Connection String, Storage Account and Storage Account Key for Azure Event Hub input type.
6. Select "Save and continue" to save the integration.

## Logs reference

### Alert

This is the `Alert` dataset.

#### Example

An example event for `alert` looks as following:

```json
{
    "@timestamp": "2020-07-20T18:21:53.615Z",
    "agent": {
        "ephemeral_id": "fef91ec8-bbe7-494a-b3b4-a8d9d79b11c3",
        "id": "2ca2bad8-2946-4164-8d1c-4b0dd7281ae6",
        "name": "elastic-agent-77518",
        "type": "filebeat",
        "version": "8.14.0"
    },
    "data_stream": {
        "dataset": "microsoft_sentinel.alert",
        "namespace": "19076",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "2ca2bad8-2946-4164-8d1c-4b0dd7281ae6",
        "snapshot": false,
        "version": "8.14.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "microsoft_sentinel.alert",
        "duration": 86400000000000,
        "end": "2020-07-21T18:21:53.615Z",
        "id": "/subscriptions/abcdef1-111111-4647-9105-6339bfdb4e6a/resourceGroups/myRG/providers/Microsoft.OperationalInsights/workspaces/myWorkspace/providers/Microsoft.SecurityInsights/Entities/abcdef-6fde-4ab7-a093-d09f7b75c58c",
        "ingested": "2024-11-12T06:18:55Z",
        "original": "{\"id\":\"/subscriptions/abcdef1-111111-4647-9105-6339bfdb4e6a/resourceGroups/myRG/providers/Microsoft.OperationalInsights/workspaces/myWorkspace/providers/Microsoft.SecurityInsights/Entities/abcdef-6fde-4ab7-a093-d09f7b75c58c\",\"kind\":\"SecurityAlert\",\"name\":\"abcdef-6fde-4ab7-a093-d09f7b75c58c\",\"properties\":{\"additionalData\":{\"AlertMessageEnqueueTime\":\"2020-07-20T18:21:57.304Z\"},\"alertDisplayName\":\"myAlert\",\"alertType\":\"myAlert\",\"confidenceLevel\":\"Unknown\",\"endTimeUtc\":\"2020-07-21T18:21:53.6158361Z\",\"friendlyName\":\"myAlert\",\"processingEndTime\":\"2020-07-20T18:21:53.6158361Z\",\"productName\":\"AzureSecurityCenter\",\"resourceIdentifiers\":[{\"resourceGroup\":\"myRG\",\"subscriptionId\":\"a123456-4d29-4647-9105-6339bfdb4e6a\",\"type\":\"LogAnalytics\",\"workspaceId\":\"abcdefg-985d-4e4e-8e91-fb3466cd0e5b\"}],\"severity\":\"Low\",\"startTimeUtc\":\"2020-07-20T18:21:53.6158361Z\",\"status\":\"New\",\"systemAlertId\":\"abcdef-6fde-4ab7-a093-d09f7b75c58c\",\"tactics\":[\"abc\"],\"timeGenerated\":\"2020-07-20T18:21:53.6158361Z\",\"vendorName\":\"Microsoft\"},\"systemData\":{\"createdAt\":\"2020-07-20T18:21:57.304Z\",\"createdBy\":\"admin\",\"createdByType\":\"new\",\"lastModifiedAt\":\"2020-07-20T18:21:57.304Z\"},\"type\":\"Microsoft.SecurityInsights/Entities\"}",
        "severity": 1,
        "start": "2020-07-20T18:21:53.615Z"
    },
    "input": {
        "type": "cel"
    },
    "microsoft_sentinel": {
        "alert": {
            "id": "/subscriptions/abcdef1-111111-4647-9105-6339bfdb4e6a/resourceGroups/myRG/providers/Microsoft.OperationalInsights/workspaces/myWorkspace/providers/Microsoft.SecurityInsights/Entities/abcdef-6fde-4ab7-a093-d09f7b75c58c",
            "kind": "SecurityAlert",
            "name": "abcdef-6fde-4ab7-a093-d09f7b75c58c",
            "properties": {
                "additional_data": {
                    "AlertMessageEnqueueTime": "2020-07-20T18:21:57.304Z"
                },
                "alert": {
                    "display_name": "myAlert",
                    "type": "myAlert"
                },
                "confidence_level": "Unknown",
                "end_time_utc": "2020-07-21T18:21:53.615Z",
                "friendly_name": "myAlert",
                "processing_end_time": "2020-07-20T18:21:53.615Z",
                "product": {
                    "name": "AzureSecurityCenter"
                },
                "resource_identifiers": [
                    {
                        "resourceGroup": "myRG",
                        "subscriptionId": "a123456-4d29-4647-9105-6339bfdb4e6a",
                        "type": "LogAnalytics",
                        "workspaceId": "abcdefg-985d-4e4e-8e91-fb3466cd0e5b"
                    }
                ],
                "severity": "Low",
                "start_time_utc": "2020-07-20T18:21:53.615Z",
                "status": "New",
                "system_alert_id": "abcdef-6fde-4ab7-a093-d09f7b75c58c",
                "tactics": [
                    "abc"
                ],
                "time_generated": "2020-07-20T18:21:53.615Z",
                "vendor_name": "Microsoft"
            },
            "system_data": {
                "created_at": "2020-07-20T18:21:57.304Z",
                "created_by": "admin",
                "created_by_type": "new",
                "last_modified_at": "2020-07-20T18:21:57.304Z"
            },
            "type": "Microsoft.SecurityInsights/Entities"
        }
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "microsoft_sentinel-alert"
    ],
    "threat": {
        "indicator": {
            "confidence": "Not Specified"
        },
        "tactic": {
            "name": [
                "abc"
            ]
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.kind |  | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| microsoft_sentinel.alert.id | Fully qualified resource ID for the resource. | keyword |
| microsoft_sentinel.alert.kind | The kind of the entity. | keyword |
| microsoft_sentinel.alert.name | The name of the resource. | keyword |
| microsoft_sentinel.alert.properties.additional_data | A bag of custom fields that should be part of the entity and will be presented to the user. | flattened |
| microsoft_sentinel.alert.properties.alert.display_name | The display name of the alert. | keyword |
| microsoft_sentinel.alert.properties.alert.link | The uri link of the alert. | keyword |
| microsoft_sentinel.alert.properties.alert.type | The type name of the alert. | keyword |
| microsoft_sentinel.alert.properties.compromised_entity | Display name of the main entity being reported on. | keyword |
| microsoft_sentinel.alert.properties.confidence_level | The confidence level of this alert. | keyword |
| microsoft_sentinel.alert.properties.confidence_reasons.reason | The reason's description. | keyword |
| microsoft_sentinel.alert.properties.confidence_reasons.reason_type | The type (category) of the reason. | keyword |
| microsoft_sentinel.alert.properties.confidence_score | The confidence score of the alert. | long |
| microsoft_sentinel.alert.properties.confidence_score_status | The confidence score calculation status. | keyword |
| microsoft_sentinel.alert.properties.description | Alert description. | keyword |
| microsoft_sentinel.alert.properties.end_time_utc | The impact end time of the alert. | date |
| microsoft_sentinel.alert.properties.friendly_name | The graph item display name which is a short humanly readable description of the graph item instance. | keyword |
| microsoft_sentinel.alert.properties.intent | Holds the alert intent stage(s) mapping for this alert. | keyword |
| microsoft_sentinel.alert.properties.processing_end_time | The time the alert was made available for consumption. | date |
| microsoft_sentinel.alert.properties.product.component_name | The name of a component inside the product which generated the alert. | keyword |
| microsoft_sentinel.alert.properties.product.name | The name of the product which published this alert. | keyword |
| microsoft_sentinel.alert.properties.product.version | The version of the product generating the alert. | keyword |
| microsoft_sentinel.alert.properties.provider_alert_id | The identifier of the alert inside the product which generated the alert. | keyword |
| microsoft_sentinel.alert.properties.remediation_steps | Manual action items to take to remediate the alert. | keyword |
| microsoft_sentinel.alert.properties.resource_identifiers | The list of resource identifiers of the alert. | object |
| microsoft_sentinel.alert.properties.severity | The severity of the alert. | keyword |
| microsoft_sentinel.alert.properties.start_time_utc | The impact start time of the alert. | date |
| microsoft_sentinel.alert.properties.status | The lifecycle status of the alert. | keyword |
| microsoft_sentinel.alert.properties.system_alert_id | Holds the product identifier of the alert for the product. | keyword |
| microsoft_sentinel.alert.properties.tactics | The tactics of the alert. | keyword |
| microsoft_sentinel.alert.properties.time_generated | The time the alert was generated. | date |
| microsoft_sentinel.alert.properties.vendor_name | The name of the vendor that raise the alert. | keyword |
| microsoft_sentinel.alert.system_data.created_at | The timestamp of resource creation (UTC). | date |
| microsoft_sentinel.alert.system_data.created_by | The identity that created the resource. | keyword |
| microsoft_sentinel.alert.system_data.created_by_type | The type of identity that created the resource. | keyword |
| microsoft_sentinel.alert.system_data.last_modified_at | The timestamp of resource last modification (UTC). | date |
| microsoft_sentinel.alert.system_data.last_modified_by | The identity that last modified the resource. | keyword |
| microsoft_sentinel.alert.system_data.last_modified_by_type | The type of identity that last modified the resource. | keyword |
| microsoft_sentinel.alert.type | The type of the resource. | keyword |
| observer.product |  | constant_keyword |
| observer.vendor |  | constant_keyword |
| tags | User defined tags. | keyword |


### Event

This is the `Event` dataset.

#### Example

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.kind |  | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| microsoft_sentinel.event.alert.link | A link to the alert in the portal of the originating product. | keyword |
| microsoft_sentinel.event.alert.name | The display name of the alert. | keyword |
| microsoft_sentinel.event.alert.severity | The severity of the alert. | keyword |
| microsoft_sentinel.event.alert.type | The type of alert. | keyword |
| microsoft_sentinel.event.compromised_entity | The display name of the main entity being alerted on. | keyword |
| microsoft_sentinel.event.confidence.level | The confidence level of this alert. | keyword |
| microsoft_sentinel.event.confidence.score | The confidence score of the alert. | double |
| microsoft_sentinel.event.description | The description of the alert. | keyword |
| microsoft_sentinel.event.display_name | The display name of the alert. | keyword |
| microsoft_sentinel.event.end_time | The end time of the impact of the alert. | date |
| microsoft_sentinel.event.entities | A list of the entities identified in the alert. | object |
| microsoft_sentinel.event.extended.links | A bag (a collection) for all links related to the alert. . | keyword |
| microsoft_sentinel.event.extended.properties | A collection of other properties of the alert, including user-defined properties. Any custom details defined in the alert, and any dynamic content in the alert details, are stored here. | object |
| microsoft_sentinel.event.internal_workspace_resource_id |  | keyword |
| microsoft_sentinel.event.is_incident | Always set to false. | boolean |
| microsoft_sentinel.event.item_id |  | keyword |
| microsoft_sentinel.event.processing_end_time | The time of the alert's publishing. | date |
| microsoft_sentinel.event.product.component_name | The name of the component of the product that generated the alert. | keyword |
| microsoft_sentinel.event.product.name | The name of the product that generated the alert. | keyword |
| microsoft_sentinel.event.provider_name | The name of the alert provider (the service within the product) that generated the alert. | keyword |
| microsoft_sentinel.event.remediation_steps | A list of action items to take to remediate the alert. | keyword |
| microsoft_sentinel.event.resource_id | A unique identifier for the resource that is the subject of the alert. | keyword |
| microsoft_sentinel.event.source.computer_id | Was the agent ID on the server that created the alert. | keyword |
| microsoft_sentinel.event.source.system | Always populated with the string "Detection". | keyword |
| microsoft_sentinel.event.start_time | The start time of the impact of the alert. | date |
| microsoft_sentinel.event.status | The status of the alert within the life cycle. | keyword |
| microsoft_sentinel.event.system_alert_id | The internal unique ID for the alert in Microsoft Sentinel. | keyword |
| microsoft_sentinel.event.tactics | A comma-delineated list of MITRE ATT&CK tactics associated with the alert. | keyword |
| microsoft_sentinel.event.techniques | A comma-delineated list of MITRE ATT&CK techniques associated with the alert. | keyword |
| microsoft_sentinel.event.tenant_id | The unique ID of the tenant. | keyword |
| microsoft_sentinel.event.time_generated | The time the alert was generated (in UTC). | date |
| microsoft_sentinel.event.type | The constant ('SecurityAlert'). | keyword |
| microsoft_sentinel.event.vendor.name | The vendor of the product that produced the alert. | keyword |
| microsoft_sentinel.event.vendor.original_id | Unique ID for the specific alert instance, set by the originating product. | keyword |
| microsoft_sentinel.event.workspace.resource_group |  | keyword |
| microsoft_sentinel.event.workspace.subscription_id |  | keyword |
| tags | User defined tags. | keyword |


### Incident

This is the `Incident` dataset.

#### Example

An example event for `incident` looks as following:

```json
{
    "@timestamp": "2024-10-23T13:15:30.000Z",
    "agent": {
        "ephemeral_id": "f2937dba-f98d-44e6-a1e2-161b5d5a8ea7",
        "id": "648b0051-77fb-49c2-a0ab-952d43da9d7f",
        "name": "elastic-agent-18094",
        "type": "filebeat",
        "version": "8.14.0"
    },
    "data_stream": {
        "dataset": "microsoft_sentinel.incident",
        "namespace": "18260",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "648b0051-77fb-49c2-a0ab-952d43da9d7f",
        "snapshot": false,
        "version": "8.14.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2019-01-01T13:15:30.000Z",
        "dataset": "microsoft_sentinel.incident",
        "id": "/subscriptions/d0cfe6b2-9ac0-4464-9919-dccaee2e48c0/resourceGroups/myRg/providers/Microsoft.OperationalInsights/workspaces/myWorkspace/providers/Microsoft.SecurityInsights/incidents/aaaaaa-5cd7-4139-a149-9f2736ff2ab5",
        "ingested": "2024-11-12T06:19:52Z",
        "original": "{\"etag\":\"\\\"bbbbbbbb-0000-0000-0000-5c37296e0000\\\"\",\"id\":\"/subscriptions/d0cfe6b2-9ac0-4464-9919-dccaee2e48c0/resourceGroups/myRg/providers/Microsoft.OperationalInsights/workspaces/myWorkspace/providers/Microsoft.SecurityInsights/incidents/aaaaaa-5cd7-4139-a149-9f2736ff2ab5\",\"name\":\"aaaaaaa-5cd7-4139-a149-9f2736ff2ab5\",\"properties\":{\"additionalData\":{\"alertProductNames\":[],\"alertsCount\":0,\"bookmarksCount\":0,\"commentsCount\":3,\"tactics\":[\"InitialAccess\",\"Persistence\"]},\"classification\":\"FalsePositive\",\"classificationComment\":\"Notamaliciousactivity\",\"classificationReason\":\"InaccurateData\",\"createdTimeUtc\":\"2019-01-01T13:15:30Z\",\"description\":\"Thisisademoincident\",\"firstActivityTimeUtc\":\"2019-01-01T13:00:30Z\",\"incidentNumber\":3177,\"incidentUrl\":\"https://portal.azure.com/#asset/Microsoft_Azure_Security_Insights/Incident/subscriptions/d0cfe6b2-9ac0-4464-9919-dccaee2e48c0/resourceGroups/myRg/providers/Microsoft.OperationalInsights/workspaces/myWorkspace/providers/Microsoft.SecurityInsights/incidents/73e01a99-5cd7-4139-a149-9f2736ff2ab5\",\"labels\":[],\"lastActivityTimeUtc\":\"2019-01-01T13:05:30Z\",\"lastModifiedTimeUtc\":\"2024-10-23T13:15:30Z\",\"owner\":{\"assignedTo\":\"johndoe\",\"email\":\"john.doe@example.com\",\"objectId\":\"abcdefghij-040d-4a46-9e2b-91c2941bfa70\",\"userPrincipalName\":\"john@example.com\"},\"providerIncidentId\":\"3177\",\"providerName\":\"AzureSentinel\",\"relatedAnalyticRuleIds\":[\"/subscriptions/abc12345678-9ac0-4464-9919-dccaee2e48c0/resourceGroups/myRg/providers/Microsoft.OperationalInsights/workspaces/myWorkspace/providers/Microsoft.SecurityInsights/alertRules/fab3d2d4-747f-46a7-8ef0-9c0be8112bf7\"],\"severity\":\"High\",\"status\":\"Closed\",\"title\":\"Myincident\"},\"type\":\"Microsoft.SecurityInsights/incidents\"}",
        "severity": 3,
        "url": "https://portal.azure.com/#asset/Microsoft_Azure_Security_Insights/Incident/subscriptions/d0cfe6b2-9ac0-4464-9919-dccaee2e48c0/resourceGroups/myRg/providers/Microsoft.OperationalInsights/workspaces/myWorkspace/providers/Microsoft.SecurityInsights/incidents/73e01a99-5cd7-4139-a149-9f2736ff2ab5"
    },
    "input": {
        "type": "cel"
    },
    "message": "Thisisademoincident",
    "microsoft_sentinel": {
        "incident": {
            "etag": "\"bbbbbbbb-0000-0000-0000-5c37296e0000\"",
            "id": "/subscriptions/d0cfe6b2-9ac0-4464-9919-dccaee2e48c0/resourceGroups/myRg/providers/Microsoft.OperationalInsights/workspaces/myWorkspace/providers/Microsoft.SecurityInsights/incidents/aaaaaa-5cd7-4139-a149-9f2736ff2ab5",
            "name": "aaaaaaa-5cd7-4139-a149-9f2736ff2ab5",
            "properties": {
                "additional_data": {
                    "alerts": {
                        "count": 0
                    },
                    "bookmarks_count": 0,
                    "comments_count": 3,
                    "tactics": [
                        "InitialAccess",
                        "Persistence"
                    ]
                },
                "classification": "FalsePositive",
                "classification_comment": "Notamaliciousactivity",
                "classification_reason": "InaccurateData",
                "created_time_utc": "2019-01-01T13:15:30.000Z",
                "description": "Thisisademoincident",
                "first_activity_time_utc": "2019-01-01T13:00:30.000Z",
                "incident": {
                    "number": 3177,
                    "url": "https://portal.azure.com/#asset/Microsoft_Azure_Security_Insights/Incident/subscriptions/d0cfe6b2-9ac0-4464-9919-dccaee2e48c0/resourceGroups/myRg/providers/Microsoft.OperationalInsights/workspaces/myWorkspace/providers/Microsoft.SecurityInsights/incidents/73e01a99-5cd7-4139-a149-9f2736ff2ab5"
                },
                "last_activity_time_utc": "2019-01-01T13:05:30.000Z",
                "last_modified_time_utc": "2024-10-23T13:15:30.000Z",
                "owner": {
                    "assigned_to": "johndoe",
                    "email": "john.doe@example.com",
                    "object_id": "abcdefghij-040d-4a46-9e2b-91c2941bfa70",
                    "user_principal_name": "john@example.com"
                },
                "provider": {
                    "incident_id": "3177",
                    "name": "AzureSentinel"
                },
                "related_analytic_rule_ids": [
                    "/subscriptions/abc12345678-9ac0-4464-9919-dccaee2e48c0/resourceGroups/myRg/providers/Microsoft.OperationalInsights/workspaces/myWorkspace/providers/Microsoft.SecurityInsights/alertRules/fab3d2d4-747f-46a7-8ef0-9c0be8112bf7"
                ],
                "severity": "High",
                "status": "Closed",
                "title": "Myincident"
            },
            "type": "Microsoft.SecurityInsights/incidents"
        }
    },
    "related": {
        "user": [
            "johndoe",
            "john.doe@example.com",
            "john@example.com"
        ]
    },
    "rule": {
        "id": [
            "/subscriptions/abc12345678-9ac0-4464-9919-dccaee2e48c0/resourceGroups/myRg/providers/Microsoft.OperationalInsights/workspaces/myWorkspace/providers/Microsoft.SecurityInsights/alertRules/fab3d2d4-747f-46a7-8ef0-9c0be8112bf7"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "microsoft_sentinel-incident"
    ],
    "threat": {
        "tactic": {
            "name": [
                "InitialAccess",
                "Persistence"
            ]
        }
    },
    "user": {
        "domain": "example.com",
        "email": "john.doe@example.com",
        "name": "johndoe"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.kind |  | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |
| log.offset | Log offset. | long |
| microsoft_sentinel.incident.etag | Etag of the azure resource. | keyword |
| microsoft_sentinel.incident.id | Fully qualified resource ID for the resource. | keyword |
| microsoft_sentinel.incident.name | The name of the resource. | keyword |
| microsoft_sentinel.incident.properties.additional_data.alert.product_names | List of product names of alerts in the incident. | keyword |
| microsoft_sentinel.incident.properties.additional_data.alerts.count | The number of alerts in the incident. | long |
| microsoft_sentinel.incident.properties.additional_data.bookmarks_count | The number of bookmarks in the incident. | long |
| microsoft_sentinel.incident.properties.additional_data.comments_count | The number of comments in the incident. | long |
| microsoft_sentinel.incident.properties.additional_data.provider_incident_url | The provider incident url to the incident in Microsoft 365 Defender portal. | keyword |
| microsoft_sentinel.incident.properties.additional_data.tactics | The tactics associated with incident. | keyword |
| microsoft_sentinel.incident.properties.classification | The reason the incident was closed. | keyword |
| microsoft_sentinel.incident.properties.classification_comment | Describes the reason the incident was closed. | keyword |
| microsoft_sentinel.incident.properties.classification_reason | The classification reason the incident was closed with. | keyword |
| microsoft_sentinel.incident.properties.created_time_utc | The time the incident was created. | date |
| microsoft_sentinel.incident.properties.description | The description of the incident. | keyword |
| microsoft_sentinel.incident.properties.first_activity_time_utc | The time of the first activity in the incident. | date |
| microsoft_sentinel.incident.properties.incident.number | A sequential number. | long |
| microsoft_sentinel.incident.properties.incident.url | The deep-link url to the incident in Azure portal. | keyword |
| microsoft_sentinel.incident.properties.labels.name | The name of the label. | keyword |
| microsoft_sentinel.incident.properties.labels.type | The type of the label. | keyword |
| microsoft_sentinel.incident.properties.last_activity_time_utc | The time of the last activity in the incident. | date |
| microsoft_sentinel.incident.properties.last_modified_time_utc | The last time the incident was updated. | date |
| microsoft_sentinel.incident.properties.owner.assigned_to | The name of the user the incident is assigned to. | keyword |
| microsoft_sentinel.incident.properties.owner.email | The email of the user the incident is assigned to. | keyword |
| microsoft_sentinel.incident.properties.owner.object_id | The object id of the user the incident is assigned to. | keyword |
| microsoft_sentinel.incident.properties.owner.type | The type of the owner the incident is assigned to. | keyword |
| microsoft_sentinel.incident.properties.owner.user_principal_name | The user principal name of the user the incident is assigned to. | keyword |
| microsoft_sentinel.incident.properties.provider.incident_id | The incident ID assigned by the incident provider. | keyword |
| microsoft_sentinel.incident.properties.provider.name | The name of the source provider that generated the incident. | keyword |
| microsoft_sentinel.incident.properties.related_analytic_rule_ids | List of resource ids of Analytic rules related to the incident. | keyword |
| microsoft_sentinel.incident.properties.severity | The severity of the incident. | keyword |
| microsoft_sentinel.incident.properties.status | The status of the incident. | keyword |
| microsoft_sentinel.incident.properties.title | The title of the incident. | keyword |
| microsoft_sentinel.incident.system_data.created_at | The timestamp of resource creation (UTC). | date |
| microsoft_sentinel.incident.system_data.created_by | The identity that created the resource. | keyword |
| microsoft_sentinel.incident.system_data.created_by_type | The type of identity that created the resource. | keyword |
| microsoft_sentinel.incident.system_data.last_modified_at | The timestamp of resource last modification (UTC). | date |
| microsoft_sentinel.incident.system_data.last_modified_by | The identity that last modified the resource. | keyword |
| microsoft_sentinel.incident.system_data.last_modified_by_type | The type of identity that last modified the resource. | keyword |
| microsoft_sentinel.incident.type | The type of the resource. | keyword |
| observer.product |  | constant_keyword |
| observer.vendor |  | constant_keyword |
| tags | User defined tags. | keyword |

