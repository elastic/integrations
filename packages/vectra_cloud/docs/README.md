# Vectra Cloud

## Overview

[Vectra AI](https://www.vectra.ai/) is a provider of cybersecurity solutions, including threat detection and response solutions. Vectra AI also provides cloud security, detects ransomware, secures remote workplaces, hunts and investigates threats, and offers investigations, risk and compliance services.

This integration enables to collect, parse Audit, Detection Event, Entity Event, Health and Lockdown data via [Vectra Cloud REST API](https://support.vectra.ai/vectra/article/KB-VS-1835), then visualise the data in Kibana.

## Data streams

The Vectra Cloud integration collects logs for five types of events.

**Audit:** Audit allows collecting Audit Log Events, which are recorded whenever a user performs an action on the system. These events are sequential and provide a reliable audit trail of user activity.

**Detection Event:** Detection Event allows collecting Detection Events, which are generated upon the initial detection and each subsequent update.

**Entity Event:** Entity Event allows collecting Entity scoring events, which are generated whenever an entity's score changes, such as during initial threat detection, the discovery of additional detections, or updates to existing ones.

**Health:** Health allows collecting system health data, with API responses that may vary based on product subscriptions such as Network, AWS, or M365.

**Lockdown:** Lockdown allows collecting entities lockdown status for accounts and hosts type, that are currently in lockdown mode.

## Agentless Enabled Integration
Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

## Requirements

Unless you choose `Agentless` deployment, the Elastic Agent must be installed. For more details and installation instructions, please refer to the [Elastic Agent Installation Guide](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

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

For Rest API, this module has been tested against the **v3.4** version.  

## Setup

### To collect data from the Vectra Cloud API:  

1. Navigate to **Manage > API Clients** in Vectra Console.
2. Click on **Add API Client**.
3. Add **Client Name**, **Description** and select the appropriate **Role** based on the endpoint, as outlined in the below table:
    | Endpoint               | Role               |
    | -----------------------| -------------------|
    | Audit                  | Auditor            |
    | Detection Event        | Read-Only          |
    | Entity Event           | Read-Only          |
    | Health                 | Auditor            |
    | Lockdown               | Read-Only          |  
4. Click **Generate Credentials**.
5. Copy **Client ID** and **Secret Key**.

For more details, see [Documentation](https://support.vectra.ai/vectra/article/KB-VS-1572).

### Enabling the integration in Elastic:

1. In Kibana navigate to Management > Integrations.
2. In "Search for integrations" top bar, search for `Vectra Cloud`.
3. Select the "Vectra Cloud" integration from the search results.
4. Select "Add Vectra Cloud" to add the integration.
5. Add all the required integration configuration parameters, including the URL, Client ID, Client Secret, Interval, and Initial Interval, to enable data collection for REST API input type.
6. Select "Save and continue" to save the integration.

## Logs reference

### Audit

This is the `Audit` dataset.

#### Example

An example event for `audit` looks as following:

```json
{
    "@timestamp": "2025-02-01T00:00:00.000Z",
    "agent": {
        "ephemeral_id": "7e06eae8-0a5b-40ed-9cf9-1f5a55600840",
        "id": "2f0b5a5d-96b7-4357-bbbf-ec4be7abf953",
        "name": "elastic-agent-56311",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "vectra_cloud.audit",
        "namespace": "40839",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "2f0b5a5d-96b7-4357-bbbf-ec4be7abf953",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "action": "updated",
        "agent_id_status": "verified",
        "category": [
            "configuration"
        ],
        "dataset": "vectra_cloud.audit",
        "ingested": "2025-04-22T07:22:43Z",
        "kind": "event",
        "original": "{\"api_client_id\":\"0cc5c3a9-4b1d-4b3a-9c5c-3a9b1d4b3a9b\",\"event_action\":\"updated\",\"event_data\":{},\"event_object\":\"account_tags\",\"event_timestamp\":\"2025-02-01T00:00:00.000Z\",\"id\":3,\"message\":\"[table:linked_account][id:1] with tags [] was changed to ['tag1', 'tag2', 'tag3', 'tag4', 'tag5', 'tag6']\",\"result_status\":\"success\",\"source_ip\":\"89.160.20.156\",\"user_id\":3,\"user_role\":\"Security Analyst\",\"user_type\":\"API_CLIENT\",\"username\":\"admin\",\"version\":\"2022.0.0\"}",
        "outcome": "success",
        "type": [
            "change"
        ]
    },
    "input": {
        "type": "cel"
    },
    "message": "[table:linked_account][id:1] with tags [] was changed to ['tag1', 'tag2', 'tag3', 'tag4', 'tag5', 'tag6']",
    "observer": {
        "product": "Vectra Cloud",
        "vendor": "Vectra",
        "version": "2022.0.0"
    },
    "related": {
        "ip": [
            "89.160.20.156"
        ],
        "user": [
            "3",
            "admin"
        ]
    },
    "source": {
        "as": {
            "number": 29518,
            "organization": {
                "name": "Bredband2 AB"
            }
        },
        "geo": {
            "city_name": "Linköping",
            "continent_name": "Europe",
            "country_iso_code": "SE",
            "country_name": "Sweden",
            "location": {
                "lat": 58.4167,
                "lon": 15.6167
            },
            "region_iso_code": "SE-E",
            "region_name": "Östergötland County"
        },
        "ip": "89.160.20.156"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "vectra_cloud-audit"
    ],
    "user": {
        "id": "3",
        "name": "admin",
        "roles": [
            "Security Analyst"
        ]
    },
    "vectra_cloud": {
        "audit": {
            "api_client_id": "0cc5c3a9-4b1d-4b3a-9c5c-3a9b1d4b3a9b",
            "event": {
                "action": "updated",
                "object": "account_tags",
                "timestamp": "2025-02-01T00:00:00.000Z"
            },
            "id": "3",
            "message": "[table:linked_account][id:1] with tags [] was changed to ['tag1', 'tag2', 'tag3', 'tag4', 'tag5', 'tag6']",
            "result_status": "success",
            "source_ip": "89.160.20.156",
            "user": {
                "id": "3",
                "name": "admin",
                "role": "Security Analyst",
                "type": "API_CLIENT"
            },
            "version": "2022.0.0"
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
| event.module | Event module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| vectra_cloud.audit.api_client_id | API client ID, if an event was caused by an API client interaction. | keyword |
| vectra_cloud.audit.event.action | What type of action is being audited. | keyword |
| vectra_cloud.audit.event.data | JSON data specific to the event type. | flattened |
| vectra_cloud.audit.event.object | The object type the audited action is being performed on. | keyword |
| vectra_cloud.audit.event.timestamp | Event timestamp (UTC) in ISO-8601 format. | date |
| vectra_cloud.audit.id | Auto incrementing ID. | keyword |
| vectra_cloud.audit.message | Message describing the event. | keyword |
| vectra_cloud.audit.result_status | Result status of the event. "success" or "failure". | keyword |
| vectra_cloud.audit.source_ip | IP address of the user/API client. | ip |
| vectra_cloud.audit.user.id | User ID of the user account associated with the event. | keyword |
| vectra_cloud.audit.user.name | Username of the account associated with the event, at the time of the event. | keyword |
| vectra_cloud.audit.user.role | Role the user/API client had at the time of the event. | keyword |
| vectra_cloud.audit.user.type | User type. | keyword |
| vectra_cloud.audit.version | Vectra UI version at the time of the event. | keyword |


### Detection Event

This is the `Detection Event` dataset.

#### Example

An example event for `detection_event` looks as following:

```json
{
    "@timestamp": "2022-09-13T16:31:35.000Z",
    "agent": {
        "ephemeral_id": "822cb9c5-bbdb-4307-934e-a1700d7dcc02",
        "id": "e0b27fe9-5d53-40ed-b4c9-940bf1d66e6c",
        "name": "elastic-agent-37687",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "vectra_cloud.detection_event",
        "namespace": "77275",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "e0b27fe9-5d53-40ed-b4c9-940bf1d66e6c",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "vectra_cloud.detection_event",
        "id": "959",
        "ingested": "2025-04-22T07:17:06Z",
        "kind": "alert",
        "original": "{\"category\":\"command_and_control\",\"certainty\":50,\"d_type_vname\":\"Azure AD Redundant Access Creation\",\"detail\":{},\"detection_href\":\"https://207031206993.uw2.devportal.vectra.ai/detections/959?detail_id=94341\",\"detection_id\":959,\"detection_type\":\"Azure AD Redundant Access Creation\",\"entity_href\":\"https://207031206993.uw2.devportal.vectra.ai/accounts/1\",\"entity_id\":1,\"entity_uid\":\"O365:ServicePrincipal_3fb87dda-882a-49e1-88b9-67d2499b2fd4\",\"event_timestamp\":\"2022-09-13T16:31:35Z\",\"id\":5,\"mitre\":[\"T1526\"],\"severity\":5,\"src_entity\":\"O365:ServicePrincipal_3fb87dda-882a-49e1-88b9-67d2499b2fd4\",\"threat\":50,\"triaged\":false,\"type\":\"account\",\"url\":\"https://207031206993.uw2.devportal.vectra.ai/detections/959\"}",
        "reference": "https://207031206993.uw2.devportal.vectra.ai/detections/959?detail_id=94341",
        "severity": 5,
        "type": [
            "indicator"
        ],
        "url": "https://207031206993.uw2.devportal.vectra.ai/detections/959"
    },
    "input": {
        "type": "cel"
    },
    "observer": {
        "product": "Vectra Cloud",
        "vendor": "Vectra"
    },
    "related": {
        "user": [
            "1"
        ]
    },
    "rule": {
        "name": "Azure AD Redundant Access Creation"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "vectra_cloud-detection_event"
    ],
    "threat": {
        "indicator": {
            "reference": "https://207031206993.uw2.devportal.vectra.ai/detections/959?detail_id=94341"
        },
        "tactic": {
            "name": [
                "command_and_control"
            ]
        },
        "technique": {
            "id": [
                "T1526"
            ]
        }
    },
    "url": {
        "domain": "207031206993.uw2.devportal.vectra.ai",
        "original": "https://207031206993.uw2.devportal.vectra.ai/detections/959?detail_id=94341",
        "path": "/detections/959",
        "query": "detail_id=94341",
        "scheme": "https"
    },
    "user": {
        "id": "1",
        "risk": {
            "calculated_score": 50
        }
    },
    "vectra_cloud": {
        "detection_event": {
            "category": "command_and_control",
            "certainty": 50,
            "d_type_vname": "Azure AD Redundant Access Creation",
            "detection": {
                "href": "https://207031206993.uw2.devportal.vectra.ai/detections/959?detail_id=94341",
                "id": "959",
                "type": "Azure AD Redundant Access Creation"
            },
            "entity": {
                "id": "1",
                "uid": "O365:ServicePrincipal_3fb87dda-882a-49e1-88b9-67d2499b2fd4"
            },
            "event_timestamp": "2022-09-13T16:31:35.000Z",
            "id": "5",
            "mitre": [
                "T1526"
            ],
            "severity": 5,
            "src_entity": "O365:ServicePrincipal_3fb87dda-882a-49e1-88b9-67d2499b2fd4",
            "threat": 50,
            "triaged": false,
            "type": "account",
            "url": "https://207031206993.uw2.devportal.vectra.ai/detections/959"
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
| event.module | Event module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| vectra_cloud.detection_event.category | The detection category. | keyword |
| vectra_cloud.detection_event.certainty | The certainty score attributed to the detection. | long |
| vectra_cloud.detection_event.d_type_vname | The detection name. | keyword |
| vectra_cloud.detection_event.detail | The detection detail. | flattened |
| vectra_cloud.detection_event.detection.href | Link to the detection. | keyword |
| vectra_cloud.detection_event.detection.id | The ID of the detection. | keyword |
| vectra_cloud.detection_event.detection.type | Type of detection. | keyword |
| vectra_cloud.detection_event.entity.id | Id of the related entity. | keyword |
| vectra_cloud.detection_event.entity.uid | UID of the related entity. | keyword |
| vectra_cloud.detection_event.event_timestamp | Timestamp when the Account Detection Event occurred. | date |
| vectra_cloud.detection_event.id | The ID of the Account Detection Event. | keyword |
| vectra_cloud.detection_event.mitre | Type of Mitre Technique. | keyword |
| vectra_cloud.detection_event.severity | The severity of the detection. | long |
| vectra_cloud.detection_event.src_entity |  | keyword |
| vectra_cloud.detection_event.threat | The threat score attributed to the detection. | long |
| vectra_cloud.detection_event.triaged | Indicates whether the detection has been triaged. | boolean |
| vectra_cloud.detection_event.type | Type of the related entity. | keyword |
| vectra_cloud.detection_event.url | Corresponding URL of the detection event. | keyword |


### Entity Event

This is the `Entity Event` dataset.

#### Example

An example event for `entity_event` looks as following:

```json
{
    "@timestamp": "2022-07-07T00:14:31.000Z",
    "agent": {
        "ephemeral_id": "ecb9d4d7-e559-4878-bfc4-877574f2ed28",
        "id": "5a97e1cc-469c-483d-a3e7-de1f951fa66f",
        "name": "elastic-agent-90415",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "vectra_cloud.entity_event",
        "namespace": "79854",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "5a97e1cc-469c-483d-a3e7-de1f951fa66f",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "host"
        ],
        "dataset": "vectra_cloud.entity_event",
        "id": "100",
        "ingested": "2025-04-22T07:11:48Z",
        "kind": "event",
        "original": "{\"active_detection_types\":[\"hidden_https_tunnel_cnc\"],\"attack_rating\":0,\"breadth_contrib\":0,\"category\":\"HOST_SCORING\",\"entity_id\":100,\"event_timestamp\":\"2022-07-07T00:14:31Z\",\"id\":1,\"importance\":0,\"is_prioritized\":false,\"last_detection\":{\"id\":103,\"type\":\"hidden_https_tunnel_cnc\",\"url\":\"https://200888808432.uw2.devportal.vectra.ai/detections/103\"},\"name\":\"piper-desktop\",\"severity\":\"Low\",\"type\":\"host\",\"urgency_reason\":\"Ransomware: This entity was prioritized because it was implicated in an active ransomware detection\",\"urgency_score\":0,\"url\":\"https://200888808432.uw2.devportal.vectra.ai/accounts/8\",\"velocity_contrib\":0}",
        "reference": "https://200888808432.uw2.devportal.vectra.ai/detections/103",
        "severity": 33,
        "type": [
            "info"
        ],
        "url": "https://200888808432.uw2.devportal.vectra.ai/accounts/8"
    },
    "host": {
        "id": "100",
        "name": "piper-desktop"
    },
    "input": {
        "type": "cel"
    },
    "message": "Ransomware: This entity was prioritized because it was implicated in an active ransomware detection",
    "observer": {
        "product": "Vectra Cloud",
        "vendor": "Vectra"
    },
    "related": {
        "hosts": [
            "100",
            "piper-desktop"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "vectra_cloud-entity_event",
        "vectra_cloud-entity_event-host"
    ],
    "threat": {
        "indicator": {
            "reference": "https://200888808432.uw2.devportal.vectra.ai/detections/103"
        }
    },
    "url": {
        "domain": "200888808432.uw2.devportal.vectra.ai",
        "original": "https://200888808432.uw2.devportal.vectra.ai/detections/103",
        "path": "/detections/103",
        "scheme": "https"
    },
    "vectra_cloud": {
        "entity_event": {
            "active_detection_types": [
                "hidden_https_tunnel_cnc"
            ],
            "attack_rating": 0,
            "breadth_contrib": 0,
            "category": "HOST_SCORING",
            "entity_id": "100",
            "event_timestamp": "2022-07-07T00:14:31.000Z",
            "id": "1",
            "importance": 0,
            "is_prioritized": false,
            "last_detection": {
                "id": "103",
                "type": "hidden_https_tunnel_cnc",
                "url": "https://200888808432.uw2.devportal.vectra.ai/detections/103"
            },
            "name": "piper-desktop",
            "severity": "Low",
            "type": "host",
            "urgency": {
                "reason": "Ransomware: This entity was prioritized because it was implicated in an active ransomware detection",
                "score": 0
            },
            "url": "https://200888808432.uw2.devportal.vectra.ai/accounts/8",
            "velocity_contrib": 0
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
| event.module | Event module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| vectra_cloud.entity_event.active_detection_types | A list of all active detection types on the entity. | keyword |
| vectra_cloud.entity_event.attack_rating |  | long |
| vectra_cloud.entity_event.breadth_contrib | Breadth contribution of the entity. | long |
| vectra_cloud.entity_event.category | The event category. | keyword |
| vectra_cloud.entity_event.entity_id | Entity ID. | keyword |
| vectra_cloud.entity_event.event_timestamp | Timestamp when the detection event occurred. | date |
| vectra_cloud.entity_event.id |  | keyword |
| vectra_cloud.entity_event.importance | Importance score of the entity. | long |
| vectra_cloud.entity_event.is_prioritized | Whether or not the priority of this entity is above the configured priority threshold. | boolean |
| vectra_cloud.entity_event.last_detection.id |  | keyword |
| vectra_cloud.entity_event.last_detection.type |  | keyword |
| vectra_cloud.entity_event.last_detection.url |  | keyword |
| vectra_cloud.entity_event.name | The name associated with the account, or the learned hostname. | keyword |
| vectra_cloud.entity_event.severity | Entity severity. | keyword |
| vectra_cloud.entity_event.type | Entity type. | keyword |
| vectra_cloud.entity_event.urgency.reason | Reason behind the urgency_score. | keyword |
| vectra_cloud.entity_event.urgency.score | Priority or urgency of the entity. | long |
| vectra_cloud.entity_event.url | The URL link directly to this entity. | keyword |
| vectra_cloud.entity_event.velocity_contrib | Velocity contribution of the entity. | long |


### Health

This is the `Health` dataset.

#### Example

An example event for `health` looks as following:

```json
{
    "@timestamp": "2025-04-15T09:39:45.146Z",
    "agent": {
        "ephemeral_id": "6e5e3d80-a99a-491c-9d99-750805eb3370",
        "id": "84fa4753-f029-468c-a8ab-9e551a4ecf92",
        "name": "elastic-agent-29987",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "vectra_cloud.health",
        "namespace": "11227",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "84fa4753-f029-468c-a8ab-9e551a4ecf92",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "vectra_cloud.health",
        "ingested": "2025-04-22T09:53:06Z",
        "kind": "event",
        "original": "{\"connectivity\":{\"sensors\":[{\"affected_metadata_hours\":[\"2025-04-18T00:00:00Z\",\"2025-04-18T01:00:00Z\"],\"error\":\"metadata replication seems fine\",\"ip_address\":\"216.160.83.56\",\"luid\":\"w4ftj0a8\",\"name\":\"EDR Sensor\",\"serial_number\":\"V421353ef386550fb2f9a959fa3f52aee\",\"status\":\"OK\"},{\"affected_metadata_hours\":[\"2025-04-18T00:00:00Z\",\"2025-04-18T01:00:00Z\"],\"error\":\"metadata replication seems fine\",\"ip_address\":\"81.2.69.142\",\"luid\":\"w4ftj0a8\",\"name\":\"XDR Sensor\",\"serial_number\":\"V423ef386550fb2f9a959fa3f52aee\",\"status\":\"OK\"}],\"updated_at\":\"2025-04-18 07:17:35+00:00\"},\"cpu\":{\"idle_percent\":43.9,\"nice_percent\":0,\"system_percent\":24.9,\"updated_at\":\"2025-04-18 07:17:35+00:00\",\"user_percent\":30},\"detection\":{\"detection_type\":\"AWS\",\"message\":\"This is detection message\",\"name\":\"Detection 1\",\"status\":\"OK\",\"updated_at\":\"2025-04-18 07:17:33+00:00\"},\"disk\":{\"degraded_raid_volume\":{\"error\":\"error\",\"output\":\"output\",\"status\":\"OK\"},\"disk_raid\":{\"error\":\"error\",\"output\":\"output\",\"status\":\"OK\"},\"disk_utilization\":{\"free_bytes\":10000109,\"total_bytes\":67444477952,\"usage_percent\":47,\"used_bytes\":33078743040},\"raid_disks_missing\":{\"error\":\"error\",\"output\":\"output\",\"status\":\"OK\"},\"updated_at\":\"2025-04-18 07:17:34+00:00\"},\"event_timestamp\":\"2025-04-15T09:39:45.146Z\",\"hostid\":{\"artifact_counts\":{\"TestEDR\":0,\"arsenic\":0,\"carbon_black\":0,\"cb_cloud\":0,\"clear_state\":0,\"cookie\":0,\"crowdstrike\":0,\"cybereason\":0,\"dhcp\":6606,\"dns\":27818,\"end_time\":0,\"fireeye\":0,\"generic_edr\":0,\"idle_end\":27818,\"idle_start\":27936,\"invalid\":0,\"kerberos\":209,\"kerberos_user\":0,\"mdns\":18575,\"netbios\":15596,\"proxy_ip\":0,\"rdns\":0,\"sentinelone\":0,\"split\":0,\"src_port\":0,\"static_ip\":0,\"total\":134681,\"uagent\":10122,\"vmachine_info\":0,\"windows_defender\":1,\"zpa_user\":0},\"ip_always_percent\":18.52,\"ip_never_percent\":79.01,\"ip_sometimes_percent\":2.47,\"updated_at\":\"2025-04-18 07:17:35+00:00\"},\"memory\":{\"free_bytes\":5597118464,\"total_bytes\":67444477952,\"updated_at\":\"2025-04-18 07:17:35+00:00\",\"usage_percent\":47,\"used_bytes\":33078743040},\"network\":{\"updated_at\":\"2025-04-18 07:17:34+00:00\",\"vlans\":{\"count\":1,\"vlan_ids\":[\"7\",\"8\"]}},\"power\":{\"error\":\"Power check for this device is not supported\",\"status\":\"SKIP\",\"updated_at\":\"2025-04-18 07:17:35+00:00\"},\"sensors\":[{\"headend_uri\":\"175.16.199.24\",\"id\":3,\"ip_address\":\"175.16.199.0\",\"last_seen\":\"2025-04-18T07:15:37.685Z\",\"location\":\"hyp-2-37\",\"luid\":\"w4ftj0a8\",\"mode\":\"sensor\",\"name\":\"EDR Sensor\",\"original_version\":\"7.9.0-17-38\",\"product_name\":\"DCS\",\"public_key\":\"-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1y0zv2goBjkol/8TggJJ\\nMgP03tIZ6B6w9PVpF/bK8KTT0/hinX8PHP/MdDS58sVE6DuAqAkkELqN55f35AhB\\nOqztY9xWDH8bO7Y0P0kbBIQ9+/abyfNpaxbiQe5Yk8oClyEgtXH4GKJCNxkGgbIb\\n-----END PUBLIC KEY-----\\n\",\"serial_number\":\"V421353ef386550fb2f9a959fa3f52aee\",\"ssh_tunnel_port\":\"38113\",\"status\":\"paired\",\"update_count\":0,\"version\":\"9.0.3-1-62\"},{\"headend_uri\":\"175.16.199.24\",\"id\":2,\"ip_address\":\"175.16.199.0\",\"last_seen\":\"2025-04-18T07:15:37.685Z\",\"location\":\"hyp-2-35\",\"luid\":\"w4ftj0a8\",\"mode\":\"sensor\",\"name\":\"XDR Sensor\",\"original_version\":\"7.9.0-17-38\",\"product_name\":\"DCS\",\"public_key\":\"-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1y0zv2goBjkol/8TggJJ\\nMgP03tIZ6B6w9PVpF/bK8KTT0/hinX8PHP/MdDS58sVE6DuAqAkkELqN55f35AhB\\nOqztY9xWDH8bO7Y0P0kbBIQ9+/abyfNpaxbiQe5Yk8oClyEgtXH4GKJCNxkGgbIb\\n-----END PUBLIC KEY-----\\n\",\"serial_number\":\"12421353ef386550fb2f9a959fa3f52aee\",\"ssh_tunnel_port\":\"38113\",\"status\":\"paired\",\"update_count\":0,\"version\":\"9.0.3-1-62\"},{\"headend_uri\":\"http://headend_uri/\",\"id\":1,\"ip_address\":\"175.16.199.0\",\"last_seen\":\"2025-04-18T07:15:37.685Z\",\"location\":\"hyp-2-30\",\"luid\":\"w4ftj0a8\",\"mode\":\"sensor\",\"name\":\"DR Sensor\",\"original_version\":\"7.9.0-17-38\",\"product_name\":\"DCS\",\"public_key\":\"-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1y0zv2goBjkol/8TggJJ\\nMgP03tIZ6B6w9PVpF/bK8KTT0/hinX8PHP/MdDS58sVE6DuAqAkkELqN55f35AhB\\nOqztY9xWDH8bO7Y0P0kbBIQ9+/abyfNpaxbiQe5Yk8oClyEgtXH4GKJCNxkGgbIb\\n-----END PUBLIC KEY-----\\n\",\"serial_number\":\"V4121353ef386550fb2f9a959fa3f52aee\",\"ssh_tunnel_port\":\"38113\",\"status\":\"paired\",\"update_count\":0,\"version\":\"9.0.3-1-62\"}],\"system\":{\"serial_number\":\"VHE66258a5e8dafe76d9a5dd741abd94ee8\",\"updated_at\":\"2025-04-18 07:17:33+00:00\",\"uptime\":\"261 days, 13 hours, 33 minutes\",\"version\":{\"cloud_bridge\":true,\"gmt\":\"2025-04-18T07:14:09.593927Z\",\"last_update\":\"Wed Apr  9 02:03:16 2025\",\"last_update_utc\":\"2025-04-09T02:03:16+00:00\",\"mode\":\"brain\",\"model\":\"VHE\",\"vectra_instance_type\":\"medium\",\"vectra_version\":\"9.0.3-2-62\",\"vm_type\":\"vmware\"}},\"trafficdrop\":{\"sensors\":[{\"error\":\"All interfaces have traffic volume within range\",\"ip_address\":\"1.128.0.0\",\"luid\":\"w4ftj0a8\",\"name\":\"EDR Sensor\",\"serial_number\":\"V421353ef386550fb2f9a959fa3f52aee\",\"status\":\"OK\"},{\"error\":\"Interface have traffic volume within range\",\"ip_address\":\"1.128.0.11\",\"luid\":\"w4ftj0a8\",\"name\":\"XDR Sensor\",\"serial_number\":\"1421353ef386550fb2f9a959fa3f52aee\",\"status\":\"OK\"}],\"updated_at\":\"2025-04-18 07:17:35+00:00\"}}"
    },
    "host": {
        "cpu": {
            "usage": 30
        },
        "id": "VHE66258a5e8dafe76d9a5dd741abd94ee8",
        "type": "vmware"
    },
    "input": {
        "type": "cel"
    },
    "message": "This is detection message",
    "network": {
        "vlan": {
            "id": [
                "7",
                "8"
            ]
        }
    },
    "observer": {
        "ip": [
            "175.16.199.0"
        ],
        "name": [
            "EDR Sensor",
            "XDR Sensor",
            "DR Sensor"
        ],
        "serial_number": [
            "V421353ef386550fb2f9a959fa3f52aee",
            "12421353ef386550fb2f9a959fa3f52aee",
            "V4121353ef386550fb2f9a959fa3f52aee"
        ],
        "version": [
            "9.0.3-1-62"
        ]
    },
    "related": {
        "ip": [
            "216.160.83.56",
            "81.2.69.142",
            "175.16.199.0",
            "175.16.199.24",
            "1.128.0.0",
            "1.128.0.11"
        ]
    },
    "rule": {
        "name": "Detection 1"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "vectra_cloud-health"
    ],
    "threat": {
        "indicator": {
            "description": "This is detection message"
        }
    },
    "vectra_cloud": {
        "health": {
            "connectivity": {
                "sensors": [
                    {
                        "affected_metadata_hours": [
                            "2025-04-18T00:00:00Z",
                            "2025-04-18T01:00:00Z"
                        ],
                        "error": "metadata replication seems fine",
                        "ip_address": "216.160.83.56",
                        "luid": "w4ftj0a8",
                        "name": "EDR Sensor",
                        "serial_number": "V421353ef386550fb2f9a959fa3f52aee",
                        "status": "OK"
                    },
                    {
                        "affected_metadata_hours": [
                            "2025-04-18T00:00:00Z",
                            "2025-04-18T01:00:00Z"
                        ],
                        "error": "metadata replication seems fine",
                        "ip_address": "81.2.69.142",
                        "luid": "w4ftj0a8",
                        "name": "XDR Sensor",
                        "serial_number": "V423ef386550fb2f9a959fa3f52aee",
                        "status": "OK"
                    }
                ]
            },
            "cpu": {
                "idle_percent": 43.9,
                "nice_percent": 0,
                "system_percent": 24.9,
                "updated_at": "2025-04-18T07:17:35.000Z",
                "user_percent": 30
            },
            "detection": {
                "detection_type": "AWS",
                "message": "This is detection message",
                "name": "Detection 1",
                "status": "OK",
                "updated_at": "2025-04-18T07:17:33.000Z"
            },
            "disk": {
                "degraded_raid_volume": {
                    "error": "error",
                    "output": "output",
                    "status": "OK"
                },
                "disk_raid": {
                    "error": "error",
                    "output": "output",
                    "status": "OK"
                },
                "disk_utilization": {
                    "free_bytes": 10000109,
                    "total_bytes": 67444477952,
                    "usage_percent": 47,
                    "used_bytes": 33078743040
                },
                "raid_disks_missing": {
                    "error": "error",
                    "output": "output",
                    "status": "OK"
                },
                "updated_at": "2025-04-18T07:17:34.000Z"
            },
            "event_timestamp": "2025-04-15T09:39:45.146Z",
            "hostid": {
                "artifact_counts": {
                    "TestEDR": 0,
                    "arsenic": 0,
                    "carbon_black": 0,
                    "cb_cloud": 0,
                    "clear_state": 0,
                    "cookie": 0,
                    "crowdstrike": 0,
                    "cybereason": 0,
                    "dhcp": 6606,
                    "dns": 27818,
                    "end_time": 0,
                    "fireeye": 0,
                    "generic_edr": 0,
                    "idle_end": 27818,
                    "idle_start": 27936,
                    "invalid": 0,
                    "kerberos": 209,
                    "kerberos_user": 0,
                    "mdns": 18575,
                    "netbios": 15596,
                    "proxy_ip": 0,
                    "rdns": 0,
                    "sentinelone": 0,
                    "split": 0,
                    "src_port": 0,
                    "static_ip": 0,
                    "total": 134681,
                    "uagent": 10122,
                    "vmachine_info": 0,
                    "windows_defender": 1,
                    "zpa_user": 0
                },
                "ip_always_percent": 18.52,
                "ip_never_percent": 2.47,
                "ip_sometimes_percent": 79.01,
                "updated_at": "2025-04-18T07:17:35.000Z"
            },
            "memory": {
                "free_bytes": 5597118464,
                "total_bytes": 67444477952,
                "updated_at": "2025-04-18T07:17:35.000Z",
                "usage_percent": 47,
                "used_bytes": 33078743040
            },
            "network": {
                "updated_at": "2025-04-18T07:17:34.000Z",
                "vlans": {
                    "count": 1,
                    "vlan_ids": [
                        "7",
                        "8"
                    ]
                }
            },
            "power": {
                "error": "Power check for this device is not supported",
                "status": "SKIP",
                "updated_at": "2025-04-18T07:17:35.000Z"
            },
            "sensors": [
                {
                    "headend_ip": "175.16.199.24",
                    "id": "3",
                    "location": "hyp-2-37",
                    "luid": "w4ftj0a8",
                    "mode": "sensor",
                    "name": "EDR Sensor",
                    "original_version": "7.9.0-17-38",
                    "product_name": "DCS",
                    "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1y0zv2goBjkol/8TggJJ\nMgP03tIZ6B6w9PVpF/bK8KTT0/hinX8PHP/MdDS58sVE6DuAqAkkELqN55f35AhB\nOqztY9xWDH8bO7Y0P0kbBIQ9+/abyfNpaxbiQe5Yk8oClyEgtXH4GKJCNxkGgbIb\n-----END PUBLIC KEY-----\n",
                    "serial_number": "V421353ef386550fb2f9a959fa3f52aee",
                    "ssh_tunnel_port": "38113",
                    "status": "paired",
                    "update_count": 0,
                    "version": "9.0.3-1-62"
                },
                {
                    "headend_ip": "175.16.199.24",
                    "id": "2",
                    "location": "hyp-2-35",
                    "luid": "w4ftj0a8",
                    "mode": "sensor",
                    "name": "XDR Sensor",
                    "original_version": "7.9.0-17-38",
                    "product_name": "DCS",
                    "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1y0zv2goBjkol/8TggJJ\nMgP03tIZ6B6w9PVpF/bK8KTT0/hinX8PHP/MdDS58sVE6DuAqAkkELqN55f35AhB\nOqztY9xWDH8bO7Y0P0kbBIQ9+/abyfNpaxbiQe5Yk8oClyEgtXH4GKJCNxkGgbIb\n-----END PUBLIC KEY-----\n",
                    "serial_number": "12421353ef386550fb2f9a959fa3f52aee",
                    "ssh_tunnel_port": "38113",
                    "status": "paired",
                    "update_count": 0,
                    "version": "9.0.3-1-62"
                },
                {
                    "headend_url": "http://headend_uri/",
                    "id": "1",
                    "location": "hyp-2-30",
                    "luid": "w4ftj0a8",
                    "mode": "sensor",
                    "name": "DR Sensor",
                    "original_version": "7.9.0-17-38",
                    "product_name": "DCS",
                    "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1y0zv2goBjkol/8TggJJ\nMgP03tIZ6B6w9PVpF/bK8KTT0/hinX8PHP/MdDS58sVE6DuAqAkkELqN55f35AhB\nOqztY9xWDH8bO7Y0P0kbBIQ9+/abyfNpaxbiQe5Yk8oClyEgtXH4GKJCNxkGgbIb\n-----END PUBLIC KEY-----\n",
                    "serial_number": "V4121353ef386550fb2f9a959fa3f52aee",
                    "ssh_tunnel_port": "38113",
                    "status": "paired",
                    "update_count": 0,
                    "version": "9.0.3-1-62"
                }
            ],
            "system": {
                "serial_number": "VHE66258a5e8dafe76d9a5dd741abd94ee8",
                "updated_at": "2025-04-18T07:17:33.000Z",
                "uptime": "261 days, 13 hours, 33 minutes",
                "version": {
                    "cloud_bridge": true,
                    "gmt": "2025-04-18T07:14:09.593Z",
                    "last_update": "2025-04-09T02:03:16.000Z",
                    "last_update_utc": "2025-04-09T02:03:16.000Z",
                    "mode": "brain",
                    "model": "VHE",
                    "vectra_instance_type": "medium",
                    "vectra_version": "9.0.3-2-62",
                    "vm_type": "vmware"
                }
            },
            "trafficdrop": {
                "sensors": [
                    {
                        "error": "All interfaces have traffic volume within range",
                        "ip_address": "1.128.0.0",
                        "luid": "w4ftj0a8",
                        "name": "EDR Sensor",
                        "serial_number": "V421353ef386550fb2f9a959fa3f52aee",
                        "status": "OK"
                    },
                    {
                        "error": "Interface have traffic volume within range",
                        "ip_address": "1.128.0.11",
                        "luid": "w4ftj0a8",
                        "name": "XDR Sensor",
                        "serial_number": "1421353ef386550fb2f9a959fa3f52aee",
                        "status": "OK"
                    }
                ],
                "updated_at": "2025-04-18T07:17:35.000Z"
            }
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
| event.module | Event module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| vectra_cloud.health.connectivity.sensors.affected_metadata_hours | Field not present if status is 'OK'. | keyword |
| vectra_cloud.health.connectivity.sensors.error |  | keyword |
| vectra_cloud.health.connectivity.sensors.ip_address |  | ip |
| vectra_cloud.health.connectivity.sensors.luid |  | keyword |
| vectra_cloud.health.connectivity.sensors.name |  | keyword |
| vectra_cloud.health.connectivity.sensors.output |  | flattened |
| vectra_cloud.health.connectivity.sensors.serial_number |  | keyword |
| vectra_cloud.health.connectivity.sensors.status | Status can be OK, WARNING, CRITICAL, or UNKNOWN. | keyword |
| vectra_cloud.health.cpu.idle_percent | % of CPU idle. | double |
| vectra_cloud.health.cpu.nice_percent | % of CPU processing higher prioritized tasks. | double |
| vectra_cloud.health.cpu.system_percent | % of CPU processing system specific tasks. | double |
| vectra_cloud.health.cpu.updated_at |  | date |
| vectra_cloud.health.cpu.user_percent | % of CPU processing tasks. | double |
| vectra_cloud.health.detection.check_results | One entry per failing detection model, or exactly one entry if all detection models are healthy. | flattened |
| vectra_cloud.health.detection.detection_type |  | keyword |
| vectra_cloud.health.detection.message |  | keyword |
| vectra_cloud.health.detection.name |  | keyword |
| vectra_cloud.health.detection.status | Status can be OK or CRITICAL. | keyword |
| vectra_cloud.health.detection.updated_at |  | date |
| vectra_cloud.health.disk.degraded_raid_volume.error |  | keyword |
| vectra_cloud.health.disk.degraded_raid_volume.output |  | keyword |
| vectra_cloud.health.disk.degraded_raid_volume.status |  | keyword |
| vectra_cloud.health.disk.disk_raid.error |  | keyword |
| vectra_cloud.health.disk.disk_raid.output |  | keyword |
| vectra_cloud.health.disk.disk_raid.status |  | keyword |
| vectra_cloud.health.disk.disk_utilization.free_bytes |  | long |
| vectra_cloud.health.disk.disk_utilization.total_bytes |  | long |
| vectra_cloud.health.disk.disk_utilization.usage_percent |  | double |
| vectra_cloud.health.disk.disk_utilization.used_bytes |  | long |
| vectra_cloud.health.disk.raid_disks_missing.error |  | keyword |
| vectra_cloud.health.disk.raid_disks_missing.output |  | keyword |
| vectra_cloud.health.disk.raid_disks_missing.status |  | keyword |
| vectra_cloud.health.disk.updated_at |  | date |
| vectra_cloud.health.event_timestamp |  | date |
| vectra_cloud.health.hostid.artifact_counts |  | object |
| vectra_cloud.health.hostid.ip_always_percent |  | double |
| vectra_cloud.health.hostid.ip_never_percent |  | double |
| vectra_cloud.health.hostid.ip_sometimes_percent |  | double |
| vectra_cloud.health.hostid.updated_at |  | date |
| vectra_cloud.health.memory.free_bytes |  | long |
| vectra_cloud.health.memory.total_bytes |  | long |
| vectra_cloud.health.memory.updated_at |  | date |
| vectra_cloud.health.memory.usage_percent |  | double |
| vectra_cloud.health.memory.used_bytes |  | long |
| vectra_cloud.health.network.interfaces |  | flattened |
| vectra_cloud.health.network.traffic |  | flattened |
| vectra_cloud.health.network.updated_at |  | date |
| vectra_cloud.health.network.vlans.count |  | long |
| vectra_cloud.health.network.vlans.vlan_ids |  | keyword |
| vectra_cloud.health.power.error |  | keyword |
| vectra_cloud.health.power.power_supplies |  | flattened |
| vectra_cloud.health.power.status |  | keyword |
| vectra_cloud.health.power.updated_at |  | date |
| vectra_cloud.health.sensors.headend_ip |  | ip |
| vectra_cloud.health.sensors.headend_url |  | keyword |
| vectra_cloud.health.sensors.id |  | keyword |
| vectra_cloud.health.sensors.ip_address |  | ip |
| vectra_cloud.health.sensors.last_seen |  | date |
| vectra_cloud.health.sensors.location |  | keyword |
| vectra_cloud.health.sensors.luid |  | keyword |
| vectra_cloud.health.sensors.mode |  | keyword |
| vectra_cloud.health.sensors.name |  | keyword |
| vectra_cloud.health.sensors.original_version |  | keyword |
| vectra_cloud.health.sensors.product_name |  | keyword |
| vectra_cloud.health.sensors.public_key |  | keyword |
| vectra_cloud.health.sensors.serial_number |  | keyword |
| vectra_cloud.health.sensors.ssh_tunnel_port |  | keyword |
| vectra_cloud.health.sensors.status |  | keyword |
| vectra_cloud.health.sensors.update_count |  | long |
| vectra_cloud.health.sensors.version |  | keyword |
| vectra_cloud.health.system.serial_number |  | keyword |
| vectra_cloud.health.system.updated_at |  | date |
| vectra_cloud.health.system.uptime |  | keyword |
| vectra_cloud.health.system.version.cloud_bridge |  | boolean |
| vectra_cloud.health.system.version.gmt |  | date |
| vectra_cloud.health.system.version.last_update |  | date |
| vectra_cloud.health.system.version.last_update_utc |  | date |
| vectra_cloud.health.system.version.mode |  | keyword |
| vectra_cloud.health.system.version.model |  | keyword |
| vectra_cloud.health.system.version.vectra_instance_type |  | keyword |
| vectra_cloud.health.system.version.vectra_version |  | keyword |
| vectra_cloud.health.system.version.vm_type |  | keyword |
| vectra_cloud.health.trafficdrop.sensors.error |  | keyword |
| vectra_cloud.health.trafficdrop.sensors.ip_address |  | ip |
| vectra_cloud.health.trafficdrop.sensors.luid |  | keyword |
| vectra_cloud.health.trafficdrop.sensors.name |  | keyword |
| vectra_cloud.health.trafficdrop.sensors.output |  | flattened |
| vectra_cloud.health.trafficdrop.sensors.serial_number |  | keyword |
| vectra_cloud.health.trafficdrop.sensors.status | Status can be OK, WARNING, UNKNOWN, or SKIP. | keyword |
| vectra_cloud.health.trafficdrop.updated_at |  | date |


### Lockdown

This is the `Lockdown` dataset.

#### Example

An example event for `lockdown` looks as following:

```json
{
    "@timestamp": "2023-03-06T22:30:06.000Z",
    "agent": {
        "ephemeral_id": "49698955-0071-46d8-a16d-f0088a3feed5",
        "id": "3ab4c8f0-2526-48d2-847d-ae032b14206f",
        "name": "elastic-agent-98615",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "vectra_cloud.lockdown",
        "namespace": "10855",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "3ab4c8f0-2526-48d2-847d-ae032b14206f",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "host"
        ],
        "dataset": "vectra_cloud.lockdown",
        "end": "2023-03-07T22:30:06.000Z",
        "ingested": "2025-04-22T06:53:52Z",
        "kind": "event",
        "original": "{\"certainty\":0,\"entity_id\":1184,\"entity_name\":\"Windows10_Jump\",\"id\":1,\"lock_event_timestamp\":\"2023-03-06T22:30:06Z\",\"locked_by\":\"vadmin\",\"type\":\"host\",\"unlock_event_timestamp\":\"2023-03-07T22:30:06Z\"}",
        "start": "2023-03-06T22:30:06.000Z",
        "type": [
            "info"
        ]
    },
    "host": {
        "id": "1184",
        "name": "Windows10_Jump"
    },
    "input": {
        "type": "cel"
    },
    "related": {
        "hosts": [
            "1184",
            "Windows10_Jump"
        ],
        "user": [
            "vadmin"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "vectra_cloud-lockdown"
    ],
    "user": {
        "name": "vadmin"
    },
    "vectra_cloud": {
        "lockdown": {
            "certainty": 0,
            "entity_id": "1184",
            "entity_name": "Windows10_Jump",
            "id": "1",
            "lock_event_timestamp": "2023-03-06T22:30:06.000Z",
            "locked_by": "vadmin",
            "type": "host",
            "unlock_event_timestamp": "2023-03-07T22:30:06.000Z"
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
| event.module | Event module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| vectra_cloud.lockdown.certainty |  | long |
| vectra_cloud.lockdown.entity_id | ID of the related entity. | keyword |
| vectra_cloud.lockdown.entity_name | Name of the related entity. | keyword |
| vectra_cloud.lockdown.id | Autoincrementing ID. | keyword |
| vectra_cloud.lockdown.lock_event_timestamp | Time when the lockdown occurred. | date |
| vectra_cloud.lockdown.locked_by | User who issued the lockdown. | keyword |
| vectra_cloud.lockdown.type | Type of the related entity. | keyword |
| vectra_cloud.lockdown.unlock_event_timestamp | Time when the lockdown expires. | date |
