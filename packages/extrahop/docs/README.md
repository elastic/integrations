# ExtraHop

## Overview

[ExtraHop](https://www.extrahop.com/) delivers complete network visibility through its agentless RevealX NDR platform, empowering security teams to close detection gaps left by EDR, SIEM, and logs. ExtraHop provides the deep intelligence needed to detect threats faster, investigate with greater context, and respond at the speed of modern risk.

This integration enables to collect, Detection data via [ExtraHop RevealX 360 API](https://docs.extrahop.com/current/rx360-rest-api/), then visualise the data in Kibana.

## Data streams

The ExtraHop integration collects logs for one type of event.

**Detection:** This datastream enables you to retrieve detections that have been identified by the ExtraHop system.

## Requirements

### Agentless enabled integration
Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent based installation
Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

## Compatibility

For the REST API, this module has been tested against **ExtraHop RevealX 360 version 25.2 using the v1** API.

## Setup

### Enable the REST API for RevealX 360:

1. Log in to RevealX 360.
2. Click the System Settings icon at the top right of the page and then click **All Administration**.
3. Click **API Access**.
4. In the Manage API Access section, click **Enable**.
>**Note**: If you disable and then re-enable the REST API, the REST API might be unavailable for approximately 15 minutes due to DNS propagation, even if the Status section indicates that access is enabled. We recommend that you do not disable and re-enable the REST API often.

### To collect data from the ExtraHop RevealX 360 API:

1. Log in to RevealX 360.
2. Click the System Settings icon at the top right of the page and then click **All Administration**.
3. Click **API Access**.
4. Click **Create Credentials**.
5. In the **Name** field, type a name for the credentials.
6. In the **Privileges** field, specify a privilege level for the credentials. For more information about each privilege level, see [ExtraHop user account privileges](https://docs.extrahop.com/25.2/users-overview/#extrahop-user-account-privileges).
7. In the **Packet Access** field, specify whether you can retrieve packets and session keys with the credentials.
8. Click **Save**.
9. Copy REST API **Credentials**.

For more details, see [Documentation](https://docs.extrahop.com/current/rx360-rest-api/).

>**Note**: You must have system and access administration privileges.

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search top bar, type **ExtraHop**.
3. Select the **ExtraHop** integration and add it.
4. Add all the required integration configuration parameters: URL, Client ID and Client Secret.
5. Save the integration.

## Logs reference

### Detection

This is the `Detection` dataset.

#### Example

An example event for `detection` looks as following:

```json
{
    "@timestamp": "2025-02-19T16:25:42.927Z",
    "agent": {
        "ephemeral_id": "2771a69d-7394-4328-9019-49735bd8f885",
        "id": "3804bd48-1872-46b7-9dbc-0390cbbea830",
        "name": "elastic-agent-34521",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "extrahop.detection",
        "namespace": "60020",
        "type": "logs"
    },
    "device": {
        "id": "6"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "3804bd48-1872-46b7-9dbc-0390cbbea830",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2025-02-19T16:24:44.047Z",
        "dataset": "extrahop.detection",
        "id": "25769803828-1739982342927",
        "ingested": "2025-07-14T06:54:49Z",
        "kind": "event",
        "original": "{\"appliance_id\":6,\"assignee\":\"sam.joe\",\"categories\":[\"sec\",\"sec.command\",\"sec.attack\"],\"create_time\":1739982284047,\"description\":\"[Device 0e8398d29d3b0000](https://extrahop-bd.cloud.extrahop.com#/metrics/devices/71c6ffe3ae8548bbbb9bf279c912d3ae.0e8398d29d3b0000/overview?from=1739982210\\u0026interval_type=DT\\u0026until=1739982300) sent ICMP requests that contain unique payloads to an external IP address. The number of requests was unusually high compared to past activity for this device. Check for unexpected or unauthorized activity, such as hidden information within ping packets.\\n\\nThis device sent approximately 13000 ICMP requests with unique payloads to external hosts.\",\"end_time\":1739982300000,\"id\":25769803828,\"is_user_created\":false,\"mitre_tactics\":[{\"id\":\"TA0011\",\"name\":\"Command and Control\",\"url\":\"https://attack.mitre.org/tactics/TA0011\"}],\"mitre_techniques\":[{\"id\":\"T1095\",\"legacy_ids\":[\"T1094\",\"T1095\"],\"name\":\"Non-Application Layer Protocol\",\"url\":\"https://attack.mitre.org/techniques/T1095\"},{\"id\":\"T1572\",\"name\":\"Protocol Tunneling\",\"url\":\"https://attack.mitre.org/techniques/T1572\"}],\"mod_time\":1739982342927,\"participants\":[{\"endpoint\":\"receiver\",\"external\":true,\"hostname\":\"09i2TY0xVtw7DPECOJQte01i7IK8B9FV.rx.tours\",\"id\":7189,\"object_id\":25769803780,\"object_type\":\"ipaddr\",\"object_value\":\"175.16.199.0\",\"role\":\"offender\",\"scanner_service\":null,\"username\":null},{\"endpoint\":\"sender\",\"external\":false,\"id\":7167,\"object_id\":25769803807,\"object_type\":\"device\",\"object_value\":\"81.2.69.142\",\"role\":\"victim\",\"scanner_service\":null,\"username\":null}],\"properties\":{},\"recommended\":true,\"recommended_factors\":[\"rare_type\",\"top_offender\"],\"resolution\":\"action_taken\",\"risk_score\":61,\"start_time\":1739982210001,\"status\":\"open\",\"ticket_id\":\"2996\",\"title\":\"ICMP Tunnel\",\"type\":\"icmp_tunnel\",\"update_time\":1739982300000,\"url\":\"https://extrahop-bd.cloud.extrahop.com/extrahop/#/detections/detail/25769803828/?from=1739981310\\u0026until=1739983200\\u0026interval_type=DT\"}",
        "risk_score": 61,
        "start": "2025-02-19T16:23:30.001Z",
        "type": [
            "indicator"
        ],
        "url": "https://extrahop-bd.cloud.extrahop.com/extrahop/#/detections/detail/25769803828/?from=1739981310&until=1739983200&interval_type=DT"
    },
    "extrahop": {
        "detection": {
            "appliance_id": "6",
            "assignee": "sam.joe",
            "categories": [
                "sec",
                "sec.command",
                "sec.attack"
            ],
            "create_time": "2025-02-19T16:24:44.047Z",
            "description": "[Device 0e8398d29d3b0000](https://extrahop-bd.cloud.extrahop.com#/metrics/devices/71c6ffe3ae8548bbbb9bf279c912d3ae.0e8398d29d3b0000/overview?from=1739982210&interval_type=DT&until=1739982300) sent ICMP requests that contain unique payloads to an external IP address. The number of requests was unusually high compared to past activity for this device. Check for unexpected or unauthorized activity, such as hidden information within ping packets.\n\nThis device sent approximately 13000 ICMP requests with unique payloads to external hosts.",
            "id": "25769803828",
            "is_user_created": false,
            "mitre_tactics": [
                {
                    "id": "TA0011",
                    "name": "Command and Control",
                    "url": "https://attack.mitre.org/tactics/TA0011"
                }
            ],
            "mitre_techniques": [
                {
                    "id": "T1095",
                    "legacy_ids": [
                        "T1094",
                        "T1095"
                    ],
                    "name": "Non-Application Layer Protocol",
                    "url": "https://attack.mitre.org/techniques/T1095"
                },
                {
                    "id": "T1572",
                    "name": "Protocol Tunneling",
                    "url": "https://attack.mitre.org/techniques/T1572"
                }
            ],
            "mod_time": "2025-02-19T16:25:42.927Z",
            "participants": [
                {
                    "endpoint": "receiver",
                    "external": true,
                    "hostname": "09i2TY0xVtw7DPECOJQte01i7IK8B9FV.rx.tours",
                    "id": "7189",
                    "object_id": "25769803780",
                    "object_type": "ipaddr",
                    "object_value": "175.16.199.0",
                    "role": "offender"
                },
                {
                    "endpoint": "sender",
                    "external": false,
                    "id": "7167",
                    "object_id": "25769803807",
                    "object_type": "device",
                    "object_value": "81.2.69.142",
                    "role": "victim"
                }
            ],
            "recommended": true,
            "recommended_factors": [
                "rare_type",
                "top_offender"
            ],
            "resolution": "action_taken",
            "risk_score": 61,
            "start_time": "2025-02-19T16:23:30.001Z",
            "status": "open",
            "ticket_id": "2996",
            "title": "ICMP Tunnel",
            "type": "icmp_tunnel",
            "update_time": "2025-02-19T16:25:00.000Z",
            "url": "https://extrahop-bd.cloud.extrahop.com/extrahop/#/detections/detail/25769803828/?from=1739981310&until=1739983200&interval_type=DT"
        }
    },
    "input": {
        "type": "cel"
    },
    "message": "ICMP Tunnel",
    "related": {
        "hosts": [
            "09i2TY0xVtw7DPECOJQte01i7IK8B9FV.rx.tours"
        ],
        "ip": [
            "175.16.199.0",
            "81.2.69.142"
        ],
        "user": [
            "sam.joe"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "extrahop-detection"
    ],
    "threat": {
        "indicator": {
            "description": "[Device 0e8398d29d3b0000](https://extrahop-bd.cloud.extrahop.com#/metrics/devices/71c6ffe3ae8548bbbb9bf279c912d3ae.0e8398d29d3b0000/overview?from=1739982210&interval_type=DT&until=1739982300) sent ICMP requests that contain unique payloads to an external IP address. The number of requests was unusually high compared to past activity for this device. Check for unexpected or unauthorized activity, such as hidden information within ping packets.\n\nThis device sent approximately 13000 ICMP requests with unique payloads to external hosts.",
            "modified_at": "2025-02-19T16:25:42.927Z"
        },
        "tactic": {
            "id": [
                "TA0011"
            ],
            "name": [
                "Command and Control"
            ],
            "reference": [
                "https://attack.mitre.org/tactics/TA0011"
            ]
        },
        "technique": {
            "id": [
                "T1095",
                "T1572"
            ],
            "name": [
                "Non-Application Layer Protocol",
                "Protocol Tunneling"
            ],
            "reference": [
                "https://attack.mitre.org/techniques/T1095",
                "https://attack.mitre.org/techniques/T1572"
            ]
        }
    },
    "user": {
        "name": "sam.joe"
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
| extrahop.detection.appliance_id |  | keyword |
| extrahop.detection.assignee |  | keyword |
| extrahop.detection.categories |  | keyword |
| extrahop.detection.create_time |  | date |
| extrahop.detection.description |  | keyword |
| extrahop.detection.id |  | keyword |
| extrahop.detection.is_user_created |  | boolean |
| extrahop.detection.mitre_tactics.id |  | keyword |
| extrahop.detection.mitre_tactics.name |  | keyword |
| extrahop.detection.mitre_tactics.url |  | keyword |
| extrahop.detection.mitre_techniques.id |  | keyword |
| extrahop.detection.mitre_techniques.legacy_ids |  | keyword |
| extrahop.detection.mitre_techniques.name |  | keyword |
| extrahop.detection.mitre_techniques.url |  | keyword |
| extrahop.detection.mod_time |  | date |
| extrahop.detection.participants.endpoint |  | keyword |
| extrahop.detection.participants.external |  | boolean |
| extrahop.detection.participants.hostname |  | keyword |
| extrahop.detection.participants.id |  | keyword |
| extrahop.detection.participants.object_id |  | keyword |
| extrahop.detection.participants.object_type |  | keyword |
| extrahop.detection.participants.object_value |  | ip |
| extrahop.detection.participants.role |  | keyword |
| extrahop.detection.participants.scanner_service |  | keyword |
| extrahop.detection.participants.username |  | keyword |
| extrahop.detection.properties.certificate |  | keyword |
| extrahop.detection.properties.client_port |  | long |
| extrahop.detection.properties.hacking_tool_name |  | keyword |
| extrahop.detection.properties.server_port |  | long |
| extrahop.detection.recommended |  | boolean |
| extrahop.detection.recommended_factors |  | keyword |
| extrahop.detection.resolution |  | keyword |
| extrahop.detection.risk_score |  | float |
| extrahop.detection.start_time |  | date |
| extrahop.detection.status |  | keyword |
| extrahop.detection.ticket_id |  | keyword |
| extrahop.detection.ticket_url |  | keyword |
| extrahop.detection.title |  | match_only_text |
| extrahop.detection.type |  | keyword |
| extrahop.detection.update_time |  | date |
| extrahop.detection.url |  | keyword |
| input.type | Type of filebeat input. | keyword |
| labels.is_transform_source | Indicates whether a detection is in the raw source data stream, or the in latest destination index. | constant_keyword |
| log.offset | Log offset. | long |
| observer.product |  | constant_keyword |
| observer.type |  | constant_keyword |
| observer.vendor |  | constant_keyword |
