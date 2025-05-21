# Armis

[Armis](https://www.armis.com/) is an enterprise-class security platform designed to provide visibility and protection for managed, unmanaged, and IoT devices. It enables organizations to detect threats, manage vulnerabilities, and enforce security policies across their network.

Use this integration to collect and parse data from your Armis instance.

## Compatibility

This module has been tested against the Armis API version **v1**.

## Data Streams

The Armis integration collects three types of logs.

- **Devices** : Fetches the latest updates for all devices monitored by Armis.
- **Alerts** : Gathers alerts associated with all devices monitored by Armis.
- **Vulnerabilities** : Retrieves detected vulnerabilities and possible mitigation steps across all devices monitored by Armis.

**Note** :

1. The **vulnerability data stream** retrieves information by first fetching vulnerabilities and then identifying the devices where these vulnerabilities were detected, using a chained call between the vulnerability search and vulnerability match endpoints.

## Requirements

### Agentless Enabled Integration
Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent Based Installation
- Elastic Agent must be installed
- You can install only one Elastic Agent per host.
- Elastic Agent is required to stream data from the GCP Pub/Sub or REST API and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

#### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

#### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

#### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

#### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

## Setup

### To collect logs through REST API, follow the below steps:

1. Log in to your Armis portal.
2. Navigate to the **Settings** tab.
3. Select **Asset Management & Security**.
4. Go to **API Management** and generate a **Secret Key**.

### Enabling the integration in Elastic:

1. In Kibana navigate to Management > Integrations.
2. In "Search for integrations" top bar, search for `Armis`.
3. Select the "Armis" integration from the search results.
4. Select "Add Armis" to add the integration.
5. Add all the required integration configuration parameters, including the URL, Secret Key to enable data collection.
6. Select "Save and continue" to save the integration.

## Limitations

1. In the **vulnerability data stream**, our filtering mechanism for the **vulnerability search API** relies specifically on the `lastDetected` field. This means that when a user takes action on a vulnerability and `lastDetected` updates, only then will the event for that vulnerability be retrieved. Initially, we assumed this field would always have a value and could be used as a cursor timestamp for fetching data between intervals. However, due to inconsistencies in the API response, we observed cases where `lastDetected` is `null`.

## Troubleshooting

- If you are seeing below mentioned errors in the **vulnerability data stream**, try reducing the page size in your request.

  **Common errors:**
  - `502 Bad Gateway`
  - `414 Request-URI Too Large`

- If you are encountering issues in the **alert data stream**, particularly during the initial data fetch, try reducing the initial interval.

  **Example error:**
  - `The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application.`

## Logs reference

### Alert

This is the `alert` dataset.

#### Example

An example event for `alert` looks as following:

An example event for `alert` looks as following:

```json
{
    "@timestamp": "2025-03-29T00:12:57.306Z",
    "agent": {
        "ephemeral_id": "693c9ba7-607a-44d6-b0bc-3afdda78193c",
        "id": "64c14a85-1de8-434c-9493-8f31805a1c44",
        "name": "elastic-agent-14454",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "armis": {
        "alert": {
            "activity_uuids": [
                "6f3d6d3a-6732-44cc-9d63-10a38277fb15"
            ],
            "affected_devices_count": 1,
            "alert_id": "61",
            "classification": "Security - Other",
            "description": "The Armis security platform has detected a violation of a policy and generated an alert.",
            "device_ids": [
                "854"
            ],
            "severity": "Critical",
            "status": "Unhandled",
            "status_change_time": "2025-03-29T00:12:57.306Z",
            "time": "2025-03-29T00:12:57.306Z",
            "title": "[Risk] Device Susceptible to Ransomware",
            "type": "System Policy Violation"
        }
    },
    "data_stream": {
        "dataset": "armis.alert",
        "namespace": "11102",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "64c14a85-1de8-434c-9493-8f31805a1c44",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "armis.alert",
        "id": "61",
        "ingested": "2025-05-21T07:44:13Z",
        "kind": "alert",
        "original": "{\"activityUUIDs\":[\"6f3d6d3a-6732-44cc-9d63-10a38277fb15\"],\"affectedDevicesCount\":1,\"alertId\":61,\"classification\":\"Security - Other\",\"connectionIds\":[],\"description\":\"The Armis security platform has detected a violation of a policy and generated an alert.\",\"destinationEndpoints\":[],\"deviceIds\":[854],\"lastAlertUpdateTime\":null,\"mitreAttackLabels\":null,\"policyId\":null,\"policyLabels\":null,\"policyTitle\":null,\"severity\":\"Critical\",\"sourceEndpoints\":[],\"status\":\"Unhandled\",\"statusChangeTime\":\"2025-03-29T00:12:57.306928+00:00\",\"time\":\"2025-03-29T00:12:57.306928+00:00\",\"title\":\"[Risk] Device Susceptible to Ransomware\",\"type\":\"System Policy Violation\"}",
        "severity": 99
    },
    "host": {
        "id": [
            "854"
        ]
    },
    "input": {
        "type": "cel"
    },
    "message": "The Armis security platform has detected a violation of a policy and generated an alert.",
    "observer": {
        "product": "Asset Management and Security",
        "vendor": "Armis"
    },
    "related": {
        "hosts": [
            "854"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "armis-alert"
    ]
}
```

#### Exported fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| armis.alert.activity_uuids |  | keyword |
| armis.alert.affected_devices_count |  | long |
| armis.alert.alert_id |  | keyword |
| armis.alert.classification |  | keyword |
| armis.alert.connection_ids |  | keyword |
| armis.alert.description |  | keyword |
| armis.alert.destination_endpoints |  | keyword |
| armis.alert.device_ids |  | keyword |
| armis.alert.friendly_name |  | keyword |
| armis.alert.last_alert_update_time |  | date |
| armis.alert.mitre_attack_labels |  | keyword |
| armis.alert.policy_id |  | keyword |
| armis.alert.policy_labels |  | keyword |
| armis.alert.policy_title |  | keyword |
| armis.alert.severity |  | keyword |
| armis.alert.source_endpoints |  | keyword |
| armis.alert.status |  | keyword |
| armis.alert.status_change_time |  | date |
| armis.alert.time |  | date |
| armis.alert.title |  | keyword |
| armis.alert.type |  | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |
| log.offset | Log offset. | long |


### Device

This is the `device` dataset.

#### Example

An example event for `device` looks as following:

An example event for `device` looks as following:

```json
{
    "@timestamp": "2025-03-29T10:43:55.988Z",
    "agent": {
        "ephemeral_id": "d10f731b-c124-4bf6-8820-7b873224d411",
        "id": "14af6cec-a54e-4616-a404-4bd1a7f496cd",
        "name": "elastic-agent-52983",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "armis": {
        "device": {
            "boundaries": "Corporate",
            "business_impact": "Unassigned",
            "category": "Network Equipment",
            "data_sources": [
                {
                    "first_seen": "2024-10-09T05:09:02.988Z",
                    "last_seen": "2025-03-29T10:43:55.988Z",
                    "name": "Knowledge Base",
                    "types": [
                        "Traffic Inspection",
                        "Data Analysis"
                    ]
                }
            ],
            "display_title": "Test",
            "first_seen": "2024-10-09T05:09:02.988Z",
            "id": "1154",
            "ip_address": [
                "89.160.20.128"
            ],
            "last_seen": "2025-03-29T10:43:55.988Z",
            "mac_address": [
                "50:76:AF:D3:3F:AB"
            ],
            "manufacturer": "Test Manufacturer",
            "model": "Test Model",
            "name": "Test Name",
            "names": [
                "Test Names"
            ],
            "operating_system": "Windows",
            "operating_system_version": "Server 2016",
            "purdue_level": 4,
            "risk_level": 10,
            "sensor": {
                "name": "test Enterprise",
                "type": "test LAN Controller"
            },
            "site": {
                "location": "Zurich",
                "name": "Zurich Enterprise"
            },
            "tags": [
                "Misconfigurations"
            ],
            "type": "Switches",
            "type_enum": "SWITCH",
            "visibility": "Full"
        }
    },
    "data_stream": {
        "dataset": "armis.device",
        "namespace": "27823",
        "type": "logs"
    },
    "device": {
        "manufacturer": "Test Manufacturer",
        "model": {
            "name": "Test Model"
        }
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "14af6cec-a54e-4616-a404-4bd1a7f496cd",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "host"
        ],
        "dataset": "armis.device",
        "ingested": "2025-05-21T07:45:04Z",
        "kind": "event",
        "original": "{\"accessSwitch\":null,\"boundaries\":\"Corporate\",\"businessImpact\":\"Unassigned\",\"category\":\"Network Equipment\",\"customProperties\":{},\"dataSources\":[{\"firstSeen\":\"2024-10-09T05:09:02.988081+00:00\",\"instances\":[],\"lastSeen\":\"2025-03-29T10:43:55.988081+00:00\",\"name\":\"Knowledge Base\",\"types\":[\"Traffic Inspection\",\"Data Analysis\"]}],\"displayTitle\":\"Test\",\"firstSeen\":\"2024-10-09T05:09:02.988081+00:00\",\"id\":1154,\"ipAddress\":\"89.160.20.128\",\"ipv6\":[],\"lastSeen\":\"2025-03-29T10:43:55.988081+00:00\",\"macAddress\":\"50:76:AF:D3:3F:AB\",\"manufacturer\":\"Test Manufacturer\",\"model\":\"Test Model\",\"name\":\"Test Name\",\"names\":\"Test Names\",\"operatingSystem\":\"Windows\",\"operatingSystemVersion\":\"Server 2016\",\"protections\":[],\"purdueLevel\":4,\"riskLevel\":10,\"sensor\":{\"name\":\"test Enterprise\",\"type\":\"test LAN Controller\"},\"site\":{\"location\":\"Zurich\",\"name\":\"Zurich Enterprise\"},\"tags\":[\"Misconfigurations\"],\"type\":\"Switches\",\"typeEnum\":\"SWITCH\",\"userIds\":[],\"visibility\":\"Full\"}",
        "start": "2024-10-09T05:09:02.988Z",
        "type": [
            "info"
        ]
    },
    "host": {
        "id": "1154",
        "ip": [
            "89.160.20.128"
        ],
        "mac": [
            "50-76-AF-D3-3F-AB"
        ],
        "name": [
            "test names"
        ],
        "os": {
            "family": "windows",
            "version": "Server 2016"
        },
        "risk": {
            "static_score": 10
        },
        "type": "Network Equipment"
    },
    "input": {
        "type": "cel"
    },
    "observer": {
        "product": "Asset Management and Security",
        "vendor": "Armis"
    },
    "related": {
        "hosts": [
            "test names"
        ],
        "ip": [
            "89.160.20.128"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "armis-device"
    ]
}
```

#### Exported fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| armis.device.access_switch |  | keyword |
| armis.device.boundaries |  | keyword |
| armis.device.business_impact |  | keyword |
| armis.device.category |  | keyword |
| armis.device.custom_properties |  | flattened |
| armis.device.data_sources.first_seen |  | date |
| armis.device.data_sources.instances.first_seen |  | date |
| armis.device.data_sources.instances.last_seen |  | date |
| armis.device.data_sources.instances.name |  | keyword |
| armis.device.data_sources.last_seen |  | date |
| armis.device.data_sources.name |  | keyword |
| armis.device.data_sources.types |  | keyword |
| armis.device.display_title |  | keyword |
| armis.device.first_seen |  | date |
| armis.device.id |  | keyword |
| armis.device.ip_address |  | ip |
| armis.device.ip_v6 |  | ip |
| armis.device.last_seen |  | date |
| armis.device.mac_address |  | keyword |
| armis.device.manufacturer |  | keyword |
| armis.device.model |  | keyword |
| armis.device.name |  | keyword |
| armis.device.names |  | keyword |
| armis.device.operating_system |  | keyword |
| armis.device.operating_system_version |  | keyword |
| armis.device.protections.creation_time |  | date |
| armis.device.protections.device_id |  | keyword |
| armis.device.protections.last_seen_time |  | date |
| armis.device.protections.protection_name |  | keyword |
| armis.device.purdue_level |  | double |
| armis.device.risk_level |  | long |
| armis.device.sensor.name |  | keyword |
| armis.device.sensor.type |  | keyword |
| armis.device.site.location |  | keyword |
| armis.device.site.name |  | keyword |
| armis.device.tags |  | keyword |
| armis.device.type |  | keyword |
| armis.device.type_enum |  | keyword |
| armis.device.user_ids |  | keyword |
| armis.device.visibility |  | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |
| log.offset | Log offset. | long |


### Vulnerability

This is the `vulnerability` dataset.

#### Example

An example event for `vulnerability` looks as following:

An example event for `vulnerability` looks as following:

```json
{
    "@timestamp": "2025-04-03T10:38:59.297Z",
    "agent": {
        "ephemeral_id": "10441499-27b3-41da-b6a0-74f54f98a4fd",
        "id": "044f39cb-175e-4747-a359-2c9e3f202e47",
        "name": "elastic-agent-53672",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "armis": {
        "vulnerability": {
            "affected_devices_count": 13,
            "attack_complexity": "Low",
            "attack_vector": "Network",
            "availability_impact": "High",
            "confidentiality_impact": "High",
            "cve_uid": "CVE-2024-44148",
            "cvss_score": 10,
            "description": "This issue was addressed with improved validation of file attributes.",
            "epss_percentile": 0.31,
            "epss_score": 0.00139,
            "exploitability_score": 3.9,
            "first_detected": "2025-04-03T09:18:31.915Z",
            "has_remediation_info": "No",
            "id": "CVE-2024-44148",
            "impact_score": 6,
            "integrity_impact": "High",
            "last_detected": "2025-04-03T10:38:59.372Z",
            "num_of_exploits": 0,
            "number_of_threat_actors": 0,
            "privileges_required": "None",
            "published_date": "2024-09-17T00:15:50.617Z",
            "scope": "Changed",
            "score": 10,
            "severity": "Critical",
            "status": "Open",
            "type": "OS",
            "user_interaction": "None",
            "vulnerability_match": {
                "confidence_level": "High",
                "cve_uid": "CVE-2024-44148",
                "device_id": "109",
                "first_detected": "2025-04-03T10:38:59.297Z",
                "has_remediation_info": "No",
                "last_detected": "2025-04-03T10:38:59.297Z",
                "match_criteria_string": "OS",
                "status": "Open",
                "status_source": "Discovered by Armis"
            }
        }
    },
    "data_stream": {
        "dataset": "armis.vulnerability",
        "namespace": "50611",
        "type": "logs"
    },
    "device": {
        "id": "109"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "044f39cb-175e-4747-a359-2c9e3f202e47",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "vulnerability"
        ],
        "dataset": "armis.vulnerability",
        "ingested": "2025-05-21T07:45:53Z",
        "kind": "event",
        "original": "{\"affectedDevicesCount\":13,\"attackComplexity\":\"Low\",\"attackVector\":\"Network\",\"availabilityImpact\":\"High\",\"avmRating\":null,\"avmRatingManualChangeReason\":null,\"avmRatingManualChangedBy\":\"\",\"avmRatingManualUpdateTime\":null,\"botnets\":null,\"cisaDueDate\":null,\"commonName\":null,\"confidentialityImpact\":\"High\",\"cveUid\":\"CVE-2024-44148\",\"cvssScore\":10,\"cvssScoreV4\":null,\"description\":\"This issue was addressed with improved validation of file attributes.\",\"epssPercentile\":0.31,\"epssScore\":0.00139,\"exploitabilityScore\":3.9,\"firstDetected\":\"2025-04-03T09:18:31.915543+00:00\",\"firstReferencePublishDate\":null,\"firstWeaponizedReferencePublishDate\":null,\"hasRansomware\":null,\"hasRemediationInfo\":\"No\",\"id\":\"CVE-2024-44148\",\"impactScore\":6,\"integrityImpact\":\"High\",\"isWeaponized\":null,\"lastDetected\":\"2025-04-03T10:38:59.372389+00:00\",\"latestExploitUpdate\":null,\"numOfExploits\":0,\"numberOfThreatActors\":0,\"privilegesRequired\":\"None\",\"publishedDate\":\"2024-09-17T00:15:50.617000+00:00\",\"reportedByGoogleZeroDays\":null,\"scope\":\"Changed\",\"score\":10,\"severity\":\"Critical\",\"status\":\"Open\",\"threatActors\":null,\"threatTags\":null,\"type\":\"OS\",\"userInteraction\":\"None\",\"vulnerability_match\":{\"advisoryId\":null,\"avmRating\":null,\"confidenceLevel\":\"High\",\"confidenceLevelDescription\":null,\"cveUid\":\"CVE-2024-44148\",\"deviceId\":109,\"firstDetected\":\"2025-04-03T10:38:59.297015+00:00\",\"hasRemediationInfo\":\"No\",\"lastDetected\":\"2025-04-03T10:38:59.297015+00:00\",\"matchCriteriaString\":\"OS\",\"recommendedSteps\":null,\"remediationTypes\":null,\"status\":\"Open\",\"statusChangeReason\":null,\"statusSource\":\"Discovered by Armis\"}}",
        "start": "2025-04-03T09:18:31.915Z",
        "type": [
            "info"
        ]
    },
    "host": {
        "id": "109"
    },
    "input": {
        "type": "cel"
    },
    "message": "This issue was addressed with improved validation of file attributes.",
    "observer": {
        "product": "Asset Management and Security",
        "vendor": "Armis"
    },
    "related": {
        "hosts": [
            "109"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "armis-vulnerability"
    ],
    "threat": {
        "indicator": {
            "last_seen": "2025-04-03T10:38:59.297Z"
        }
    },
    "vulnerability": {
        "category": [
            "Network"
        ],
        "description": "This issue was addressed with improved validation of file attributes.",
        "id": "CVE-2024-44148",
        "scanner": {
            "vendor": "Armis"
        },
        "severity": "Critical"
    }
}
```

#### Exported fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| armis.vulnerability.affected_devices_count |  | long |
| armis.vulnerability.attack_complexity |  | keyword |
| armis.vulnerability.attack_vector |  | keyword |
| armis.vulnerability.availability_impact |  | keyword |
| armis.vulnerability.avm_rating |  | keyword |
| armis.vulnerability.avm_rating_manual_change_reason |  | keyword |
| armis.vulnerability.avm_rating_manual_changed_by |  | keyword |
| armis.vulnerability.avm_rating_manual_update_time |  | date |
| armis.vulnerability.botnets |  | keyword |
| armis.vulnerability.cisa_due_date |  | date |
| armis.vulnerability.common_name |  | keyword |
| armis.vulnerability.confidentiality_impact |  | keyword |
| armis.vulnerability.cve_uid |  | keyword |
| armis.vulnerability.cvss_score |  | double |
| armis.vulnerability.cvss_score_v4 |  | keyword |
| armis.vulnerability.description |  | keyword |
| armis.vulnerability.epss_percentile |  | double |
| armis.vulnerability.epss_score |  | double |
| armis.vulnerability.exploitability_score |  | double |
| armis.vulnerability.first_detected |  | date |
| armis.vulnerability.first_reference_publish_date |  | date |
| armis.vulnerability.first_weaponized_reference_publish_date |  | date |
| armis.vulnerability.has_ransomware |  | boolean |
| armis.vulnerability.has_remediation_info |  | keyword |
| armis.vulnerability.id |  | keyword |
| armis.vulnerability.impact_score |  | double |
| armis.vulnerability.integrity_impact |  | keyword |
| armis.vulnerability.is_weaponized |  | boolean |
| armis.vulnerability.last_detected |  | date |
| armis.vulnerability.latest_exploit_update |  | date |
| armis.vulnerability.num_of_exploits |  | long |
| armis.vulnerability.number_of_threat_actors |  | long |
| armis.vulnerability.privileges_required |  | keyword |
| armis.vulnerability.published_date |  | date |
| armis.vulnerability.reported_by_google_zero_days |  | boolean |
| armis.vulnerability.scope |  | keyword |
| armis.vulnerability.score |  | double |
| armis.vulnerability.severity |  | keyword |
| armis.vulnerability.status |  | keyword |
| armis.vulnerability.threat_actors |  | keyword |
| armis.vulnerability.threat_tags |  | keyword |
| armis.vulnerability.type |  | keyword |
| armis.vulnerability.user_interaction |  | keyword |
| armis.vulnerability.vulnerability_match.advisory_id |  | keyword |
| armis.vulnerability.vulnerability_match.avm_rating |  | keyword |
| armis.vulnerability.vulnerability_match.confidence_level |  | keyword |
| armis.vulnerability.vulnerability_match.confidence_level_description |  | keyword |
| armis.vulnerability.vulnerability_match.cve_uid |  | keyword |
| armis.vulnerability.vulnerability_match.device_id |  | keyword |
| armis.vulnerability.vulnerability_match.first_detected |  | date |
| armis.vulnerability.vulnerability_match.has_remediation_info |  | keyword |
| armis.vulnerability.vulnerability_match.last_detected |  | date |
| armis.vulnerability.vulnerability_match.match_criteria_string |  | keyword |
| armis.vulnerability.vulnerability_match.recommended_steps |  | keyword |
| armis.vulnerability.vulnerability_match.remediation_types |  | keyword |
| armis.vulnerability.vulnerability_match.status |  | keyword |
| armis.vulnerability.vulnerability_match.status_change_reason |  | keyword |
| armis.vulnerability.vulnerability_match.status_source |  | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |
| log.offset | Log offset. | long |

