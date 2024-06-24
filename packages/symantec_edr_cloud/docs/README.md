# Symantec EDR Cloud

Symantec Endpoint Security is the fully cloud-managed version of the on-premises Symantec Endpoint Protection (SEP), which delivers multilayer protection to stop threats regardless of how they attack your endpoints. You manage Symantec Endpoint Security through a unified cloud console that provides threat visibility across your endpoints and uses multiple technologies to manage the security of your organization.

## Data streams

This integration supports ingestion of incidents from Symantec EDR Cloud, via the [Incidents API](https://apidocs.securitycloud.symantec.com/#/doc?id=edr_incidents).

**Incident** is used to retrieve EDR incidents. See more details in the API documentation [here](https://apidocs.securitycloud.symantec.com/#/doc?id=edr_incidents).

## Requirements

Elastic Agent must be installed. For more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).  

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

This module has been tested against the **Symantec EDR Cloud API Version v1**.

## Setup

### To collect data from Symantec EDR Cloud, the following parameters from your Symantec EDR Cloud instance are required:

1. Client ID
2. Client Secret

### Steps to obtain Client ID and Client Secret:

1. Login to your [Symantec EDR Cloud console](https://sep.securitycloud.symantec.com/v2/landing).
2. Click Integration > Client Applications.
3. Click Add for adding Client Application.
4. Enter Client Application Name and press the Add button.
5. Select Client Secret from the top.
6. Copy the Client ID and Client Secret.

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations
2. In "Search for integrations" search bar, type Symantec EDR Cloud
3. Click on the "Symantec EDR Cloud" integration from the search results.
4. Click on the "Add Symantec EDR Cloud" button to add the integration.
5. Add all the required integration configuration parameters, such as Client ID, Client Secret, URL, and Token URL. For incident data stream, these parameters must be provided in order to retrieve logs.
6. Save the integration.

### Troubleshooting

If the user stops integration and starts integration again after 30 days, then user will not be able to collect data and will get an error as Symantec EDR Cloud only collects data for the last 30 days. To avoid this issue, create a new integration instead of restarting it after 30 days.

## Logs Reference

### Incident

This is the `Incident` dataset.

#### Example

An example event for `incident` looks as following:

```json
{
    "@timestamp": "2023-04-26T21:46:10.400Z",
    "agent": {
        "ephemeral_id": "e84ef800-cd51-4dd1-b1f4-c33951281380",
        "id": "94a22d9c-6d6d-444a-9f96-6383ca581cef",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.10.1"
    },
    "data_stream": {
        "dataset": "symantec_edr_cloud.incident",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "94a22d9c-6d6d-444a-9f96-6383ca581cef",
        "snapshot": false,
        "version": "8.10.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "malware"
        ],
        "created": "2023-04-26T21:46:10.400Z",
        "dataset": "symantec_edr_cloud.incident",
        "id": "8e7edfb1-27d2-4837-98ca-e7d794119c3b",
        "ingested": "2023-10-25T06:42:49Z",
        "kind": "alert",
        "original": "{\"category_id\":1,\"conclusion\":\"Suspicious Activity\",\"created\":\"2023-04-26T21:46:10.400+00:00\",\"customer_uid\":\"TEST-JvOsaJktSS-eyL-dXhxOvA\",\"detection_type\":\"Advanced Analytics\",\"device_time\":1682545570400,\"domain_uid\":\"TEST-ZBg_IqnyTAijNjP2BOOcuw\",\"event_id\":8075004,\"id\":4,\"incident_uid\":\"8e7edfb1-27d2-4837-98ca-e7d794119c3b\",\"incident_url\":\"https://sep.securitycloud.symantec.com/v2/incidents/incidentListing/8e7edfb1-27d2-4837-98ca-e7d794119c3b/details\",\"message\":\"Victim-2:Signed Binary Proxy Execution, Deobfuscate/Decode Files or Information, Command and Scripting Interpreter: PowerShell, System Services: Service Execution\",\"modified\":\"2023-04-26T22:01:58.648+00:00\",\"priority_id\":4,\"product_name\":\"Symantec Integrated Cyber Defense Manager\",\"product_uid\":\"31B0C880-0229-49E8-94C5-48D56B1BD7B9\",\"ref_incident_uid\":102110,\"remediation\":\"Investigate further activity at the endpoint by downloading a full dump of the endpoint's recorded data. Give particular attention to activities performed by cmd.exe.\",\"resolution_id\":1,\"rule_name\":\"Advanced Attack Technique\",\"severity_id\":4,\"state_id\":1,\"suspected_breach\":\"Yes\",\"time\":1682545570400,\"type\":\"INCIDENT_CREATION\",\"type_id\":8075,\"version\":\"1.0\"}",
        "provider": "Symantec Integrated Cyber Defense Manager",
        "reason": "Suspicious Activity",
        "severity": 4,
        "type": [
            "info"
        ],
        "url": "https://sep.securitycloud.symantec.com/v2/incidents/incidentListing/8e7edfb1-27d2-4837-98ca-e7d794119c3b/details"
    },
    "http": {
        "version": "1.0"
    },
    "input": {
        "type": "cel"
    },
    "message": "Victim-2:Signed Binary Proxy Execution, Deobfuscate/Decode Files or Information, Command and Scripting Interpreter: PowerShell, System Services: Service Execution",
    "rule": {
        "name": "Advanced Attack Technique"
    },
    "symantec_edr_cloud": {
        "incident": {
            "category": "Security",
            "category_id": "1",
            "conclusion": "Suspicious Activity",
            "created": "2023-04-26T21:46:10.400Z",
            "customer_uid": "TEST-JvOsaJktSS-eyL-dXhxOvA",
            "detection_type": "Advanced Analytics",
            "device_time": "2023-04-26T21:46:10.400Z",
            "domain_uid": "TEST-ZBg_IqnyTAijNjP2BOOcuw",
            "event": "Incident Creation: Logged",
            "event_id": "8075004",
            "id": "4",
            "incident_uid": "8e7edfb1-27d2-4837-98ca-e7d794119c3b",
            "incident_url": "https://sep.securitycloud.symantec.com/v2/incidents/incidentListing/8e7edfb1-27d2-4837-98ca-e7d794119c3b/details",
            "message": "Victim-2:Signed Binary Proxy Execution, Deobfuscate/Decode Files or Information, Command and Scripting Interpreter: PowerShell, System Services: Service Execution",
            "modified": "2023-04-26T22:01:58.648Z",
            "outcome": "Logged",
            "priority": "Critical",
            "priority_id": "4",
            "product_name": "Symantec Integrated Cyber Defense Manager",
            "product_uid": "31B0C880-0229-49E8-94C5-48D56B1BD7B9",
            "ref_incident_uid": "102110",
            "remediation": "Investigate further activity at the endpoint by downloading a full dump of the endpoint's recorded data. Give particular attention to activities performed by cmd.exe.",
            "resolution": "Insufficient data",
            "resolution_id": "1",
            "rule_name": "Advanced Attack Technique",
            "severity": "Major",
            "severity_id": 4,
            "state": "New",
            "state_id": "1",
            "suspected_breach": true,
            "time": "2023-04-26T21:46:10.400Z",
            "type": "INCIDENT_CREATION",
            "type_id": "8075",
            "version": "1.0"
        }
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "symantec_edr_cloud-incident"
    ],
    "url": {
        "domain": "sep.securitycloud.symantec.com",
        "original": "https://sep.securitycloud.symantec.com/v2/incidents/incidentListing/8e7edfb1-27d2-4837-98ca-e7d794119c3b/details",
        "path": "/v2/incidents/incidentListing/8e7edfb1-27d2-4837-98ca-e7d794119c3b/details",
        "scheme": "https"
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
| symantec_edr_cloud.incident.category |  | keyword |
| symantec_edr_cloud.incident.category_id | Event type category. | keyword |
| symantec_edr_cloud.incident.conclusion |  | keyword |
| symantec_edr_cloud.incident.created | The creation time of the incident in ISO 8601 format. | date |
| symantec_edr_cloud.incident.customer_uid | Customer id. | keyword |
| symantec_edr_cloud.incident.detection_type |  | keyword |
| symantec_edr_cloud.incident.device_time | The time that the event occurred at the device. | date |
| symantec_edr_cloud.incident.domain_uid | Domain Id. | keyword |
| symantec_edr_cloud.incident.event |  | keyword |
| symantec_edr_cloud.incident.event_id | ID that identifies the semantics, structure and outcome. | keyword |
| symantec_edr_cloud.incident.id | The outcome of the event. | keyword |
| symantec_edr_cloud.incident.incident_uid | A unique identifier for this incident. | keyword |
| symantec_edr_cloud.incident.incident_url | The url pointing to ICDM console for this incident details. | keyword |
| symantec_edr_cloud.incident.log_time |  | date |
| symantec_edr_cloud.incident.message |  | keyword |
| symantec_edr_cloud.incident.modified |  | date |
| symantec_edr_cloud.incident.outcome |  | keyword |
| symantec_edr_cloud.incident.priority |  | keyword |
| symantec_edr_cloud.incident.priority_id |  | keyword |
| symantec_edr_cloud.incident.product_name | The name of the product originating the incident. | keyword |
| symantec_edr_cloud.incident.product_uid | The unique identifier of the product originating the incident. | keyword |
| symantec_edr_cloud.incident.ref_incident_uid | User friendly ID for this incident_uid. | keyword |
| symantec_edr_cloud.incident.remediation | Recommended action. | keyword |
| symantec_edr_cloud.incident.resolution |  | keyword |
| symantec_edr_cloud.incident.resolution_id |  | keyword |
| symantec_edr_cloud.incident.rule_name | The rule that triggered the incident. | keyword |
| symantec_edr_cloud.incident.severity |  | keyword |
| symantec_edr_cloud.incident.severity_id |  | long |
| symantec_edr_cloud.incident.state |  | keyword |
| symantec_edr_cloud.incident.state_id |  | keyword |
| symantec_edr_cloud.incident.suspected_breach |  | boolean |
| symantec_edr_cloud.incident.time | The event occurrence time. | date |
| symantec_edr_cloud.incident.type | Event type. | keyword |
| symantec_edr_cloud.incident.type_id |  | keyword |
| symantec_edr_cloud.incident.version | API version in the form major.minor. | keyword |

