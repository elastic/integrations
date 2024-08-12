# Digital Guardian

This integration is for ingesting events and alerts from [Fortra's Digital Guardian](https://www.digitalguardian.com/). Fortra’s Digital Guardian helps organizations protect data, performing across the corporate network, traditional endpoints, and cloud applications. Digital Guardian's data loss prevention, available as a software-as-a-service or managed service, helps to see that data, support compliance initiatives, and protect against serious risk. 

The integration allows collection of events and alerts from [Digital Guardian Analytics & Reporting Cloud (ARC)](https://www.digitalguardian.com/blog/new-dawn-dlp-digital-guardian-releases-its-analytics-reporting-cloud-arc) via the REST API.

## Data streams

The Digital Guardian integration collects events to populate following data-streams:

- `digital_guardian.arc`: Collects all events and alerts from `Digital Guardian Analytics & Reporting Cloud (ARC)` via the REST API.

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

## Setup

### Digital Guardian ARC

#### Copy Digital Guardian ARC required configuration properties:

1. Copy `Client ID`: From ARC Tenant Settings, copy the Tenant ID.
2. Copy `Client Secret`: From ARC Tenant Settings, copy the Authentication Token.
3. Copy `ARC Server URL`: From Digital Guardian Management Console (DGMC), copy the Access Gateway Base URL.
4. Copy `Authorization Server URL`: From Digital Guardian Management Console (DGMC), copy the Authorization server URL.
5. Copy `ARC Export Profile ID`: 
    - Navigate to `Admin > reports > export profiles`
    - Copy only the GUID part from the export profile.

#### Enabling the Digital Guardian integration in Elastic with ARC dataset:

1. In Kibana go to Management > Integrations.
2. In "Search for integrations" search bar, type Digital Guardian.
3. Click on the "Digital Guardian" integration from the search results.
4. Click on the "Add Digital Guardian" button to add the integration.
5. Configure all required integration parameters. 
    - ARC data requires following parameters:
        - `Client ID`
        - `Client Secret`
        - `ARC Server URL`
        - `Authorization Server URL`
        - `ARC Export Profile ID`
6. Save the integration.

## Logs reference

### arc

This is the `arc` dataset.

#### Example

An example event for `arc` looks as following:

```json
{
    "@timestamp": "2023-05-23T06:56:39.000Z",
    "agent": {
        "ephemeral_id": "bc19c27a-7a31-4b0c-b04b-b3be2ab95a02",
        "id": "1edfb948-2ef5-4b96-8747-225d782bb6dd",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "digital_guardian.arc",
        "namespace": "19912",
        "type": "logs"
    },
    "digital_guardian": {
        "arc": {
            "dg_description": "This file outlook.exe was going to [demo.digitalg@gmail.com]",
            "dg_guid": "1dc3c1fa-5474-4fc0-a7c3-74ff42d28e5e",
            "dg_name": "test has attached a Salesforce data to an email",
            "dg_tenant": "279b59f3-02f3-44ea-a7c3-9bac2eb0224d",
            "dg_utype": "Incident",
            "inc_assign": "test@dgdemo",
            "inc_creator": "dg",
            "inc_id": "230523-WIQHA",
            "inc_mtime": "2023-05-23T06:56:39.000Z",
            "inc_sev": "Critical",
            "inc_state": "Created"
        }
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "1edfb948-2ef5-4b96-8747-225d782bb6dd",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "action": "incident-created",
        "agent_id_status": "verified",
        "dataset": "digital_guardian.arc",
        "id": "1dc3c1fa-5474-4fc0-a7c3-74ff42d28e5e",
        "ingested": "2024-07-30T15:23:06Z",
        "kind": "alert",
        "original": "{\"dg_comment\":\"-\",\"dg_description\":\"This file outlook.exe was going to [demo.digitalg@gmail.com]\",\"dg_guid\":\"1dc3c1fa-5474-4fc0-a7c3-74ff42d28e5e\",\"dg_name\":\"test has attached a Salesforce data to an email\",\"dg_tenant\":\"279b59f3-02f3-44ea-a7c3-9bac2eb0224d\",\"dg_utype\":\"Incident\",\"inc_assign\":\"test@dgdemo\",\"inc_creator\":\"dg\",\"inc_id\":\"230523-WIQHA\",\"inc_mtime\":\"2023-05-23 06:56:39\",\"inc_sev\":\"Critical\",\"inc_state\":\"Created\"}",
        "severity": 1
    },
    "input": {
        "type": "cel"
    },
    "related": {
        "user": [
            "dg",
            "test@dgdemo"
        ]
    },
    "rule": {
        "name": "test has attached a Salesforce data to an email"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "digital_guardian-arc"
    ],
    "user": {
        "name": "dg"
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
| digital_guardian.arc.dg_comment | Comment | keyword |
| digital_guardian.arc.dg_description | Description | keyword |
| digital_guardian.arc.dg_guid | Unique ID | keyword |
| digital_guardian.arc.dg_name | Name. | keyword |
| digital_guardian.arc.dg_tenant | Tenant ID | keyword |
| digital_guardian.arc.dg_utype | Operation Type | keyword |
| digital_guardian.arc.inc_assign | Incident Assignee | keyword |
| digital_guardian.arc.inc_creator | Incident Creator | keyword |
| digital_guardian.arc.inc_id | Incident ID | keyword |
| digital_guardian.arc.inc_mtime | Incident Modified Time | date |
| digital_guardian.arc.inc_sev | Incident Severity | keyword |
| digital_guardian.arc.inc_state | Incident State | keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |

