# Digital Guardian

This integration is for ingesting events and alerts from [Fortra's Digital Guardian](https://www.digitalguardian.com/). Fortra’s Digital Guardian helps organizations protect data, performing across the corporate network, traditional endpoints, and cloud applications. Digital Guardian's data loss prevention, available as a software-as-a-service or managed service, helps to see that data, support compliance initiatives, and protect against serious risk. 

The integration allows collection of events and alerts from [Digital Guardian Analytics & Reporting Cloud (ARC)](https://www.digitalguardian.com/blog/new-dawn-dlp-digital-guardian-releases-its-analytics-reporting-cloud-arc) via the REST API.

## Data streams

The Digital Guardian integration collects events to populate following data-streams:

- **digital_guardian.arc**: Collects all events and alerts from `Digital Guardian Analytics & Reporting Cloud (ARC)` via the REST API.

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

1. In Kibana navigate to Management > Integrations.
2. In "Search for integrations" top bar, search for `Digital Guardian`.
3. Select the "Digital Guardian" integration from the search results.
4. Select "Add Digital Guardian" to add the integration.
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

The `@timestamp` field will be assigned one of several values, in the following order of precedence:
1. `digital_guardian.arc.dg_time`
2. `digital_guardian.arc.dg_processed_time`
3. `digital_guardian.arc.inc_mtime`
4. The time received by the pipeline (if none of the above are available).

#### Example

An example event for `arc` looks as following:

```json
{
    "@timestamp": "2025-02-18T04:00:28.647Z",
    "agent": {
        "ephemeral_id": "3d727e8f-6944-41c1-a55a-dd22db00d883",
        "id": "8ae590fa-6e28-49e6-9e43-f64705ab4e6b",
        "name": "elastic-agent-15774",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "digital_guardian.arc",
        "namespace": "94938",
        "type": "logs"
    },
    "digital_guardian": {
        "arc": {
            "dg_description": "This file outlook.exe was going to [demo.digitalg@gmail.com]",
            "dg_guid": "1dc3c1fa-5474-4fc0-a7c3-74ff42d28e5e",
            "dg_name": "test has attached a Salesforce data to an email",
            "dg_tenant": "279b59f3-02f3-44ea-a7c3-9bac2eb0224d",
            "dg_utype": "Incident",
            "export_profile": "abc123",
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
        "id": "8ae590fa-6e28-49e6-9e43-f64705ab4e6b",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "action": "incident-created",
        "agent_id_status": "verified",
        "dataset": "digital_guardian.arc",
        "id": "1dc3c1fa-5474-4fc0-a7c3-74ff42d28e5e",
        "ingested": "2025-02-18T04:00:31Z",
        "kind": "alert",
        "original": "{\"dg_comment\":\"-\",\"dg_description\":\"This file outlook.exe was going to [demo.digitalg@gmail.com]\",\"dg_guid\":\"1dc3c1fa-5474-4fc0-a7c3-74ff42d28e5e\",\"dg_name\":\"test has attached a Salesforce data to an email\",\"dg_tenant\":\"279b59f3-02f3-44ea-a7c3-9bac2eb0224d\",\"dg_utype\":\"Incident\",\"export_profile\":\"abc123\",\"inc_assign\":\"test@dgdemo\",\"inc_creator\":\"dg\",\"inc_id\":\"230523-WIQHA\",\"inc_mtime\":\"2023-05-23 06:56:39\",\"inc_sev\":\"Critical\",\"inc_state\":\"Created\"}",
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
| digital_guardian.arc.dg_alert.alert_al | Alert AL | keyword |
| digital_guardian.arc.dg_alert.alert_at | Alert AT | keyword |
| digital_guardian.arc.dg_alert.alert_bc | Alert BC | keyword |
| digital_guardian.arc.dg_alert.alert_did | Alert DID | keyword |
| digital_guardian.arc.dg_alert.alert_etl | Alert ETL | keyword |
| digital_guardian.arc.dg_alert.alert_etu | Alert ETU | date |
| digital_guardian.arc.dg_alert.alert_ur | Alert UR | date |
| digital_guardian.arc.dg_alert.alert_wb | Alert WB | keyword |
| digital_guardian.arc.dg_alert.dg_category_name | Alert Category Name | keyword |
| digital_guardian.arc.dg_alert.dg_detection_source | Alert Detection Source | keyword |
| digital_guardian.arc.dg_alert.dg_name | Alert Name | keyword |
| digital_guardian.arc.dg_alert.dg_policy.dg_category_name | Alert Policy Category Name | keyword |
| digital_guardian.arc.dg_alert.dg_policy.dg_name | Alert Policy Name | keyword |
| digital_guardian.arc.dg_alert.dg_rule_action_type | Alert Rule Action Type | keyword |
| digital_guardian.arc.dg_attachments.dg_file_size | File Size | keyword |
| digital_guardian.arc.dg_attachments.dg_file_size_bytes | File Size in Bytes | long |
| digital_guardian.arc.dg_comment | Comment | keyword |
| digital_guardian.arc.dg_description | Description | keyword |
| digital_guardian.arc.dg_display | Event Display Name | keyword |
| digital_guardian.arc.dg_file_path | File Path | keyword |
| digital_guardian.arc.dg_file_size | File Size | keyword |
| digital_guardian.arc.dg_file_size_bytes | File Size in Bytes | long |
| digital_guardian.arc.dg_guid | Unique ID | keyword |
| digital_guardian.arc.dg_local_timestamp | Local Time | date |
| digital_guardian.arc.dg_mac_address | MAC Address | keyword |
| digital_guardian.arc.dg_machine_name | Computer Name | keyword |
| digital_guardian.arc.dg_machine_type | Machine Type | integer |
| digital_guardian.arc.dg_name | Name. | keyword |
| digital_guardian.arc.dg_processed_time | Server Process Time | date |
| digital_guardian.arc.dg_src_file_ext | Source File Extension | keyword |
| digital_guardian.arc.dg_src_file_name | Source File Name | keyword |
| digital_guardian.arc.dg_tenant | Tenant ID | keyword |
| digital_guardian.arc.dg_time | Event Time | date |
| digital_guardian.arc.dg_utype | Operation Type | keyword |
| digital_guardian.arc.export_profile | Export Profile GUID for the Event | keyword |
| digital_guardian.arc.inc_assign | Incident Assignee | keyword |
| digital_guardian.arc.inc_creator | Incident Creator | keyword |
| digital_guardian.arc.inc_id | Incident ID | keyword |
| digital_guardian.arc.inc_mtime | Incident Modified Time | date |
| digital_guardian.arc.inc_sev | Incident Severity | keyword |
| digital_guardian.arc.inc_state | Incident State | keyword |
| digital_guardian.arc.pi_fal | Time | date |
| digital_guardian.arc.pi_fcl | Time | date |
| digital_guardian.arc.pi_fml | Time | date |
| digital_guardian.arc.ua_sci | Scan Instance | integer |
| digital_guardian.arc.ua_scn | Appliance Scan Name | keyword |
| digital_guardian.arc.ua_sn | Scan Server Name | keyword |
| digital_guardian.arc.uad_sp | Source File Path | keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |

