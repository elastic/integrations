# ExtraHop

## Overview

[ExtraHop](https://www.extrahop.com/) delivers complete network visibility through its agentless RevealX NDR platform, empowering security teams to close detection gaps left by EDR, SIEM, and logs. ExtraHop provides the deep intelligence needed to detect threats faster, investigate with greater context, and respond at the speed of modern risk.

This integration enables you to collect investigation data via [ExtraHop RevealX 360 API](https://docs.extrahop.com/current/rx360-rest-api/), then visualise the data in Kibana.

## Data streams

The ExtraHop integration collects logs for one type of event.

**Investigation:** This datastream enables you to retrieve investigations that have been identified by the ExtraHop system.

>**Note**: For the **Investigation** Dashboard, ensure that the time range is aligned with the configured interval parameter to display accurate and consistent data.

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

### Investigation

This is the `Investigation` dataset.

#### Example

An example event for `investigation` looks as following:

```json
{
    "@timestamp": "2025-08-19T06:29:55.274Z",
    "agent": {
        "ephemeral_id": "4b0de889-c5ed-40ed-acc1-324704aabc98",
        "id": "4e3a91b3-f2a6-4168-958d-20dc25789f3b",
        "name": "elastic-agent-38848",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "extrahop.investigation",
        "namespace": "87926",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "4e3a91b3-f2a6-4168-958d-20dc25789f3b",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2025-05-21T11:08:13.321Z",
        "dataset": "extrahop.investigation",
        "duration": 788188113000000,
        "end": "2025-05-30T14:04:41.434Z",
        "id": "3-1755584998257",
        "ingested": "2025-08-19T06:29:58Z",
        "kind": "event",
        "original": "{\"assessment\":\"benign_true_positive\",\"assignee\":\"user1\",\"created_by\":\"integration@example.com\",\"creation_time\":1747825693321,\"description\":\"This investigation focuses on potential enumeration behavior observed through BloodHound. Review AD logs and user group mappings to verify intent and exposure.\",\"detections\":[25769803958],\"end_time\":1748613881434,\"id\":3,\"investigation_types\":[\"Active Directory\",\"Threat Hunting\"],\"is_user_created\":true,\"last_interaction_by\":\"user1\",\"last_interaction_time\":1748613881434,\"name\":\"BloodHound Enumeration Investigation\",\"notes\":\"Investigate Internally with AD logs\",\"start_time\":1747825693321,\"status\":\"closed\",\"update_time\":1747825693321,\"url\":\"https://example.com/#/detections/investigations/3\"}",
        "start": "2025-05-21T11:08:13.321Z",
        "type": [
            "info"
        ],
        "url": "https://example.com/#/detections/investigations/3"
    },
    "extrahop": {
        "investigation": {
            "assessment": "benign_true_positive",
            "assignee": "user1",
            "created_by": "integration@example.com",
            "creation_time": "2025-05-21T11:08:13.321Z",
            "description": "This investigation focuses on potential enumeration behavior observed through BloodHound. Review AD logs and user group mappings to verify intent and exposure.",
            "detections": [
                "25769803958"
            ],
            "end_time": "2025-05-30T14:04:41.434Z",
            "id": "3",
            "investigation_types": [
                "Active Directory",
                "Threat Hunting"
            ],
            "is_user_created": true,
            "last_interaction_by": "user1",
            "last_interaction_time": "2025-05-30T14:04:41.434Z",
            "name": "BloodHound Enumeration Investigation",
            "notes": "Investigate Internally with AD logs",
            "start_time": "2025-05-21T11:08:13.321Z",
            "status": "closed",
            "update_time": "2025-05-21T11:08:13.321Z",
            "url": "https://example.com/#/detections/investigations/3"
        }
    },
    "input": {
        "type": "cel"
    },
    "message": "BloodHound Enumeration Investigation",
    "related": {
        "user": [
            "user1",
            "integration@example.com"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "extrahop-investigation"
    ],
    "user": {
        "domain": "example.com",
        "name": "integration"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| extrahop.investigation.assessment | The assessment of the investigation. | keyword |
| extrahop.investigation.assignee | The username of the investigation assignee. | keyword |
| extrahop.investigation.created_by |  | keyword |
| extrahop.investigation.creation_time |  | date |
| extrahop.investigation.description |  | keyword |
| extrahop.investigation.detections |  | keyword |
| extrahop.investigation.end_time |  | date |
| extrahop.investigation.id |  | keyword |
| extrahop.investigation.investigation_types |  | keyword |
| extrahop.investigation.is_user_created |  | boolean |
| extrahop.investigation.last_interaction_by |  | keyword |
| extrahop.investigation.last_interaction_time |  | date |
| extrahop.investigation.name | The name of the investigation. | match_only_text |
| extrahop.investigation.notes | The notes about the investigation. | keyword |
| extrahop.investigation.start_time |  | date |
| extrahop.investigation.status | The status of the investigation. | keyword |
| extrahop.investigation.update_time |  | date |
| extrahop.investigation.url |  | keyword |
| input.type | Type of filebeat input. | keyword |
| labels.is_transform_source | Indicates whether an investigation is in the raw source data stream, or in the latest destination index. | constant_keyword |
| log.offset | Log offset. | long |
| observer.product |  | constant_keyword |
| observer.type |  | constant_keyword |
| observer.vendor |  | constant_keyword |

