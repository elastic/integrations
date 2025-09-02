# Airlock Digital Integration for Elastic

## Overview

[Airlock Digital](https://www.airlockdigital.com/) delivers an easy-to-manage and scalable application control solution to protect endpoints with confidence. Built by cybersecurity professionals and trusted by organizations worldwide, Airlock Digital enforces a Deny by Default security posture to block all untrusted code, including unknown applications, unwanted scripts, malware, and ransomware.

The Airlock Digital integration for Elastic allows you to collect logs from, [Airlock Digital REST API](https://api.airlockdigital.com/), then visualise the data in Kibana.

### Compatibility

The Airlock Digital integration is compatible with `v6.1.x` and `v1` version of Airlock Digital REST API.

### How it works

This integration periodically queries the Airlock Digital REST API to retrieve Server Activities logs.

## What data does this integration collect?

This integration collects log messages of the following types:

- `Server Activities`: Collects server activity logs via [Airlock Digital REST API](https://api.airlockdigital.com/#290b4657-17d4-4048-982e-43df95200624).


### Supported use cases
Integrating Airlock Digital server activity logs into Elastic SIEM gives deep visibility into critical system and user-level operations. By monitoring activities across tasks, users, and root-level actions, analysts can quickly identify unauthorized changes, detect policy misuse, and trace suspicious behavior. Purpose-built dashboards provide clear visibility into activity trends, user behaviors, and essential details to support faster investigations and stronger system oversight.

## What do I need to use this integration?

### From Airlock Digital

#### To collect data from the REST API:

1. In order to make the API calls, the User Group to which a user belongs should contain required permissions. You can follow the below steps for that:
2. Go to the **Settings** and navigate to **Users** tab.
3. Under **User Group Management** for the respective user group provide **logging/svractivities** roles in the REST API Roles section and click on save.

#### Generate Client API key for Authentication:

1. Log in to your Airlock console.
2. On the right side of the navigation bar, click on the dropdown with the user’s name and navigate to **My profile** section.
3. Click on the **Generate API Key** button.
4. Copy the displayed API key — it will be required later for configuration.

For more details, check [Documentation](https://api.airlockdigital.com/).

## How do I deploy this integration?

This integration supports both Elastic Agentless-based and Agent-based installations.

### Agentless-based installation

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

## Setup

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **Airlock Digital**.
3. Select the **Airlock Digital** integration from the search results.
4. Select **Add Airlock Digital** to add the integration.
5. Enable and configure only the collection methods which you will use.

    * To **Collect Airlock Digital logs via API**, you'll need to:

        - Configure **URL** and **API Key**.
        - Enable/Disable the required datasets.
        - For each dataset, adjust the integration configuration parameters if required, including the Interval, Preserve original event etc. to enable data collection.

6. Select **Save and continue** to save the integration.

### Validation

#### Dashboards populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **Airlock Digital**.
3. Select a dashboard for the dataset you are collecting, and verify the dashboard information is populated.

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### ECS field reference

#### Server Activities

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| airlock_digital.server_activities.checkpoint |  | keyword |
| airlock_digital.server_activities.datetime |  | date |
| airlock_digital.server_activities.description |  | match_only_text |
| airlock_digital.server_activities.task |  | keyword |
| airlock_digital.server_activities.user |  | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| observer.vendor | Vendor name of the observer. | constant_keyword |


### Example event

#### Server Activities

An example event for `server_activities` looks as following:

```json
{
    "@timestamp": "2024-01-25T05:23:30.880Z",
    "agent": {
        "ephemeral_id": "3b5328f7-d71f-4e8e-ada8-a29cc4086ba6",
        "id": "2dac65cf-837f-4ccf-b441-1ff021ba8529",
        "name": "elastic-agent-48732",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "airlock_digital": {
        "server_activities": {
            "checkpoint": "thirdcheckpoint",
            "datetime": "2024-01-25T05:23:30.880Z",
            "description": "DESKTOP-GG4CEJM checks in",
            "task": "Client Checkin",
            "user": "SYSTEM"
        }
    },
    "data_stream": {
        "dataset": "airlock_digital.server_activities",
        "namespace": "79666",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "2dac65cf-837f-4ccf-b441-1ff021ba8529",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "action": "client-checkin",
        "agent_id_status": "verified",
        "category": [
            "host"
        ],
        "dataset": "airlock_digital.server_activities",
        "id": "thirdcheckpoint",
        "ingested": "2025-07-16T09:50:13Z",
        "kind": "event",
        "original": "{\"checkpoint\":\"thirdcheckpoint\",\"datetime\":\"2024-01-25T05:23:30.88Z\",\"description\":\"DESKTOP-GG4CEJM checks in\",\"task\":\"Client Checkin\",\"user\":\"SYSTEM\"}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "cel"
    },
    "message": "DESKTOP-GG4CEJM checks in",
    "related": {
        "user": [
            "SYSTEM"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "airlock_digital-server_activities"
    ],
    "user": {
        "name": "SYSTEM"
    }
}
```

### Inputs used

These inputs can be used in this integration:

- [cel](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)

### API usage

These integration datasets use the following API:

- `Server Activities`: [Airlock Digital REST API](https://api.airlockdigital.com/#290b4657-17d4-4048-982e-43df95200624).
