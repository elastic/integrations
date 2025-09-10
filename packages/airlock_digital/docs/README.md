# Airlock Digital Integration for Elastic

## Overview

[Airlock Digital](https://www.airlockdigital.com/) delivers an easy-to-manage and scalable application control solution to protect endpoints with confidence. Built by cybersecurity professionals and trusted by organizations worldwide, Airlock Digital enforces a Deny by Default security posture to block all untrusted code, including unknown applications, unwanted scripts, malware, and ransomware.

The Airlock Digital integration for Elastic allows you to collect logs from, [Airlock Digital REST API](https://api.airlockdigital.com/), then visualise the data in Kibana.

### Compatibility

The Airlock Digital integration is compatible with version `v6.1.x` of Airlock Digital and `v1` of the REST API.

### How it works

This integration periodically queries the Airlock Digital REST API to retrieve Execution Histories.

## What data does this integration collect?

This integration collects log messages of the following types:

- `Execution Histories`: Collects executions history logs via [Airlock Digital REST API](https://api.airlockdigital.com/#3634a82d-eb6b-44b7-b662-dddc37d4d9d6).

### Supported use cases
Integrating Airlock Digital’s execution history logs into Elastic SIEM gives SOC teams deep visibility into endpoint activity, allowing seamless tracking of blocked or untrusted executions, policy violations, and execution patterns to accelerate investigations, strengthen compliance, and enhance endpoint security.

## What do I need to use this integration?

### From Airlock Digital

#### To collect data from the REST API:

1. In order to make the API calls, the User Group to which a user belongs should contain required permissions. You can follow the below steps for that:
2. Go to the **Settings** and navigate to **Users** tab.
3. Under **User Group Management** for the respective user group provide **logging/exechistories** roles in the REST API Roles section and click on save.

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

#### Execution Histories

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| airlock_digital.execution_histories.checkpoint |  | keyword |
| airlock_digital.execution_histories.commandline |  | wildcard |
| airlock_digital.execution_histories.datetime |  | date |
| airlock_digital.execution_histories.filename |  | keyword |
| airlock_digital.execution_histories.hostname |  | keyword |
| airlock_digital.execution_histories.md5 |  | keyword |
| airlock_digital.execution_histories.netdomain |  | keyword |
| airlock_digital.execution_histories.policyname |  | keyword |
| airlock_digital.execution_histories.policyver |  | keyword |
| airlock_digital.execution_histories.ppolicy |  | keyword |
| airlock_digital.execution_histories.pprocess |  | keyword |
| airlock_digital.execution_histories.publisher |  | keyword |
| airlock_digital.execution_histories.sha128 |  | keyword |
| airlock_digital.execution_histories.sha256 |  | keyword |
| airlock_digital.execution_histories.sha384 |  | keyword |
| airlock_digital.execution_histories.sha512 |  | keyword |
| airlock_digital.execution_histories.type |  | long |
| airlock_digital.execution_histories.type_value |  | keyword |
| airlock_digital.execution_histories.username |  | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| observer.vendor |  | constant_keyword |


### Example event

#### Execution Histories

An example event for `execution_histories` looks as following:

```json
{
    "@timestamp": "2024-04-26T14:50:56.000Z",
    "agent": {
        "ephemeral_id": "b16780c4-98ce-4524-9e9f-77ede03a3b79",
        "id": "395a6ed2-5beb-45b7-9b3c-bb08ce7c2628",
        "name": "elastic-agent-92817",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "airlock_digital": {
        "execution_histories": {
            "checkpoint": "firstcheckpoint",
            "commandline": "/bin/sh /tmp/PKInstallSandbox.mqvKk4/Scripts/ /Library/Airlock Digital / /",
            "datetime": "2024-04-26T14:50:56.000Z",
            "filename": "/tmp/PKInstallSandbox.mqvKk4/preinstall",
            "hostname": ".local",
            "netdomain": ".local",
            "policyname": "Apple Mac",
            "policyver": "v485",
            "ppolicy": "Airlock Groups",
            "pprocess": "sh",
            "publisher": "Airlock Digital Pty Ltd (MXRN6N7XFL) (Mac)",
            "sha256": "a3f791dec1f2a40bd623a9b37604e7f2dee84eab3f6a513c6882231d89037c40",
            "type": 1,
            "type_value": "Blocked Execution",
            "username": "root"
        }
    },
    "data_stream": {
        "dataset": "airlock_digital.execution_histories",
        "namespace": "75499",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "395a6ed2-5beb-45b7-9b3c-bb08ce7c2628",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "host"
        ],
        "dataset": "airlock_digital.execution_histories",
        "id": "firstcheckpoint",
        "ingested": "2025-07-11T12:26:47Z",
        "kind": "event",
        "original": "{\"checkpoint\":\"firstcheckpoint\",\"commandline\":\"/bin/sh /tmp/PKInstallSandbox.mqvKk4/Scripts/ /Library/Airlock Digital / /\",\"datetime\":\"2024-04-26T14:50:56Z\",\"filename\":\"/tmp/PKInstallSandbox.mqvKk4/preinstall\",\"hostname\":\".local\",\"md5\":\"\",\"netdomain\":\".local\",\"policyname\":\"Apple Mac\",\"policyver\":\"v485\",\"ppolicy\":\"Airlock Groups\",\"pprocess\":\"sh\",\"publisher\":\"Airlock Digital Pty Ltd (MXRN6N7XFL) (Mac)\",\"sha128\":\"\",\"sha256\":\"a3f791dec1f2a40bd623a9b37604e7f2dee84eab3f6a513c6882231d89037c40\",\"sha384\":\"\",\"sha512\":\"\",\"type\":1,\"username\":\"root\"}",
        "type": [
            "info"
        ]
    },
    "file": {
        "name": "preinstall",
        "path": "/tmp/PKInstallSandbox.mqvKk4/preinstall"
    },
    "host": {
        "hostname": ".local"
    },
    "input": {
        "type": "cel"
    },
    "process": {
        "command_line": "/bin/sh /tmp/PKInstallSandbox.mqvKk4/Scripts/ /Library/Airlock Digital / /",
        "hash": {
            "sha256": "a3f791dec1f2a40bd623a9b37604e7f2dee84eab3f6a513c6882231d89037c40"
        },
        "parent": {
            "name": "sh"
        }
    },
    "related": {
        "hash": [
            "a3f791dec1f2a40bd623a9b37604e7f2dee84eab3f6a513c6882231d89037c40"
        ],
        "hosts": [
            ".local"
        ],
        "user": [
            "root"
        ]
    },
    "rule": {
        "name": "Apple Mac",
        "ruleset": "Airlock Groups",
        "version": "v485"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "airlock_digital-execution_histories"
    ],
    "user": {
        "name": "root"
    }
}
```

### Inputs used

These inputs can be used in this integration:

- [cel](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)

### API usage

These integration datasets use the following API:

- `Execution Histories`: [Airlock Digital REST API](https://api.airlockdigital.com/#3634a82d-eb6b-44b7-b662-dddc37d4d9d6). Supported execution types are:
    - Trusted Execution
    - Blocked Execution
    - Untrusted Execution [Audit]
    - Untrusted Execution [OTP]
    - Trusted Path Execution
    - Trusted Publisher Execution
    - Blocklist Execution
    - Blocklist Execution [Audit]
    - Trusted Process Execution
    - Constrained Execution
    - Trusted Metadata Execution
    - Trusted Browser Execution
    - Blocked Browser Execution
    - Untrusted Browser Execution [Audit]
    - Untrusted Browser Execution [OTP]
    - Blocklist Browser Execution [Audit]
    - Blocklist Browser Execution
    - Trusted Installer Execution
    - Trusted Browser Metadata Execution
