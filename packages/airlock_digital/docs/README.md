# Airlock Digital Integration for Elastic

## Overview

[Airlock Digital](https://www.airlockdigital.com/) delivers an easy-to-manage and scalable application control solution to protect endpoints with confidence. Built by cybersecurity professionals and trusted by organizations worldwide, Airlock Digital enforces a Deny by Default security posture to block all untrusted code, including unknown applications, unwanted scripts, malware, and ransomware.

The Airlock Digital integration for Elastic allows you to collect logs from, [Airlock Digital REST API](https://api.airlockdigital.com/), then visualise the data in Kibana.

### Compatibility

The Airlock Digital integration is compatible with `v6.1.x` and `v1` version of Airlock Digital REST API.

### How it works

This integration periodically queries the Airlock Digital REST API to retrieve Agent logs.

## What data does this integration collect?

This integration collects log messages of the following types:

- `Agent`: Collects agent logs via [Airlock Digital REST API](https://api.airlockdigital.com/#35ef50c6-1df4-4330-a433-1915ccf380cf).

### Supported use cases
Integrating Airlock Digital agent logs with Elastic SIEM provides SOC teams with comprehensive visibility into endpoint policy enforcement and system activity. Dashboards highlight agent health, host and user patterns, OS distribution, group and policy metrics, storage availability, and trusted configurations, empowering efficient monitoring, proactive resource management, and improved operational readiness.

## What do I need to use this integration?

### From Airlock Digital

#### To collect data from the REST API:

1. In order to make the API calls, the User Group to which a user belongs should contain required permissions. You can follow the below steps for that:
2. Go to the **Settings** and navigate to **Users** tab.
3. Under **User Group Management** for the respective user group provide **agent/find** and **group/policies** roles in the REST API Roles section and click on save.

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

#### Agent

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| airlock_digital.agent.agentid |  | keyword |
| airlock_digital.agent.clientversion |  | keyword |
| airlock_digital.agent.domain |  | keyword |
| airlock_digital.agent.freespace |  | long |
| airlock_digital.agent.groupid |  | keyword |
| airlock_digital.agent.hostname |  | keyword |
| airlock_digital.agent.ip |  | ip |
| airlock_digital.agent.lastcheckin |  | date |
| airlock_digital.agent.localip |  | ip |
| airlock_digital.agent.os |  | keyword |
| airlock_digital.agent.poilcy_details.agentstopcode |  | keyword |
| airlock_digital.agent.poilcy_details.applications.applicationid |  | keyword |
| airlock_digital.agent.poilcy_details.applications.name |  | keyword |
| airlock_digital.agent.poilcy_details.applications.version |  | keyword |
| airlock_digital.agent.poilcy_details.auditmode |  | keyword |
| airlock_digital.agent.poilcy_details.autoupdate |  | keyword |
| airlock_digital.agent.poilcy_details.baselines.baselineid |  | keyword |
| airlock_digital.agent.poilcy_details.baselines.name |  | keyword |
| airlock_digital.agent.poilcy_details.batch |  | keyword |
| airlock_digital.agent.poilcy_details.blocklists |  | flattened |
| airlock_digital.agent.poilcy_details.check_ea |  | keyword |
| airlock_digital.agent.poilcy_details.command |  | keyword |
| airlock_digital.agent.poilcy_details.commlist.ip |  | ip |
| airlock_digital.agent.poilcy_details.commlist.name |  | keyword |
| airlock_digital.agent.poilcy_details.commlistid |  | keyword |
| airlock_digital.agent.poilcy_details.compiledhtml |  | keyword |
| airlock_digital.agent.poilcy_details.dylib |  | keyword |
| airlock_digital.agent.poilcy_details.enable_notifications |  | keyword |
| airlock_digital.agent.poilcy_details.extensions_enabled |  | keyword |
| airlock_digital.agent.poilcy_details.generalisation |  | keyword |
| airlock_digital.agent.poilcy_details.gprocesses |  | keyword |
| airlock_digital.agent.poilcy_details.hashdb_ver |  | keyword |
| airlock_digital.agent.poilcy_details.htmlapplication |  | keyword |
| airlock_digital.agent.poilcy_details.javaapplication |  | keyword |
| airlock_digital.agent.poilcy_details.javascript |  | keyword |
| airlock_digital.agent.poilcy_details.modreload |  | keyword |
| airlock_digital.agent.poilcy_details.name |  | keyword |
| airlock_digital.agent.poilcy_details.notification_message |  | match_only_text |
| airlock_digital.agent.poilcy_details.parent |  | keyword |
| airlock_digital.agent.poilcy_details.paths.comment |  | keyword |
| airlock_digital.agent.poilcy_details.paths.name |  | keyword |
| airlock_digital.agent.poilcy_details.policyver |  | keyword |
| airlock_digital.agent.poilcy_details.poll_time |  | keyword |
| airlock_digital.agent.poilcy_details.powershell |  | keyword |
| airlock_digital.agent.poilcy_details.pprocesses.comment |  | keyword |
| airlock_digital.agent.poilcy_details.pprocesses.name |  | keyword |
| airlock_digital.agent.poilcy_details.proxyauth |  | keyword |
| airlock_digital.agent.poilcy_details.proxyenabled |  | keyword |
| airlock_digital.agent.poilcy_details.proxypass |  | keyword |
| airlock_digital.agent.poilcy_details.proxyport |  | long |
| airlock_digital.agent.poilcy_details.proxyserver |  | keyword |
| airlock_digital.agent.poilcy_details.proxyuser |  | keyword |
| airlock_digital.agent.poilcy_details.pslockdown |  | keyword |
| airlock_digital.agent.poilcy_details.publishers.comment |  | keyword |
| airlock_digital.agent.poilcy_details.publishers.name |  | keyword |
| airlock_digital.agent.poilcy_details.python |  | keyword |
| airlock_digital.agent.poilcy_details.reflection |  | keyword |
| airlock_digital.agent.poilcy_details.script_custom |  | keyword |
| airlock_digital.agent.poilcy_details.script_enabled |  | keyword |
| airlock_digital.agent.poilcy_details.selfservice |  | keyword |
| airlock_digital.agent.poilcy_details.selfupgrade |  | keyword |
| airlock_digital.agent.poilcy_details.shellscript |  | keyword |
| airlock_digital.agent.poilcy_details.targetvers |  | flattened |
| airlock_digital.agent.poilcy_details.trusted_config |  | boolean |
| airlock_digital.agent.poilcy_details.trusted_upload |  | keyword |
| airlock_digital.agent.poilcy_details.vbscript |  | keyword |
| airlock_digital.agent.poilcy_details.windowsinstaller |  | keyword |
| airlock_digital.agent.poilcy_details.windowsscriptcomponent |  | keyword |
| airlock_digital.agent.policyversion |  | keyword |
| airlock_digital.agent.status |  | keyword |
| airlock_digital.agent.status_value |  | keyword |
| airlock_digital.agent.username |  | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |


### Example event

#### Agent

An example event for `agent` looks as following:

```json
{
    "@timestamp": "2025-07-18T11:36:13.765Z",
    "agent": {
        "ephemeral_id": "a40ebbf9-2532-4acc-804a-fdcc504b24a1",
        "id": "0bf78263-441b-45d7-a41d-9c1fccbdbe71",
        "name": "elastic-agent-31314",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "airlock_digital": {
        "agent": {
            "agentid": "b12a9d5f-d3fc-4893-8dc3-9e2982e732f1",
            "clientversion": "5.3.0.0",
            "domain": "CORP-WORKSTATION",
            "freespace": 61,
            "groupid": "f5c9a3b4-09df-4eae-bf7d-72ab9850138d",
            "hostname": "CORP-WORKSTATION",
            "ip": "175.16.199.1",
            "lastcheckin": "2024-04-29T15:12:17.001Z",
            "localip": "175.16.199.254",
            "os": "Windows 11 x64 (Release: 23H2)",
            "poilcy_details": {
                "applications": [
                    {
                        "applicationid": "1570641682",
                        "name": "Airlock Enforcement Agents"
                    }
                ],
                "auditmode": "0",
                "autoupdate": "0",
                "baselines": [
                    {
                        "baselineid": "1567253648",
                        "name": "Windows 10 1903 x64 May 2019 (Reference)"
                    },
                    {
                        "baselineid": "1569941628",
                        "name": "Windows 10 1803 x64 May 2019 (Reference)"
                    },
                    {
                        "baselineid": "1597574944",
                        "name": "Windows 10 2004 x86 RTM (Reference)"
                    }
                ],
                "batch": "1",
                "check_ea": "0",
                "command": "1",
                "commlist": [
                    {
                        "ip": "81.2.69.143",
                        "name": "test.server.com"
                    }
                ],
                "commlistid": "airlock-default-communication-list",
                "compiledhtml": "1",
                "dylib": "0",
                "enable_notifications": "1",
                "extensions_enabled": "0",
                "generalisation": "0",
                "hashdb_ver": "215",
                "htmlapplication": "1",
                "javaapplication": "1",
                "javascript": "1",
                "modreload": "0",
                "name": "ADL Workstations",
                "notification_message": "%filename% has been prevented from executing as a result of Application Whitelisting. If this event caused unexpected system behaviour please contact your Administrator",
                "parent": "Airlock Groups",
                "paths": [
                    {
                        "name": "C:\\\\Windows\\\\assembly\\\\GAC*\\\\*\\\\*.*.*_*\\\\*.dll"
                    },
                    {
                        "name": "C:\\\\Windows\\\\Temp\\\\__PSScriptPolicyTest_????????.???.ps1"
                    },
                    {
                        "name": "C:\\\\Users\\\\*\\\\AppData\\\\Local\\\\Temp\\\\__PSScriptPolicyTest_????????.???.ps1"
                    }
                ],
                "policyver": "316",
                "poll_time": "600",
                "powershell": "1",
                "pprocesses": [
                    {
                        "comment": "comment on inherited proc",
                        "name": "testprocInherited.exe"
                    }
                ],
                "proxyauth": "0",
                "proxyenabled": "0",
                "pslockdown": "0",
                "publishers": [
                    {
                        "name": "Microsoft Corporation"
                    },
                    {
                        "name": "Microsoft Dynamic Code Publisher"
                    },
                    {
                        "name": "Microsoft Windows"
                    }
                ],
                "python": "1",
                "reflection": "0",
                "script_custom": "0",
                "script_enabled": "2",
                "selfservice": "0",
                "selfupgrade": "0",
                "shellscript": "0",
                "targetvers": [
                    {
                        "macos": "6.1.0.8047"
                    }
                ],
                "trusted_config": false,
                "trusted_upload": "0",
                "vbscript": "1",
                "windowsinstaller": "1",
                "windowsscriptcomponent": "1"
            },
            "policyversion": "9.1",
            "status": "3",
            "status_value": "Safemode",
            "username": "jane.doe"
        }
    },
    "data_stream": {
        "dataset": "airlock_digital.agent",
        "namespace": "98907",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "0bf78263-441b-45d7-a41d-9c1fccbdbe71",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "host"
        ],
        "dataset": "airlock_digital.agent",
        "ingested": "2025-07-18T11:36:16Z",
        "kind": "event",
        "original": "{\"agentid\":\"b12a9d5f-d3fc-4893-8dc3-9e2982e732f1\",\"clientversion\":\"5.3.0.0\",\"domain\":\"CORP-WORKSTATION\",\"freespace\":\"61\",\"groupid\":\"f5c9a3b4-09df-4eae-bf7d-72ab9850138d\",\"hostname\":\"CORP-WORKSTATION\",\"ip\":\"175.16.199.1\",\"lastcheckin\":\"2024-04-29T15:12:17.001Z\",\"localip\":\"175.16.199.254\",\"os\":\"Windows 11 x64 (Release: 23H2)\",\"policy_details\":{\"agentstopcode\":\"\",\"applications\":[{\"applicationid\":\"1570641682\",\"name\":\"Airlock Enforcement Agents\",\"version\":\"\"}],\"auditmode\":0,\"autoupdate\":0,\"baselines\":[{\"baselineid\":\"1567253648\",\"name\":\"Windows 10 1903 x64 May 2019 (Reference)\"},{\"baselineid\":\"1569941628\",\"name\":\"Windows 10 1803 x64 May 2019 (Reference)\"},{\"baselineid\":\"1597574944\",\"name\":\"Windows 10 2004 x86 RTM (Reference)\"}],\"batch\":1,\"blocklists\":null,\"check_ea\":0,\"command\":1,\"commlist\":[{\"ip\":\"81.2.69.143\",\"name\":\"test.server.com\"}],\"commlistid\":\"airlock-default-communication-list\",\"compiledhtml\":1,\"dylib\":0,\"enable_notifications\":1,\"extensions_enabled\":0,\"generalisation\":0,\"gprocesses\":null,\"groupid\":\"f5c9a3b4-09df-4eae-bf7d-72ab9850138d\",\"hashdb_ver\":\"215\",\"htmlapplication\":1,\"javaapplication\":1,\"javascript\":1,\"modreload\":0,\"name\":\"ADL Workstations\",\"notification_message\":\"%filename% has been prevented from executing as a result of Application Whitelisting. If this event caused unexpected system behaviour please contact your Administrator\",\"parent\":\"Airlock Groups\",\"paths\":[{\"comment\":\"\",\"name\":\"C:\\\\\\\\Windows\\\\\\\\assembly\\\\\\\\GAC*\\\\\\\\*\\\\\\\\*.*.*_*\\\\\\\\*.dll\"},{\"comment\":\"\",\"name\":\"C:\\\\\\\\Windows\\\\\\\\Temp\\\\\\\\__PSScriptPolicyTest_????????.???.ps1\"},{\"comment\":\"\",\"name\":\"C:\\\\\\\\Users\\\\\\\\*\\\\\\\\AppData\\\\\\\\Local\\\\\\\\Temp\\\\\\\\__PSScriptPolicyTest_????????.???.ps1\"}],\"policyver\":\"316\",\"poll_time\":600,\"powershell\":1,\"pprocesses\":[{\"comment\":\"comment on inherited proc\",\"name\":\"testprocInherited.exe\"}],\"proxyauth\":0,\"proxyenabled\":0,\"proxypass\":\"\",\"proxyport\":\"\",\"proxyserver\":\"\",\"proxyuser\":\"\",\"pslockdown\":0,\"publishers\":[{\"comment\":\"\",\"name\":\"Microsoft Corporation\"},{\"comment\":\"\",\"name\":\"Microsoft Dynamic Code Publisher\"},{\"comment\":\"\",\"name\":\"Microsoft Windows\"}],\"python\":1,\"reflection\":0,\"script_custom\":0,\"script_enabled\":2,\"selfservice\":0,\"selfupgrade\":0,\"shellscript\":0,\"targetvers\":[{\"linux\":\"\",\"macos\":\"6.1.0.8047\",\"windows\":\"\"}],\"trusted_config\":false,\"trusted_upload\":0,\"vbscript\":1,\"windowsinstaller\":1,\"windowsscriptcomponent\":1},\"policyversion\":\"9.1\",\"status\":3,\"username\":\"jane.doe\"}",
        "type": [
            "info"
        ]
    },
    "file": {
        "path": [
            "C:\\\\Windows\\\\assembly\\\\GAC*\\\\*\\\\*.*.*_*\\\\*.dll",
            "C:\\\\Windows\\\\Temp\\\\__PSScriptPolicyTest_????????.???.ps1",
            "C:\\\\Users\\\\*\\\\AppData\\\\Local\\\\Temp\\\\__PSScriptPolicyTest_????????.???.ps1"
        ]
    },
    "host": {
        "domain": "CORP-WORKSTATION",
        "hostname": "CORP-WORKSTATION",
        "id": "b12a9d5f-d3fc-4893-8dc3-9e2982e732f1",
        "ip": [
            "175.16.199.1"
        ],
        "os": {
            "full": "Windows 11 x64 (Release: 23H2)",
            "name": "Windows",
            "type": "windows"
        }
    },
    "input": {
        "type": "cel"
    },
    "message": "%filename% has been prevented from executing as a result of Application Whitelisting. If this event caused unexpected system behaviour please contact your Administrator",
    "observer": {
        "vendor": "Airlock Digital"
    },
    "process": {
        "parent": {
            "name": [
                "testprocInherited.exe"
            ]
        }
    },
    "related": {
        "hosts": [
            "CORP-WORKSTATION"
        ],
        "ip": [
            "175.16.199.1",
            "175.16.199.254",
            "81.2.69.143"
        ],
        "user": [
            "jane.doe"
        ]
    },
    "rule": {
        "id": "f5c9a3b4-09df-4eae-bf7d-72ab9850138d",
        "name": "ADL Workstations",
        "version": "9.1"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "airlock_digital-agent"
    ],
    "user": {
        "name": "jane.doe"
    }
}
```

### Inputs used

These inputs can be used in this integration:

- [cel](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)

### API usage

These integration datasets use the following API:

- `Agent`: [Airlock Digital REST API](https://api.airlockdigital.com/#35ef50c6-1df4-4330-a433-1915ccf380cf).
