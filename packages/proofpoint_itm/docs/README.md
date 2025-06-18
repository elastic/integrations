# Proofpoint Insider Threat Management (ITM)

[Proofpoint Insider Threat Management (ITM)](https://www.proofpoint.com/us/products/insider-threat-management) is a people-centric SaaS solution that helps you protect sensitive data from insider threats and data loss at the endpoint. It combines context across content, behavior and threats to provide you with deep visibility into user activities. Proofpoint ITM helps security teams tackle the challenges of detecting and preventing insider threats. It can streamline their responses to insider-led incidents and provide insights that help prevent further damage.

Use this integration to collect and parse data from your Proofpoint ITM instance.

## Compatibility

This module has been tested against the Proofpoint ITM API version **v2**.

## Data streams

This integration collects the following logs:

- **Reports** - This data stream enables users to retrieve reports from Proofpoint ITM, including the following log types:

- User activity
- DBA activity
- System events
- Alerts activity
- Audit activity
- In-App elements

## Requirements

### Agentless-enabled integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

## Setup

Follow the [ITM On-Prem (ObserveIT) API Portal](https://prod.docs.oit.proofpoint.com/configuration_guide/observeit_api_portal.htm) guide to setup the Proofpoint ITM On-Prem API Portal.

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search top bar, type **Proofpoint ITM**.
3. Select the **Proofpoint ITM** integration and add it.
4. Add all the required integration configuration parameters: URL, Token URL, Client ID, and Client type.
5. Save the integration.

## Logs reference

### Report

This is the `report` dataset.

#### Example

An example event for `report` looks as following:

```json
{
    "@timestamp": "2025-03-01T12:00:00.000Z",
    "agent": {
        "ephemeral_id": "12fe4ae6-bc36-46eb-8476-a1bd11861a63",
        "id": "45f2c37d-e743-4930-a341-4fb252244526",
        "name": "elastic-agent-17075",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "proofpoint_itm.report",
        "namespace": "39091",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "45f2c37d-e743-4930-a341-4fb252244526",
        "snapshot": true,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "session"
        ],
        "created": "2025-02-25T16:08:11.000Z",
        "dataset": "proofpoint_itm.report",
        "id": "7340EB6D-A8BB-4F25-9408-2BD807FB7B13",
        "ingested": "2025-03-20T06:31:52Z",
        "kind": "alert",
        "original": "{\"_time\":\"2025-02-25T16:08:11Z\",\"accessedSiteName\":\"c-awfi.top\",\"accessedUrl\":\"http://c-awfi.top/\",\"applicationName\":\"Windows Shell Experience Host\",\"collectorId\":\"C2C1C429-C002-4FB8-99F4-7F1005ED9889\",\"collectorUrl\":\"https://code1.preview.observeit.net/\",\"command\":\"example_command\",\"commandParams\":\"--example --params\",\"createdAt\":\"2025-02-25T16:08:11Z\",\"databaseName\":\"example_database\",\"details\":\"Detailed description of the event.\",\"detailsUrl\":\"https://details.example.com/event/abcde\",\"domainName\":\"code1.observeit.net\",\"endpointId\":\"E035BBC2-1D72-4F25-9408-2BD807FB7B13\",\"endpointName\":\"Example Endpoint\",\"eventPlaybackUrl\":\"https://playback.example.com/event/abcde\",\"host\":\"host.example.com\",\"id\":\"7340EB6D-A8BB-4F25-9408-2BD807FB7B13\",\"loginName\":\"Administrator\",\"observedAt\":\"2025-02-25T16:08:11Z\",\"operationKind\":\"Read\",\"originFileName\":\"confidential.docx\",\"originSiteName\":\"Internal SharePoint\",\"os\":\"Windows\",\"playbackUrl\":\"https://code1.preview.observeit.net/ObserveIT/SlideViewer.aspx?SessionID=1A8B5249-EDAC-A8BB-4F25-9408-2BD807FB7B13\",\"processExecutable\":\"shellexexperiencehost\",\"remoteAddress\":\"175.16.199.0\",\"remoteHostName\":\"Dake-WinX\",\"risingValue\":\"2025-03-01T12:00:00Z\",\"ruleCategoryName\":\"Security\",\"ruleDesc\":\"Description of the security rule.\",\"ruleName\":\"Invalid User Asstempt\",\"secondaryDomainName\":\"n/a\",\"secondaryLoginName\":\"n/a\",\"sessionId\":\"1A8B52A9-EDAC-448E-9871-79DB21D53C28\",\"sessionUrl\":\"https://session.example.com/abc123\",\"severity\":\"High\",\"sqlCommand\":\"SELECT * FROM users;\",\"sqlUserName\":\"db_user\",\"targetFileName\":\"confidential_copy.docx\",\"targetSiteName\":\"External Drive\",\"timezoneOffset\":\"0\",\"userActivityEventId\":9876543210,\"userActivityObservedAt\":\"2025-02-25T16:08:11Z\",\"windowTitle\":\"Start\"}",
        "type": [
            "info"
        ]
    },
    "file": {
        "name": "confidential.docx"
    },
    "host": {
        "ip": [
            "175.16.199.0"
        ],
        "name": "Dake-WinX",
        "os": {
            "type": "windows"
        }
    },
    "input": {
        "type": "cel"
    },
    "observer": {
        "product": "ObserveIT",
        "vendor": "Proofpoint"
    },
    "process": {
        "args": [
            "--example --params"
        ],
        "command_line": "example_command"
    },
    "proofpoint_itm": {
        "report": {
            "_time": "2025-02-25T16:08:11.000Z",
            "accessed": {
                "site_name": "c-awfi.top",
                "url": "http://c-awfi.top/"
            },
            "application_name": "Windows Shell Experience Host",
            "collector": {
                "id": "C2C1C429-C002-4FB8-99F4-7F1005ED9889",
                "url": "https://code1.preview.observeit.net/"
            },
            "command": {
                "params": "--example --params",
                "value": "example_command"
            },
            "created_at": "2025-02-25T16:08:11.000Z",
            "database_name": "example_database",
            "details": {
                "name": "Detailed description of the event.",
                "url": "https://details.example.com/event/abcde"
            },
            "domain_name": "code1.observeit.net",
            "endpoint": {
                "id": "E035BBC2-1D72-4F25-9408-2BD807FB7B13",
                "name": "Example Endpoint"
            },
            "event_playback_url": "https://playback.example.com/event/abcde",
            "friendly_name": "Invalid User Asstempt",
            "host": "host.example.com",
            "id": "7340EB6D-A8BB-4F25-9408-2BD807FB7B13",
            "login_name": "Administrator",
            "observed_at": "2025-02-25T16:08:11.000Z",
            "operation_kind": "Read",
            "origin": {
                "file_name": "confidential.docx",
                "site_name": "Internal SharePoint"
            },
            "os": "Windows",
            "playback_url": "https://code1.preview.observeit.net/ObserveIT/SlideViewer.aspx?SessionID=1A8B5249-EDAC-A8BB-4F25-9408-2BD807FB7B13",
            "process_executable": "shellexexperiencehost",
            "remote": {
                "address": "175.16.199.0",
                "host_name": "Dake-WinX"
            },
            "rising_value": "2025-03-01T12:00:00.000Z",
            "rule": {
                "category_name": "Security",
                "desc": "Description of the security rule.",
                "name": "Invalid User Asstempt"
            },
            "secondary": {
                "domain_name": "n/a",
                "login_name": "n/a"
            },
            "session": {
                "id": "1A8B52A9-EDAC-448E-9871-79DB21D53C28",
                "url": "https://session.example.com/abc123"
            },
            "severity": "High",
            "sql": {
                "command": "SELECT * FROM users;",
                "user_name": "db_user"
            },
            "target": {
                "file_name": "confidential_copy.docx",
                "site_name": "External Drive"
            },
            "timezone_offset": 0,
            "user_activity": {
                "event_id": "9876543210",
                "observed_at": "2025-02-25T16:08:11.000Z"
            },
            "window_title": "Start"
        }
    },
    "related": {
        "hosts": [
            "Dake-WinX"
        ],
        "ip": [
            "175.16.199.0"
        ],
        "user": [
            "Administrator",
            "n/a",
            "db_user"
        ]
    },
    "rule": {
        "category": "Security",
        "description": "Description of the security rule.",
        "name": "Invalid User Asstempt"
    },
    "source": {
        "domain": "code1.observeit.net"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "proofpoint_itm-report"
    ],
    "url": {
        "domain": "c-awfi.top",
        "full": "http://c-awfi.top/",
        "original": "http://c-awfi.top/",
        "path": "/",
        "scheme": "http"
    },
    "user": {
        "name": "Administrator"
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
| proofpoint_itm.report._time |  | date |
| proofpoint_itm.report.accessed.site_name |  | keyword |
| proofpoint_itm.report.accessed.url |  | keyword |
| proofpoint_itm.report.application_name |  | keyword |
| proofpoint_itm.report.collector.id |  | keyword |
| proofpoint_itm.report.collector.url |  | keyword |
| proofpoint_itm.report.command.params |  | keyword |
| proofpoint_itm.report.command.value |  | keyword |
| proofpoint_itm.report.created_at |  | date |
| proofpoint_itm.report.database_name |  | keyword |
| proofpoint_itm.report.details.name |  | keyword |
| proofpoint_itm.report.details.url |  | keyword |
| proofpoint_itm.report.domain_name |  | keyword |
| proofpoint_itm.report.endpoint.id |  | keyword |
| proofpoint_itm.report.endpoint.name |  | keyword |
| proofpoint_itm.report.event_playback_url |  | keyword |
| proofpoint_itm.report.friendly_name |  | keyword |
| proofpoint_itm.report.host |  | keyword |
| proofpoint_itm.report.id |  | keyword |
| proofpoint_itm.report.login_name |  | keyword |
| proofpoint_itm.report.observed_at |  | date |
| proofpoint_itm.report.operation_kind |  | keyword |
| proofpoint_itm.report.origin.file_name |  | keyword |
| proofpoint_itm.report.origin.site_name |  | keyword |
| proofpoint_itm.report.os |  | keyword |
| proofpoint_itm.report.playback_url |  | keyword |
| proofpoint_itm.report.process_executable |  | keyword |
| proofpoint_itm.report.remote.address |  | ip |
| proofpoint_itm.report.remote.host_name |  | keyword |
| proofpoint_itm.report.rising_value |  | date |
| proofpoint_itm.report.rule.category_name |  | keyword |
| proofpoint_itm.report.rule.desc |  | keyword |
| proofpoint_itm.report.rule.name |  | keyword |
| proofpoint_itm.report.secondary.domain_name |  | keyword |
| proofpoint_itm.report.secondary.login_name |  | keyword |
| proofpoint_itm.report.session.id |  | keyword |
| proofpoint_itm.report.session.url |  | keyword |
| proofpoint_itm.report.severity |  | keyword |
| proofpoint_itm.report.sql.command |  | keyword |
| proofpoint_itm.report.sql.user_name |  | keyword |
| proofpoint_itm.report.target.file_name |  | keyword |
| proofpoint_itm.report.target.site_name |  | keyword |
| proofpoint_itm.report.timezone_offset |  | long |
| proofpoint_itm.report.user_activity.event_id |  | keyword |
| proofpoint_itm.report.user_activity.observed_at |  | date |
| proofpoint_itm.report.window_title |  | keyword |

