# Atlassian Confluence Integration

The Confluence integration collects [audit logs](https://confluence.atlassian.com/doc/auditing-in-confluence-829076528.html) from the audit log files or the [audit API](https://developer.atlassian.com/cloud/confluence/rest/api-group-audit/).

## Authentication Set-Up

When setting up the Atlassian Confluence Integration for Atlassian Cloud you will need to use the "Confluence User Identifier" and "Confluence API Token" fields in the integration configuration. These will allow connection to the [Atlassian Cloud REST API](https://developer.atlassian.com/cloud/confluence/basic-auth-for-rest-apis/).

If you are using a self-hosted instance, you will be able to use either the "Confluence User Identifier" and "Confluence API Token" fields above, *or* use the "Personal Access Token" field to [authenticate with a PAT](https://confluence.atlassian.com/enterprise/using-personal-access-tokens-1026032365.html). If the "Personal Access Token" field is set in the configuration, it will take precedence over the User ID/API Token fields. 

## Logs

### Audit

The Confluence integration collects audit logs from the audit log files or the audit API from self hosted Confluence Data Center. It has been tested with Confluence 7.14.2 but is expected to work with newer versions. As of version 1.2.0, this integration added experimental support for Atlassian Confluence Cloud.  JIRA Cloud only supports Basic Auth using username and a Personal Access Token.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| confluence.audit.affected_objects | Affected Objects | flattened |
| confluence.audit.changed_values | Changed Values | flattened |
| confluence.audit.external_collaborator | Whether the user is an external collaborator user | boolean |
| confluence.audit.extra_attributes | Extra Attributes | flattened |
| confluence.audit.method | Method | keyword |
| confluence.audit.type.action | Action | keyword |
| confluence.audit.type.actionI18nKey | actionI18nKey | keyword |
| confluence.audit.type.area | Area | keyword |
| confluence.audit.type.category | Category | keyword |
| confluence.audit.type.categoryI18nKey | categoryI18nKey | keyword |
| confluence.audit.type.level | Audit Level | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |


An example event for `audit` looks as following:

```json
{
    "@timestamp": "2021-11-22T23:44:13.873Z",
    "agent": {
        "ephemeral_id": "806232da-7e85-4c7d-984b-fa5ca6a999b2",
        "id": "2b5e780d-acdf-4a81-a918-32e218f0e03f",
        "name": "elastic-agent-27484",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "confluence": {
        "audit": {
            "extra_attributes": [
                {
                    "name": "Query",
                    "nameI18nKey": "atlassian.audit.event.attribute.query"
                },
                {
                    "name": "Results returned",
                    "nameI18nKey": "atlassian.audit.event.attribute.results",
                    "value": "57"
                },
                {
                    "name": "ID Range",
                    "nameI18nKey": "atlassian.audit.event.attribute.id",
                    "value": "1 - 57"
                },
                {
                    "name": "Timestamp Range",
                    "nameI18nKey": "atlassian.audit.event.attribute.timestamp",
                    "value": "2021-11-22T23:42:45.791Z - 2021-11-22T23:43:22.615Z"
                }
            ],
            "method": "Browser",
            "type": {
                "action": "Audit Log search performed",
                "actionI18nKey": "atlassian.audit.event.action.audit.search",
                "area": "AUDIT_LOG",
                "category": "Auditing",
                "categoryI18nKey": "atlassian.audit.event.category.audit",
                "level": "BASE"
            }
        }
    },
    "data_stream": {
        "dataset": "atlassian_confluence.audit",
        "namespace": "58111",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "2b5e780d-acdf-4a81-a918-32e218f0e03f",
        "snapshot": true,
        "version": "8.18.0"
    },
    "event": {
        "action": "atlassian.audit.event.action.audit.search",
        "agent_id_status": "verified",
        "dataset": "atlassian_confluence.audit",
        "ingested": "2025-04-24T10:46:22Z",
        "kind": "event",
        "original": "{\"affectedObjects\":[],\"auditType\":{\"action\":\"Audit Log search performed\",\"actionI18nKey\":\"atlassian.audit.event.action.audit.search\",\"area\":\"AUDIT_LOG\",\"category\":\"Auditing\",\"categoryI18nKey\":\"atlassian.audit.event.category.audit\",\"level\":\"BASE\"},\"author\":{\"id\":\"2c9580827d4a06e8017d4a07c3e10000\",\"name\":\"test.user\",\"type\":\"user\"},\"changedValues\":[],\"extraAttributes\":[{\"name\":\"Query\",\"nameI18nKey\":\"atlassian.audit.event.attribute.query\",\"value\":\"\"},{\"name\":\"Results returned\",\"nameI18nKey\":\"atlassian.audit.event.attribute.results\",\"value\":\"57\"},{\"name\":\"ID Range\",\"nameI18nKey\":\"atlassian.audit.event.attribute.id\",\"value\":\"1 - 57\"},{\"name\":\"Timestamp Range\",\"nameI18nKey\":\"atlassian.audit.event.attribute.timestamp\",\"value\":\"2021-11-22T23:42:45.791Z - 2021-11-22T23:43:22.615Z\"}],\"method\":\"Browser\",\"source\":\"81.2.69.143\",\"system\":\"http://confluence.internal:8090\",\"timestamp\":{\"epochSecond\":1637624653,\"nano\":873000000},\"version\":\"1.0\"}",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "elastic-agent-27484",
        "ip": [
            "192.168.241.2",
            "192.168.249.4"
        ],
        "mac": [
            "02-42-C0-A8-F1-02",
            "02-42-C0-A8-F9-04"
        ],
        "name": "elastic-agent-27484",
        "os": {
            "kernel": "3.10.0-1160.81.1.el7.x86_64",
            "name": "Wolfi",
            "platform": "wolfi",
            "type": "linux",
            "version": "20230201"
        }
    },
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/test-audit.log"
        },
        "offset": 0
    },
    "related": {
        "hosts": [
            "confluence.internal"
        ],
        "ip": [
            "81.2.69.143"
        ]
    },
    "service": {
        "address": "http://confluence.internal:8090"
    },
    "source": {
        "address": "81.2.69.143",
        "geo": {
            "city_name": "London",
            "continent_name": "Europe",
            "country_iso_code": "GB",
            "country_name": "United Kingdom",
            "location": {
                "lat": 51.5142,
                "lon": -0.0931
            },
            "region_iso_code": "GB-ENG",
            "region_name": "England"
        },
        "ip": "81.2.69.143"
    },
    "tags": [
        "preserve_original_event",
        "confluence-audit"
    ],
    "user": {
        "full_name": "test.user",
        "id": "2c9580827d4a06e8017d4a07c3e10000"
    }
}
```