# Atlassian Bitbucket Integration

The Bitbucket integration collects audit logs from the audit log files or the [audit API](https://developer.atlassian.com/server/bitbucket/reference/rest-api/). 

For more information on auditing in Bitbucket and how it can be configured, see [View and configure the audit log](https://confluence.atlassian.com/bitbucketserver/view-and-configure-the-audit-log-776640417.html) on Atlassian's website.

## Logs

### Audit

The Bitbucket integration collects audit logs from the audit log files or the audit API from self hosted Bitbucket Data Center. It has been tested with Bitbucket 7.18.1 but is expected to work with newer versions.  This has not been tested with Bitbucket Cloud and is not expected to work.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| bitbucket.audit.affected_objects | Affected Objects | flattened |
| bitbucket.audit.changed_values | Changed Values | flattened |
| bitbucket.audit.extra_attributes | Extra Attributes | flattened |
| bitbucket.audit.method | Method | keyword |
| bitbucket.audit.type.action | Action | keyword |
| bitbucket.audit.type.actionI18nKey | actionI18nKey | keyword |
| bitbucket.audit.type.area | Area | keyword |
| bitbucket.audit.type.category | Category | keyword |
| bitbucket.audit.type.categoryI18nKey | categoryI18nKey | keyword |
| bitbucket.audit.type.level | Audit Level | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
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
    "@timestamp": "2021-11-27T18:13:19.888Z",
    "agent": {
        "ephemeral_id": "949c3cd9-59d0-4214-bd94-b4388d99ca39",
        "id": "111e6217-e5c2-49d6-88df-a1a2f716685b",
        "name": "elastic-agent-45713",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "bitbucket": {
        "audit": {
            "affected_objects": [
                {
                    "id": "3",
                    "name": "AT",
                    "type": "PROJECT"
                }
            ],
            "extra_attributes": [
                {
                    "name": "target",
                    "nameI18nKey": "bitbucket.audit.attribute.legacy.target",
                    "value": "AT"
                }
            ],
            "method": "Browser",
            "type": {
                "action": "Project deletion requested",
                "actionI18nKey": "bitbucket.service.project.audit.action.projectdeletionrequested",
                "area": "LOCAL_CONFIG_AND_ADMINISTRATION",
                "category": "Projects",
                "categoryI18nKey": "bitbucket.service.audit.category.projects",
                "level": "BASE"
            }
        }
    },
    "data_stream": {
        "dataset": "atlassian_bitbucket.audit",
        "namespace": "68281",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "111e6217-e5c2-49d6-88df-a1a2f716685b",
        "snapshot": false,
        "version": "8.19.4"
    },
    "event": {
        "action": "bitbucket.service.project.audit.action.projectdeletionrequested",
        "agent_id_status": "verified",
        "category": [
            "configuration"
        ],
        "dataset": "atlassian_bitbucket.audit",
        "ingested": "2025-10-05T12:01:16Z",
        "kind": "event",
        "original": "{\"affectedObjects\":[{\"id\":\"3\",\"name\":\"AT\",\"type\":\"PROJECT\"}],\"auditType\":{\"action\":\"Project deletion requested\",\"actionI18nKey\":\"bitbucket.service.project.audit.action.projectdeletionrequested\",\"area\":\"LOCAL_CONFIG_AND_ADMINISTRATION\",\"category\":\"Projects\",\"categoryI18nKey\":\"bitbucket.service.audit.category.projects\",\"level\":\"BASE\"},\"author\":{\"id\":\"2\",\"name\":\"admin\",\"type\":\"NORMAL\"},\"changedValues\":[],\"extraAttributes\":[{\"name\":\"target\",\"nameI18nKey\":\"bitbucket.audit.attribute.legacy.target\",\"value\":\"AT\"}],\"method\":\"Browser\",\"node\":\"8767044c-1b98-4d64-82db-ef29af8c3792\",\"source\":\"10.100.100.2\",\"system\":\"http://bitbucket.internal:7990\",\"timestamp\":{\"epochSecond\":1638036799,\"nano\":888000000},\"version\":\"1.0\"}",
        "type": [
            "deletion"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "elastic-agent-45713",
        "ip": [
            "192.168.244.2",
            "192.168.240.8"
        ],
        "mac": [
            "82-A2-D4-5B-A7-85",
            "9E-8C-8A-A2-0F-DB"
        ],
        "name": "elastic-agent-45713",
        "os": {
            "kernel": "5.15.0-156-generic",
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
            "bitbucket.internal"
        ],
        "ip": [
            "10.100.100.2"
        ],
        "user": [
            "admin"
        ]
    },
    "service": {
        "address": "http://bitbucket.internal:7990"
    },
    "source": {
        "address": "10.100.100.2",
        "ip": "10.100.100.2"
    },
    "tags": [
        "preserve_original_event",
        "bitbucket-audit"
    ],
    "user": {
        "id": "2",
        "name": "admin"
    }
}
```