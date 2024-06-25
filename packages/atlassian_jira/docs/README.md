# Atlassian Jira Integration

The Jira integration collects audit logs from the audit log files or the [audit API](https://confluence.atlassian.com/jiracore/audit-log-improvements-for-developers-1019401815.html).

## Authentication Set-Up

When setting up the Atlassian Jira Integration for Atlassian Cloud you will need to use the "Jira User Identifier" and "Jira API Token" fields in the integration configuration. These will allow connection to the [Atlassian Cloud REST API](https://developer.atlassian.com/cloud/jira/platform/basic-auth-for-rest-apis/) via [Basic Authentication](https://developer.atlassian.com/server/jira/platform/basic-authentication/).

If you are using a self-hosted instance, you will be able to use either the "Jira User Identifier" and "Jira API Token" fields above, *or* use the "Personal Access Token" field to [authenticate with a PAT](https://confluence.atlassian.com/enterprise/using-personal-access-tokens-1026032365.html). If the "Personal Access Token" field is set in the configuration, it will take precedence over the User ID/API Token fields. 

## Logs

### Audit

The Jira integration collects audit logs from the audit log files or the audit API from self hosted Jira Data Center. It has been tested with Jira 8.20.2 but is expected to work with newer versions.  As of version 1.2.0, this integration added experimental support for Atlassian JIRA Cloud.  JIRA Cloud only supports Basic Auth using username and a Personal Access Token.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
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
| jira.audit.affected_objects | Affected Objects | flattened |
| jira.audit.changed_values | Changed Values | flattened |
| jira.audit.extra_attributes | Extra Attributes | flattened |
| jira.audit.method | Method | keyword |
| jira.audit.type.action | Action | keyword |
| jira.audit.type.actionI18nKey | actionI18nKey | keyword |
| jira.audit.type.area | Area | keyword |
| jira.audit.type.category | Category | keyword |
| jira.audit.type.categoryI18nKey | categoryI18nKey | keyword |
| jira.audit.type.level | Audit Level | keyword |
| log.offset | Log offset | long |


An example event for `audit` looks as following:

```json
{
    "@timestamp": "2021-11-22T00:05:08.514Z",
    "agent": {
        "ephemeral_id": "4a05fc27-d72e-43ab-aa6e-e19105807ecd",
        "id": "cdda426a-7e47-48c4-b2f5-b9f1ad5bf08a",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.8.0"
    },
    "data_stream": {
        "dataset": "atlassian_jira.audit",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "cdda426a-7e47-48c4-b2f5-b9f1ad5bf08a",
        "snapshot": true,
        "version": "8.8.0"
    },
    "event": {
        "action": "jira.auditing.group.created",
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "dataset": "atlassian_jira.audit",
        "ingested": "2023-05-09T21:23:48Z",
        "kind": "event",
        "original": "{\"affectedObjects\":[{\"name\":\"jira-software-users\",\"type\":\"GROUP\"}],\"auditType\":{\"action\":\"Group created\",\"actionI18nKey\":\"jira.auditing.group.created\",\"area\":\"USER_MANAGEMENT\",\"category\":\"group management\",\"categoryI18nKey\":\"jira.auditing.category.groupmanagement\",\"level\":\"BASE\"},\"author\":{\"id\":\"-2\",\"name\":\"Anonymous\",\"type\":\"user\"},\"changedValues\":[],\"extraAttributes\":[],\"method\":\"Browser\",\"source\":\"10.50.33.72\",\"system\":\"http://jira.internal:8088\",\"timestamp\":{\"epochSecond\":1637539508,\"nano\":514000000},\"version\":\"1.0\"}",
        "type": [
            "group",
            "creation"
        ]
    },
    "group": {
        "name": "jira-software-users"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "cff3d165179d4aef9596ddbb263e3adb",
        "ip": [
            "172.23.0.7"
        ],
        "mac": [
            "02-42-AC-17-00-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.47-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.5 LTS (Focal Fossa)"
        }
    },
    "input": {
        "type": "log"
    },
    "jira": {
        "audit": {
            "affected_objects": [
                {
                    "name": "jira-software-users",
                    "type": "GROUP"
                }
            ],
            "method": "Browser",
            "type": {
                "action": "Group created",
                "actionI18nKey": "jira.auditing.group.created",
                "area": "USER_MANAGEMENT",
                "category": "group management",
                "categoryI18nKey": "jira.auditing.category.groupmanagement",
                "level": "BASE"
            }
        }
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/test-audit.log"
        },
        "offset": 0
    },
    "related": {
        "hosts": [
            "jira.internal"
        ],
        "ip": [
            "10.50.33.72"
        ],
        "user": [
            "Anonymous"
        ]
    },
    "service": {
        "address": "http://jira.internal:8088"
    },
    "source": {
        "address": "10.50.33.72",
        "ip": "10.50.33.72"
    },
    "tags": [
        "preserve_original_event",
        "jira-audit"
    ],
    "user": {
        "id": "-2",
        "name": "Anonymous"
    }
}

```
