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
    "@timestamp": "2021-11-27T18:10:57.316Z",
    "agent": {
        "ephemeral_id": "c1c6859f-88f5-4ae8-ad40-5c0c9fe933d1",
        "id": "82d0dfd8-3946-4ac0-a092-a9146a71e3f7",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0-beta1"
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
                "action": "Project created",
                "actionI18nKey": "bitbucket.service.project.audit.action.projectcreated",
                "category": "Projects",
                "categoryI18nKey": "bitbucket.service.audit.category.projects"
            }
        }
    },
    "data_stream": {
        "dataset": "atlassian_bitbucket.audit",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "82d0dfd8-3946-4ac0-a092-a9146a71e3f7",
        "snapshot": false,
        "version": "8.0.0-beta1"
    },
    "event": {
        "action": "bitbucket.service.project.audit.action.projectcreated",
        "agent_id_status": "verified",
        "category": [
            "configuration"
        ],
        "created": "2021-12-24T00:39:23.076Z",
        "dataset": "atlassian_bitbucket.audit",
        "ingested": "2021-12-24T00:39:24Z",
        "kind": "event",
        "original": "{\"affectedObjects\":[{\"id\":\"3\",\"name\":\"AT\",\"type\":\"PROJECT\"}],\"author\":{\"avatarUri\":\"\",\"id\":\"2\",\"name\":\"admin\",\"type\":\"NORMAL\",\"uri\":\"http://bitbucket.internal:7990/users/admin\"},\"changedValues\":[],\"extraAttributes\":[{\"name\":\"target\",\"nameI18nKey\":\"bitbucket.audit.attribute.legacy.target\",\"value\":\"AT\"}],\"method\":\"Browser\",\"node\":\"8767044c-1b98-4d64-82db-ef29af8c3792\",\"source\":\"10.100.100.2\",\"system\":\"http://bitbucket.internal:7990\",\"timestamp\":\"2021-11-27T18:10:57.316Z\",\"type\":{\"action\":\"Project created\",\"actionI18nKey\":\"bitbucket.service.project.audit.action.projectcreated\",\"category\":\"Projects\",\"categoryI18nKey\":\"bitbucket.service.audit.category.projects\"}}",
        "type": [
            "creation"
        ]
    },
    "input": {
        "type": "httpjson"
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
        "forwarded",
        "bitbucket-audit"
    ],
    "user": {
        "id": "2",
        "name": "admin"
    }
}

```