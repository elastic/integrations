# Mattermost Integration

The Mattermost integration collects logs from [Mattermost](
https://docs.mattermost.com/) servers.  This integration has been tested with
Mattermost version 5.31.9 but is expected to work with other versions.

## Logs

### Audit

All access to the Mattermost REST API or CLI is audited.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| mattermost.audit.api_path | REST API endpoint | keyword |
| mattermost.audit.channel.id | ID of affected channel | keyword |
| mattermost.audit.channel.name | Name of affected channel | keyword |
| mattermost.audit.channel.type | Type of affected channel | keyword |
| mattermost.audit.cluster.id | Mattermost cluster ID | keyword |
| mattermost.audit.error.message | Mattermost error message | keyword |
| mattermost.audit.patch.id | ID of patched channel/team/user... | keyword |
| mattermost.audit.patch.name | Name of patched channel/team/user... | keyword |
| mattermost.audit.patch.roles | Roles of patched user | keyword |
| mattermost.audit.patch.type | Type of patched channel/team/user... | keyword |
| mattermost.audit.post.channel.id | Channel ID of post | keyword |
| mattermost.audit.post.id | Post ID | keyword |
| mattermost.audit.post.pinned | Whether or not the post was pinned to the channel | boolean |
| mattermost.audit.related.channel | List of channels realted to the event | keyword |
| mattermost.audit.related.team | List of channels realted to the event | keyword |
| mattermost.audit.session.id | ID of session used to call the API | keyword |
| mattermost.audit.status | Outcome of action/event, ex. success, fail, attempt... | keyword |
| mattermost.audit.team.id | ID of affected team | keyword |
| mattermost.audit.team.name | Name of affected team | keyword |
| mattermost.audit.team.type | Type of affected team | keyword |


An example event for `audit` looks as following:

```json
{
    "@timestamp": "2021-12-04T23:19:32.051Z",
    "agent": {
        "ephemeral_id": "3a1ecfb2-18a4-46c9-9996-65f6853ed739",
        "id": "d2a14a09-96fc-4f81-94ef-b0cd75ad71e7",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "mattermost.audit",
        "namespace": "26102",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "d2a14a09-96fc-4f81-94ef-b0cd75ad71e7",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "action": "updateConfig",
        "agent_id_status": "verified",
        "category": [
            "configuration"
        ],
        "dataset": "mattermost.audit",
        "ingested": "2024-06-12T03:15:44Z",
        "kind": "event",
        "original": "{\"timestamp\":\"2021-12-04 23:19:32.051 Z\",\"event\":\"updateConfig\",\"status\":\"success\",\"user_id\":\"ag99yu4i1if63jrui63tsmq57y\",\"session_id\":\"pjh4n69j3p883k7hhzippskcba\",\"ip_address\":\"172.19.0.1\",\"api_path\":\"/api/v4/config\",\"cluster_id\":\"jq3utry71f8a7q9qgebmjccf4r\",\"client\":\"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36\"}",
        "outcome": "success",
        "type": [
            "change"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
        "id": "8259e024976a406e8a54cdbffeb84fec",
        "ip": [
            "172.19.0.7"
        ],
        "mac": [
            "02-42-AC-13-00-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "6.5.11-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
        }
    },
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/audit.log"
        },
        "offset": 0
    },
    "mattermost": {
        "audit": {
            "api_path": "/api/v4/config",
            "cluster": {
                "id": "jq3utry71f8a7q9qgebmjccf4r"
            },
            "session": {
                "id": "pjh4n69j3p883k7hhzippskcba"
            }
        }
    },
    "related": {
        "ip": [
            "172.19.0.1"
        ],
        "user": [
            "ag99yu4i1if63jrui63tsmq57y"
        ]
    },
    "source": {
        "address": "172.19.0.1",
        "ip": "172.19.0.1"
    },
    "tags": [
        "mattermost-audit",
        "preserve_original_event"
    ],
    "url": {
        "original": "/api/v4/config",
        "path": "/api/v4/config"
    },
    "user": {
        "id": "ag99yu4i1if63jrui63tsmq57y"
    },
    "user_agent": {
        "device": {
            "name": "Other"
        },
        "name": "Chrome",
        "original": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36",
        "os": {
            "full": "Windows 10",
            "name": "Windows",
            "version": "10"
        },
        "version": "96.0.4664.45"
    }
}
```
