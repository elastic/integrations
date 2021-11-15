# Snyk Integration

This integration is for ingesting data from the [Snyk](https://snyk.io/) API.

- `vulnerabilities`: Collects all found vulnerabilities for the related organizations and projects
- `audit`: Collects audit logging from Snyk, this can be actions like users, permissions, groups, api access and more.

To configure access to the Snyk Audit Log API you will have to generate an API access token as described in the https://snyk.docs.apiary.io/#introduction/authorization[Snyk Documentation]


## Audit

An example event for `audit` looks as following:

```json
{
    "@timestamp": "2020-11-17T14:30:13.800Z",
    "ecs": {
        "version": "1.12.0"
    },
    "snyk": {
        "audit": {
            "org_id": "orgid123test-5643asd234-asdfasdf",
            "content": {
                "sessionPublicId": "sessionId123-t34123-sdfa234-asd"
            }
        }
    },
    "event": {
        "action": "user.logged_in",
        "ingested": "2021-11-15T17:55:51.880500811Z",
        "original": "{\"groupId\":\"groupid123test-543123-54312sadf-123ad\",\"orgId\":\"orgid123test-5643asd234-asdfasdf\",\"userId\":\"userid123test-234sdfa2-423sdfa-2134\",\"projectId\":null,\"event\":\"user.logged_in\",\"content\":{\"sessionPublicId\":\"sessionId123-t34123-sdfa234-asd\"},\"created\":\"2020-11-17T14:30:13.800Z\"}"
    },
    "user": {
        "id": "userid123test-234sdfa2-423sdfa-2134",
        "group": {
            "id": "groupid123test-543123-54312sadf-123ad"
        }
    },
    "tags": [
        "preserve_original_event"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.path | Path to the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| snyk.audit.content | Overview of the content that was changed, both old and new values. | flattened |
| snyk.audit.org_id | ID of the related Organization related to the event. | keyword |
| snyk.audit.project_id | ID of the project related to the event. | keyword |
| snyk.projects | Array with all related projects objects. | flattened |
| snyk.related.projects | Array of all the related project ID's. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.id | Unique identifier of the user. | keyword |

