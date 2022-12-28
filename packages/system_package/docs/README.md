# Custom System Package integration

This is the `package` dataset of the system module.

It is implemented for Linux distributions using dpkg or rpm as their package
manager, and for Homebrew on macOS (Darwin).

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| input.type | Type of Auditbeat input. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| package.arch | Package architecture. | keyword |
| package.entity_id | ID uniquely identifying the package. It is computed as a SHA-256 hash of the   host ID, package name, and package version. | keyword |
| package.installtime | Package install time. | date |
| package.license | Package license. | keyword |
| package.name | Package name. | keyword |
| package.release | Package release. | keyword |
| package.size | Package size. | long |
| package.summary | Package summary. |  |
| package.type | Package manager type. | keyword |
| package.url | Package URL. | keyword |
| package.version | Package version. | keyword |
| tags | List of keywords used to tag each event. | keyword |


An example event for `log` looks as following:

```json
{
    "@timestamp": "2022-12-28T13:32:42.472Z",
    "agent": {
        "ephemeral_id": "bde7be28-9e57-4e31-bd5d-9175e1ab48ae",
        "id": "d2000373-45b2-4581-8f2e-1ec84f6de394",
        "name": "docker-custom-agent",
        "type": "auditbeat",
        "version": "8.5.1"
    },
    "data_stream": {
        "dataset": "system_package.log",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.5.1"
    },
    "elastic_agent": {
        "id": "d2000373-45b2-4581-8f2e-1ec84f6de394",
        "snapshot": false,
        "version": "8.5.1"
    },
    "event": {
        "action": "existing_package",
        "agent_id_status": "verified",
        "category": [
            "package"
        ],
        "dataset": "system_package.log",
        "id": "7a02b6d1-ed87-49f5-8f63-867560f345aa",
        "ingested": "2022-12-28T13:32:43Z",
        "kind": "state",
        "module": "system",
        "type": [
            "info"
        ]
    },
    "host": {
        "name": "docker-custom-agent"
    },
    "package": {
        "arch": "all",
        "entity_id": "OnUSNhuUQkyYgoKf",
        "name": "adduser",
        "size": 624,
        "summary": "add and remove users and groups",
        "type": "dpkg",
        "version": "3.118ubuntu2"
    },
    "tags": [
        "forwarded",
        "audit-system-package"
    ]
}
```
