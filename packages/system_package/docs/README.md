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
    "@timestamp": "2022-12-14T10:55:42.705Z",
    "message": "Package azure-cli (2.42.0) is already installed",
    "service": {
        "type": "system"
    },
    "agent": {
        "version": "8.7.0",
        "ephemeral_id": "7ac43448-c2d1-4ce4-aa50-9fa79da54316",
        "id": "223c1991-0f6e-4476-80e3-053282f33dd2",
        "name": "Shouries-MacBook-Pro.local",
        "type": "auditbeat"
    },
    "ecs": {
        "version": "8.5.1"
    },
    "system": {
        "audit": {
            "package": {
                "name": "azure-cli",
                "version": "2.42.0",
                "installtime": "2022-11-09T05:54:04.634Z",
                "summary": "Microsoft Azure CLI 2.0",
                "url": "https://docs.microsoft.com/cli/azure/overview",
                "entity_id": "kEElM9vlcg1VuN9E"
            }
        }
    },
    "event": {
        "kind": "state",
        "category": [
            "package"
        ],
        "type": [
            "info"
        ],
        "action": "existing_package",
        "id": "8a4dc7a9-c354-4563-a822-7dacbb146fc6",
        "module": "system",
        "dataset": "package"
    },
    "package": {
        "installed": "2022-11-09T05:54:04.634Z",
        "description": "Microsoft Azure CLI 2.0",
        "reference": "https://docs.microsoft.com/cli/azure/overview",
        "type": "brew",
        "name": "azure-cli",
        "version": "2.42.0"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "auditd-system-package"
    ]
}
```
