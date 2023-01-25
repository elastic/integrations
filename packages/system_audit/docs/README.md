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
| host.architecture | Operating system architecture. | keyword |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host MAC addresses. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | match_only_text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Type of Auditbeat input. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| package.architecture | Package architecture. | keyword |
| package.build_version | Additional information about the build version of the installed package. For example use the commit SHA of a non-released package. | keyword |
| package.checksum | Checksum of the installed package for verification. | keyword |
| package.description | Description of the package. | keyword |
| package.install_scope | Indicating how the package was installed, e.g. user-local, global. | keyword |
| package.installed | Time when package was installed. | date |
| package.license | License under which the package was released. Use a short name, e.g. the license identifier from SPDX License List where possible (https://spdx.org/licenses/). | keyword |
| package.name | Package name | keyword |
| package.path | Path where the package is installed. | keyword |
| package.reference | Home page or reference URL of the software in this package, if available. | keyword |
| package.size | Package size in bytes. | long |
| package.type | Type of package. This should contain the package file type, rather than the package manager name. Examples: rpm, dpkg, brew, npm, gem, nupkg, jar. | keyword |
| package.version | Package version | keyword |
| system.audit.package.arch | Package architecture. | keyword |
| system.audit.package.entity_id | ID uniquely identifying the package. It is computed as a SHA-256 hash of the   host ID, package name, and package version. | keyword |
| system.audit.package.installtime | Package install time. | date |
| system.audit.package.license | Package license. | keyword |
| system.audit.package.name | Package name. | keyword |
| system.audit.package.release | Package release. | keyword |
| system.audit.package.size | Package size. | long |
| system.audit.package.summary | Package summary. |  |
| system.audit.package.url | Package URL. | keyword |
| system.audit.package.version | Package version. | keyword |
| tags | User defined tags | keyword |


An example event for `package` looks as following:

```json
{
    "@timestamp": "2023-01-25T08:27:20.042Z",
    "agent": {
        "ephemeral_id": "181b1976-1f6e-4069-88f8-25e2ed01d485",
        "id": "589f5b30-8199-49ee-8dfd-973fa2933c84",
        "name": "docker-fleet-agent",
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
        "id": "589f5b30-8199-49ee-8dfd-973fa2933c84",
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
        "id": "69a704a2-dd1d-476c-9455-072cb2838ccc",
        "ingested": "2023-01-25T08:27:21Z",
        "kind": "state",
        "module": "system",
        "type": [
            "info"
        ]
    },
    "host": {
        "name": "docker-fleet-agent"
    },
    "package": {
        "architecture": "all",
        "description": "add and remove users and groups",
        "name": "adduser",
        "size": 624,
        "type": "dpkg",
        "version": "3.118ubuntu2"
    },
    "system": {
        "audit": {
            "package": {
                "arch": "all",
                "entity_id": "OnUSNhuUQkyYgoKf",
                "name": "adduser",
                "size": 624,
                "summary": "add and remove users and groups",
                "version": "3.118ubuntu2"
            }
        }
    },
    "tags": [
        "forwarded",
        "audit-system-package"
    ]
}
```
