# Google Santa Integration

The Google Santa integration collects and parses logs from [Google Santa](https://github.com/google/santa), a security tool for macOS that monitors process executions and can blacklist/whitelist
binaries.

## Compatibility

The Google Santa integration was tested with logs from Santa 0.9.14.

**Google Santa is available for MacOS only.**

The integration is by default configured to read logs from `/var/log/santa.log`.

## Logs

### Google Santa log

This is the Google Santa `log` dataset.

An example event for `log` looks as following:

```json
{
    "@timestamp": "2018-12-10T06:45:16.802Z",
    "agent": {
        "ephemeral_id": "e9d120ee-3138-47d0-9bf8-5b007a85f20e",
        "id": "584f3aea-648c-4e58-aba4-32b8f88d4396",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0-beta1"
    },
    "data_stream": {
        "dataset": "santa.log",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "1.12.0"
    },
    "elastic_agent": {
        "id": "584f3aea-648c-4e58-aba4-32b8f88d4396",
        "snapshot": false,
        "version": "8.0.0-beta1"
    },
    "event": {
        "action": "exec",
        "agent_id_status": "verified",
        "category": [
            "process"
        ],
        "dataset": "santa.log",
        "ingested": "2022-02-02T05:02:06Z",
        "kind": "event",
        "outcome": "success",
        "type": [
            "start"
        ]
    },
    "file": {
        "x509": {
            "issuer": {
                "common_name": "Software Signing"
            }
        }
    },
    "group": {
        "id": "0",
        "name": "wheel"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "4ccba669f0df47fa3f57a9e4169ae7f1",
        "ip": [
            "172.19.0.6"
        ],
        "mac": [
            "02:42:ac:13:00:06"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "Core",
            "family": "redhat",
            "kernel": "5.13.0-27-generic",
            "name": "CentOS Linux",
            "platform": "centos",
            "type": "linux",
            "version": "7 (Core)"
        }
    },
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/santa.log"
        },
        "level": "I",
        "offset": 0
    },
    "process": {
        "args": [
            "/usr/libexec/xpcproxy",
            "/usr/sbin/newsyslog"
        ],
        "executable": "/usr/libexec/xpcproxy",
        "hash": {
            "sha256": "c4bc09fd2f248534552f517acf3edb9a635aba2b02e46f49df683ea9b778e5b4"
        },
        "parent": {
            "pid": 1
        },
        "pid": 29678,
        "start": "2018-12-10T06:45:16.802Z"
    },
    "related": {
        "hash": [
            "2aa4b9973b7ba07add447ee4da8b5337c3ee2c3a991911e80e7282e8a751fc32",
            "c4bc09fd2f248534552f517acf3edb9a635aba2b02e46f49df683ea9b778e5b4"
        ],
        "user": [
            "root"
        ]
    },
    "santa": {
        "action": "EXEC",
        "certificate": {
            "common_name": "Software Signing",
            "sha256": "2aa4b9973b7ba07add447ee4da8b5337c3ee2c3a991911e80e7282e8a751fc32"
        },
        "decision": "ALLOW",
        "mode": "M",
        "reason": "CERT"
    },
    "tags": [
        "santa-log"
    ],
    "user": {
        "id": "0",
        "name": "root"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.module | Event module | constant_keyword |
| file.x509.issuer.common_name | List of common name (CN) of issuing certificate authority. | keyword |
| group.id | Unique identifier for the group on the system/platform. | keyword |
| group.name | Name of the group. | keyword |
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
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.offset | Log offset | long |
| process.args | Array of process arguments, starting with the absolute path to the executable. May be filtered to protect sensitive information. | keyword |
| process.executable | Absolute path to the process executable. | keyword |
| process.executable.text | Multi-field of `process.executable`. | match_only_text |
| process.hash.sha256 | SHA256 hash. | keyword |
| process.parent.pid | Process id. | long |
| process.pid | Process id. | long |
| process.start | The time the process started. | date |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| santa.action | Action | keyword |
| santa.certificate.common_name | Common name from code signing certificate. | keyword |
| santa.certificate.sha256 | SHA256 hash of code signing certificate. | keyword |
| santa.decision | Decision that santad took. | keyword |
| santa.disk.bsdname | The disk BSD name. | keyword |
| santa.disk.bus | The disk bus protocol. | keyword |
| santa.disk.fs | The disk volume kind (filesystem type). | keyword |
| santa.disk.model | The disk model. | keyword |
| santa.disk.mount | The disk volume path. | keyword |
| santa.disk.serial | The disk serial number. | keyword |
| santa.disk.volume | The volume name. | keyword |
| santa.mode | Operating mode of Santa. | keyword |
| santa.reason | Reason for the decision. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |

