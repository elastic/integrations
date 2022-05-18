# Google Santa Integration

The Google Santa integration collects and parses logs from [Google Santa](https://github.com/google/santa), a security tool for macOS that monitors process executions and can blacklist/whitelist
binaries.

## Compatibility

The Google Santa integration was tested with logs from Santa 2022.4.

**Google Santa is available for MacOS only.**

The integration is by default configured to read logs from `/var/db/santa/santa.log`.

## Logs

### Google Santa log

This is the Google Santa `log` dataset.

An example event for `log` looks as following:

```json
{
    "@timestamp": "2022-05-12T11:38:03.923Z",
    "ecs": {
        "version": "8.2.0"
    },
    "event": {
        "action": "exec",
        "category": [
            "process"
        ],
        "kind": "event",
        "original": "[2022-05-12T11:38:03.923Z] I santad: action=EXEC|decision=ALLOW|reason=BINARY|explain=critical system binary|sha256=43158bf397bf52001067319c591249307e2862daf8690828c15cdcc1ddf6166d|cert_sha256=d84db96af8c2e60ac4c851a21ec460f6f84e0235beb17d24a78712b9b021ed57|cert_cn=Software Signing|pid=71993|pidversion=1097732|ppid=1|uid=0|user=root|gid=0|group=wheel|mode=M|path=/usr/libexec/xpcproxy|args=xpcproxy com.apple.CoreAuthentication.agent",
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
    "log": {
        "level": "I"
    },
    "process": {
        "args": [
            "/usr/libexec/xpcproxy",
            "xpcproxy",
            "com.apple.CoreAuthentication.agent"
        ],
        "executable": "/usr/libexec/xpcproxy",
        "hash": {
            "sha256": "43158bf397bf52001067319c591249307e2862daf8690828c15cdcc1ddf6166d"
        },
        "parent": {
            "pid": 1
        },
        "pid": 71993,
        "start": "2022-05-12T11:38:03.923Z"
    },
    "related": {
        "hash": [
            "d84db96af8c2e60ac4c851a21ec460f6f84e0235beb17d24a78712b9b021ed57",
            "43158bf397bf52001067319c591249307e2862daf8690828c15cdcc1ddf6166d"
        ],
        "user": [
            "root"
        ]
    },
    "santa": {
        "action": "EXEC",
        "certificate": {
            "common_name": "Software Signing",
            "sha256": "d84db96af8c2e60ac4c851a21ec460f6f84e0235beb17d24a78712b9b021ed57"
        },
        "decision": "ALLOW",
        "explain": "critical system binary",
        "mode": "M",
        "pidversion": 1097732,
        "reason": "BINARY"
    },
    "tags": [
        "preserve_original_event"
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
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
| file.target_path | Target path for symlinks. | keyword |
| file.target_path.text | Multi-field of `file.target_path`. | match_only_text |
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
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.parent.pid | Process id. | long |
| process.pid | Process id. | long |
| process.start | The time the process started. | date |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| santa.action | Action | keyword |
| santa.certificate.common_name | Common name from code signing certificate. | keyword |
| santa.certificate.sha256 | SHA256 hash of code signing certificate. | keyword |
| santa.decision | Decision that santad took. | keyword |
| santa.disk.appearance | Timestamp for volume operation. | date |
| santa.disk.bsdname | The disk BSD name. | keyword |
| santa.disk.bus | The disk bus protocol. | keyword |
| santa.disk.fs | The disk volume kind (filesystem type). | keyword |
| santa.disk.model | The disk model. | keyword |
| santa.disk.mount | The disk volume path. | keyword |
| santa.disk.serial | The disk serial number. | keyword |
| santa.disk.volume | The volume name. | keyword |
| santa.explain | Further details for the decision. | keyword |
| santa.mode | Operating mode of Santa. | keyword |
| santa.pidversion | macOS process identity version. | long |
| santa.reason | Reason for the decision. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |

