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
    "@timestamp": "2022-05-12T11:30:05.248Z",
    "agent": {
        "ephemeral_id": "7f9603e8-5411-4ed1-acdc-d842f98e5c8b",
        "id": "fa4b2c2b-d00f-4e96-aaf3-d5de2b8544e6",
        "name": "elastic-agent-97786",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "santa.log",
        "namespace": "85590",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "fa4b2c2b-d00f-4e96-aaf3-d5de2b8544e6",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "action": "link",
        "agent_id_status": "verified",
        "dataset": "santa.log",
        "ingested": "2024-10-01T13:57:49Z",
        "kind": "event"
    },
    "file": {
        "path": "/private/var/db/santa/santa.log",
        "target_path": "/private/var/db/santa/santa.log.0"
    },
    "group": {
        "id": "0",
        "name": "wheel"
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "elastic-agent-97786",
        "id": "8269eab9370b4429947d2a16c3058fcb",
        "ip": [
            "172.19.0.2",
            "172.18.0.4"
        ],
        "mac": [
            "02-42-AC-12-00-04",
            "02-42-AC-13-00-02"
        ],
        "name": "elastic-agent-97786",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "6.10.0-linuxkit",
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
            "path": "/tmp/service_logs/santa.log"
        },
        "level": "I",
        "offset": 1150
    },
    "process": {
        "args": [
            "/usr/sbin/newsyslog"
        ],
        "entity_id": "fa4b2c2b-d00f-4e96-aaf3-d5de2b8544e6-71559-1096716",
        "executable": "/usr/sbin/newsyslog",
        "name": "newsyslog",
        "parent": {
            "pid": 1
        },
        "pid": 71559,
        "start": "2022-05-12T11:30:05.248Z"
    },
    "related": {
        "user": [
            "root"
        ]
    },
    "santa": {
        "action": "LINK",
        "pidversion": 1096716
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
| santa.action | Action | keyword |
| santa.certificate.common_name | Common name from code signing certificate. | keyword |
| santa.certificate.sha256 | SHA256 hash of code signing certificate. | keyword |
| santa.decision | Decision that santad took. | keyword |
| santa.disk.appearance | Timestamp for volume operation. | date |
| santa.disk.bsdname | The disk BSD name. | keyword |
| santa.disk.bus | The disk bus protocol. | keyword |
| santa.disk.dmgpath | The DMG (disk image) path. | keyword |
| santa.disk.fs | The disk volume kind (filesystem type). | keyword |
| santa.disk.model | The disk model. | keyword |
| santa.disk.mount | The disk volume path. | keyword |
| santa.disk.serial | The disk serial number. | keyword |
| santa.disk.volume | The volume name. | keyword |
| santa.event.uid | Event UID. | keyword |
| santa.event.user | Event user. | keyword |
| santa.explain | Further details for the decision. | keyword |
| santa.graphical_session_id | The graphical session ID. | long |
| santa.mode | Operating mode of Santa. | keyword |
| santa.pidversion | macOS process identity version. | long |
| santa.reason | Reason for the decision. | keyword |
| santa.team_id | Team ID. | keyword |

