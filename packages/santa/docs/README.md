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
        "ephemeral_id": "55a748a5-5ecc-451d-859d-988ea77abde5",
        "id": "bb043b0c-36d1-4054-81ed-2d3f4546a433",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.8.1"
    },
    "data_stream": {
        "dataset": "santa.log",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "bb043b0c-36d1-4054-81ed-2d3f4546a433",
        "snapshot": false,
        "version": "8.8.1"
    },
    "event": {
        "action": "link",
        "agent_id_status": "verified",
        "dataset": "santa.log",
        "ingested": "2023-07-06T20:01:12Z",
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
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "1de1e3b6561d4ccb9731539ce2f3baf3",
        "ip": [
            "192.168.16.7"
        ],
        "mac": [
            "02-42-C0-A8-10-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.47-linuxkit",
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
        "entity_id": "bb043b0c-36d1-4054-81ed-2d3f4546a433-71559-1096716",
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
| santa.disk.fs | The disk volume kind (filesystem type). | keyword |
| santa.disk.model | The disk model. | keyword |
| santa.disk.mount | The disk volume path. | keyword |
| santa.disk.serial | The disk serial number. | keyword |
| santa.disk.volume | The volume name. | keyword |
| santa.explain | Further details for the decision. | keyword |
| santa.mode | Operating mode of Santa. | keyword |
| santa.pidversion | macOS process identity version. | long |
| santa.reason | Reason for the decision. | keyword |

