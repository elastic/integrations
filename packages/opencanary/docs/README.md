# OpenCanary

This integration is for [Thinkst OpenCanary](https://github.com/thinkst/opencanary) honeypot event logs. The package processes messages from OpenCanary honeypot logs.

## Data streams

The OpenCanary integration collects the following event types:

`events`: Collects the OpenCanary logs.

## Requirements

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search top bar, type **OpenCanary**.
3. Select the **OpenCanary** integration and add it.
4. Add all the required integration configuration parameters.
5. Save the integration.

## Logs

### OpenCanary

The `events` dataset collects the OpenCanary logs.

An example event for `events` looks as following:

```json
{
    "@timestamp": "2025-05-21T02:54:23.002Z",
    "agent": {
        "ephemeral_id": "8d51c220-ed3c-4159-9811-8da1fcd45066",
        "id": "25a5d87f-ff90-46b3-bd51-d65a0f0c23c7",
        "name": "elastic-agent-32912",
        "type": "filebeat",
        "version": "8.17.4"
    },
    "data_stream": {
        "dataset": "opencanary.events",
        "namespace": "80572",
        "type": "logs"
    },
    "destination": {
        "address": "1.128.0.1",
        "as": {
            "number": 64496,
            "organization": {
                "name": "Documentation ASN"
            }
        },
        "geo": {
            "city_name": "Greenwich",
            "continent_name": "Europe",
            "country_iso_code": "GB",
            "country_name": "United Kingdom",
            "location": {
                "lat": 51.47687,
                "lon": -0.00041
            },
            "region_iso_code": "GB-ENG",
            "region_name": "England"
        },
        "ip": "1.128.0.1",
        "port": 23
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "25a5d87f-ff90-46b3-bd51-d65a0f0c23c7",
        "snapshot": false,
        "version": "8.17.4"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network",
            "intrusion_detection"
        ],
        "created": "2025-05-21T02:54:23.002Z",
        "dataset": "opencanary.events",
        "ingested": "2025-05-22T13:03:43Z",
        "kind": "alert",
        "original": "{\"dst_host\": \"1.128.0.1\", \"dst_port\": 23, \"honeycred\": false, \"local_time\": \"2025-05-21 02:54:23.002821\", \"local_time_adjusted\": \"2025-05-21 02:54:23.002888\", \"logdata\": {\"PASSWORD\": \"admin\", \"USERNAME\": \"admin\"}, \"logtype\": 6001, \"node_id\": \"opencanary-1\", \"src_host\": \"1.128.0.10\", \"src_port\": 28884, \"utc_time\": \"2025-05-21 02:54:23.002880\"}",
        "provider": "LOG_TELNET_LOGIN_ATTEMPT",
        "start": "2025-05-21T02:54:23.002Z",
        "timezone": "+00:00",
        "type": [
            "connection"
        ]
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "elastic-agent-32912",
        "ip": [
            "172.22.0.2",
            "172.20.0.4"
        ],
        "mac": [
            "72-D6-4C-81-59-51",
            "DA-7B-39-1C-96-A3"
        ],
        "name": "elastic-agent-32912",
        "os": {
            "kernel": "6.10.14-linuxkit",
            "name": "Wolfi",
            "platform": "wolfi",
            "type": "linux",
            "version": "20230201"
        }
    },
    "input": {
        "type": "filestream"
    },
    "log": {
        "file": {
            "device_id": "44",
            "inode": "116",
            "path": "/tmp/service_logs/events.log"
        },
        "logger": "LOG_TELNET_LOGIN_ATTEMPT",
        "offset": 0
    },
    "network": {
        "direction": "internal"
    },
    "opencanary": {
        "dst_host": "1.128.0.1",
        "dst_port": 23,
        "honeycred": false,
        "local_time": "2025-05-21 02:54:23.002821",
        "local_time_adjusted": "2025-05-21 02:54:23.002888",
        "logdata": {
            "password": "admin",
            "username": "admin"
        },
        "logtype": 6001,
        "node": {
            "id": "opencanary-1"
        },
        "src_host": "1.128.0.10",
        "src_port": 28884,
        "utc_time": "2025-05-21 02:54:23.002880"
    },
    "related": {
        "ip": [
            "1.128.0.1",
            "1.128.0.10"
        ],
        "user": [
            "admin"
        ]
    },
    "source": {
        "address": "1.128.0.10",
        "as": {
            "number": 64496,
            "organization": {
                "name": "Documentation ASN"
            }
        },
        "geo": {
            "city_name": "Greenwich",
            "continent_name": "Europe",
            "country_iso_code": "GB",
            "country_name": "United Kingdom",
            "location": {
                "lat": 51.47687,
                "lon": -0.00041
            },
            "region_iso_code": "GB-ENG",
            "region_name": "England"
        },
        "ip": "1.128.0.10",
        "port": 28884
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "opencanary-logs"
    ],
    "user": {
        "name": "admin"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type. | keyword |
| log.file.device_id | ID of the device containing the filesystem where the file resides. | keyword |
| log.file.fingerprint | The sha256 fingerprint identity of the file when fingerprinting is enabled. | keyword |
| log.file.inode | Inode number of the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| opencanary.dst_host |  | keyword |
| opencanary.dst_port |  | integer |
| opencanary.honeycred |  | boolean |
| opencanary.level |  | keyword |
| opencanary.local_time |  | keyword |
| opencanary.local_time_adjusted |  | keyword |
| opencanary.logdata.auditaction |  | keyword |
| opencanary.logdata.banner_id |  | keyword |
| opencanary.logdata.community_string |  | keyword |
| opencanary.logdata.cwr |  | keyword |
| opencanary.logdata.data |  | keyword |
| opencanary.logdata.df |  | keyword |
| opencanary.logdata.domain |  | keyword |
| opencanary.logdata.ece |  | keyword |
| opencanary.logdata.function |  | keyword |
| opencanary.logdata.headers.\* |  | keyword |
| opencanary.logdata.host |  | keyword |
| opencanary.logdata.hostname |  | keyword |
| opencanary.logdata.id |  | long |
| opencanary.logdata.in |  | keyword |
| opencanary.logdata.language |  | keyword |
| opencanary.logdata.len |  | keyword |
| opencanary.logdata.localname |  | keyword |
| opencanary.logdata.mac |  | keyword |
| opencanary.logdata.msg.logdata | Generic log message field | text |
| opencanary.logdata.password | The password submitted to the service | keyword |
| opencanary.logdata.path |  | keyword |
| opencanary.logdata.prec |  | keyword |
| opencanary.logdata.proto |  | keyword |
| opencanary.logdata.remotename |  | keyword |
| opencanary.logdata.repo |  | keyword |
| opencanary.logdata.requests |  | keyword |
| opencanary.logdata.res |  | keyword |
| opencanary.logdata.session |  | keyword |
| opencanary.logdata.syn |  | keyword |
| opencanary.logdata.tos |  | keyword |
| opencanary.logdata.ttl |  | long |
| opencanary.logdata.urgp |  | long |
| opencanary.logdata.user |  | keyword |
| opencanary.logdata.useragent |  | keyword |
| opencanary.logdata.username |  | keyword |
| opencanary.logdata.window |  | long |
| opencanary.logtype |  | long |
| opencanary.mssql.client.app |  | keyword |
| opencanary.mssql.client.hostname |  | keyword |
| opencanary.mssql.client.interface_library |  | keyword |
| opencanary.mssql.database |  | keyword |
| opencanary.node.id | Identifier for the OpenCanary node as configured in `/etc/opencanaryd/opencanary.conf` | keyword |
| opencanary.ntp.cmd |  | keyword |
| opencanary.redis.args |  | keyword |
| opencanary.redis.command |  | keyword |
| opencanary.skin | Skin configured for the OpenCanary service. | keyword |
| opencanary.smb.audit_action |  | keyword |
| opencanary.smb.filename |  | keyword |
| opencanary.smb.share_name |  | keyword |
| opencanary.smb.smb_arch |  | keyword |
| opencanary.smb.smb_version |  | keyword |
| opencanary.smb.status |  | keyword |
| opencanary.src_host |  | keyword |
| opencanary.src_port |  | integer |
| opencanary.ssh.local_version |  | keyword |
| opencanary.ssh.remote_version |  | keyword |
| opencanary.tcp_banner.banner_id |  | keyword |
| opencanary.tcp_banner.data |  | keyword |
| opencanary.tcp_banner.function |  | keyword |
| opencanary.tcp_banner.secret_string |  | keyword |
| opencanary.tftp.filename |  | keyword |
| opencanary.tftp.node |  | keyword |
| opencanary.tftp.opcode |  | keyword |
| opencanary.utc_time |  | keyword |
| opencanary.vnc.client_response |  | keyword |
| opencanary.vnc.password |  | keyword |
| opencanary.vnc.server_challenge |  | keyword |

