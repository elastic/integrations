# CoreDNS Integration

This integration parses logs from [CoreDNS](https://coredns.io/) instances.

## Compatibility

This integration is designed to read CoreDNS logs running within a Kubernetes cluster or via systemd with logs output to journald. The CoreDNS datasets were tested with version 1.9.3 and 1.10.0.

## Logs

The log data stream expects logs from the CoreDNS [errors](https://coredns.io/plugins/errors/) plugin and the [log](https://coredns.io/plugins/log/) plugin. Query logs from the _log_ plugin can be in either the `common` or `combined` format (see [log format](https://coredns.io/plugins/log/#log-format) for details).
An example configuration with logging enabled is:
```
. {
  forward . 8.8.8.8
  errors
  log
}
```

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| coredns.log.buffer_size | The EDNS0 buffer size advertised in the query | long |
| coredns.log.dnssec_ok | The DO bit is included in a DNS query and is an abbreviation for "DNSSEC OK".  If the DO bit is set (DO=1), then the client is DNSSEC-aware, and it is OK for the DNS server to return DNSSEC data in a response.  If the DO bit is not set (DO=0), then the client is not DNSSEC-aware, and the DNS server must not include any DNSSEC data in a DNS response. | boolean |
| coredns.log.error.message | The error message | text |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| kubernetes.container.name | Kubernetes container name | keyword |
| kubernetes.labels.\* | Kubernetes labels map | object |
| kubernetes.namespace | Kubernetes namespace | keyword |
| kubernetes.node.name | Kubernetes node name | keyword |
| kubernetes.pod.name | Kubernetes pod name | keyword |
| kubernetes.pod.uid | Kubernetes pod UID | keyword |
| kubernetes.replicaset.name | Kubernetes replicaset name | keyword |
| log.file.device_id | ID of the device containing the filesystem where the file resides. | keyword |
| log.file.fingerprint | The sha256 fingerprint identity of the file when fingerprinting is enabled. | keyword |
| log.file.idxhi | The high-order part of a unique identifier that is associated with a file. (Windows-only) | keyword |
| log.file.idxlo | The low-order part of a unique identifier that is associated with a file. (Windows-only) | keyword |
| log.file.inode | Inode number of the log file. | keyword |
| log.file.vol | The serial number of the volume that contains a file. (Windows-only) | keyword |
| log.offset | Log offset | long |


An example event for `log` looks as following:

```json
{
    "@timestamp": "2023-09-27T18:59:58.096Z",
    "agent": {
        "ephemeral_id": "bbb180b6-3756-4f5b-81d5-6e333e740796",
        "id": "86a82f91-ff66-4d28-ab7c-eb9350f317ed",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.10.1"
    },
    "coredns": {
        "log": {
            "buffer_size": 1232,
            "dnssec_ok": false
        }
    },
    "data_stream": {
        "dataset": "coredns.log",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "bytes": 65
    },
    "dns": {
        "header_flags": [
            "RD",
            "RA"
        ],
        "id": "58521",
        "question": {
            "class": "IN",
            "name": "google.com",
            "registered_domain": "google.com",
            "top_level_domain": "com",
            "type": "A"
        },
        "response_code": "NOERROR"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "86a82f91-ff66-4d28-ab7c-eb9350f317ed",
        "snapshot": false,
        "version": "8.10.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "created": "2023-09-27T18:59:58.096Z",
        "dataset": "coredns.log",
        "duration": 32133957.999999996,
        "ingested": "2023-09-27T18:59:59Z",
        "kind": "event",
        "original": "[INFO] 192.168.112.3:45632 - 58521 \"A IN google.com. udp 51 false 1232\" NOERROR qr,rd,ra 65 0.032133958s",
        "outcome": "success",
        "type": [
            "protocol"
        ]
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
        "id": "ddbe644fa129402e9d5cf6452db1422d",
        "ip": [
            "172.31.0.7"
        ],
        "mac": [
            "02-42-AC-1F-00-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.15.49-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
        }
    },
    "input": {
        "type": "filestream"
    },
    "log": {
        "file": {
            "device_id": 141,
            "inode": 18614042,
            "path": "/tmp/service_logs/coredns.log"
        },
        "level": "info",
        "offset": 67
    },
    "network": {
        "bytes": 116,
        "iana_number": "17",
        "protocol": "dns",
        "transport": "udp"
    },
    "related": {
        "hosts": [
            "google.com"
        ],
        "ip": [
            "192.168.112.3"
        ]
    },
    "source": {
        "address": "192.168.112.3",
        "bytes": 51,
        "ip": "192.168.112.3",
        "port": 45632
    },
    "tags": [
        "preserve_original_event",
        "coredns-log"
    ]
}
```