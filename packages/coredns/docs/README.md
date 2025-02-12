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

**ECS Field Reference**

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
    "@timestamp": "2025-02-11T12:35:51.176Z",
    "agent": {
        "ephemeral_id": "a75480a0-76e2-405c-8d22-f94565290605",
        "id": "350e4955-b5fc-4e5f-aec3-3fd91ae31e8c",
        "name": "elastic-agent-60157",
        "type": "filebeat",
        "version": "9.0.0"
    },
    "coredns": {
        "log": {
            "buffer_size": 1232,
            "dnssec_ok": false
        }
    },
    "data_stream": {
        "dataset": "coredns.log",
        "namespace": "52129",
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
        "id": "18320",
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
        "id": "350e4955-b5fc-4e5f-aec3-3fd91ae31e8c",
        "snapshot": true,
        "version": "9.0.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "created": "2025-02-11T12:35:51.176Z",
        "dataset": "coredns.log",
        "duration": 13501371,
        "ingested": "2025-02-11T12:35:52Z",
        "kind": "event",
        "module": "coredns",
        "original": "[INFO] 192.168.254.3:54031 - 18320 \"A IN google.com. udp 51 false 1232\" NOERROR qr,rd,ra 65 0.013501371s",
        "outcome": "success",
        "type": [
            "protocol"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "elastic-agent-60157",
        "ip": [
            "192.168.253.2",
            "192.168.245.6"
        ],
        "mac": [
            "02-42-C0-A8-F5-06",
            "02-42-C0-A8-FD-02"
        ],
        "name": "elastic-agent-60157",
        "os": {
            "family": "",
            "kernel": "3.10.0-1160.118.1.el7.x86_64",
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
            "device_id": "64768",
            "fingerprint": "e0fe3490d4af287771c9a48344064d30bc9da48cdf1c20296fd81b614118f16a",
            "inode": "35527099",
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
            "192.168.254.3"
        ]
    },
    "source": {
        "address": "192.168.254.3",
        "bytes": 51,
        "ip": "192.168.254.3",
        "port": 54031
    },
    "tags": [
        "preserve_original_event",
        "coredns-log"
    ]
}
```