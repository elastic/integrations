# FireEye Integration

This integration periodically fetches logs from [FireEye Network Security](https://www.fireeye.com/products/network-security.html) devices. 

## Compatibility

The FireEye `nx` integration has been developed against FireEye Network Security 9.0.0.916432 but is expected to work with other versions.

## Logs

### NX

The `nx` integration ingests network security logs from FireEye NX through TCP/UDP and file.

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
| fireeye.nx.fileinfo.filename | File name. | keyword |
| fireeye.nx.fileinfo.magic | Fileinfo magic. | keyword |
| fireeye.nx.fileinfo.md5 | File hash. | keyword |
| fireeye.nx.fileinfo.size | File size. | long |
| fireeye.nx.fileinfo.state | File state. | keyword |
| fireeye.nx.fileinfo.stored | File stored or not. | boolean |
| fireeye.nx.flow.age | Flow age. | long |
| fireeye.nx.flow.alerted | Flow alerted or not. | boolean |
| fireeye.nx.flow.endtime | Flow endtime. | date |
| fireeye.nx.flow.reason | Flow reason. | keyword |
| fireeye.nx.flow.starttime | Flow start time. | date |
| fireeye.nx.flow.state | Flow state. | keyword |
| fireeye.nx.flow_id | Flow ID of the event. | long |
| fireeye.nx.tcp.ack | TCP acknowledgement. | boolean |
| fireeye.nx.tcp.psh | TCP PSH. | boolean |
| fireeye.nx.tcp.state | TCP connectin state. | keyword |
| fireeye.nx.tcp.syn | TCP SYN. | boolean |
| fireeye.nx.tcp.tcp_flags | TCP flags. | keyword |
| fireeye.nx.tcp.tcp_flags_tc | TCP flags. | keyword |
| fireeye.nx.tcp.tcp_flags_ts | TCP flags. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| log.source.address | Logs Source Raw address. | keyword |
| tls.client.ciphersuites | TLS cipher suites by client. | long |
| tls.client.fingerprint | TLS fingerprint. | keyword |
| tls.client.ja3_string | A hash that identifies clients based on how they perform an SSL/TLS handshake. | keyword |
| tls.client.tls_exts | TLS extensions set by client. | long |
| tls.public_keylength | TLS public key length. | long |
| tls.server.ciphersuite | TLS cipher suites by server. | long |
| tls.server.ja3s_string | A hash that identifies servers based on how they perform an SSL/TLS handshake. | keyword |
| tls.server.tls_exts | TLS extensions set by server. | long |


An example event for `nx` looks as following:

```json
{
    "@timestamp": "2020-09-22T08:34:44.991Z",
    "agent": {
        "ephemeral_id": "dff6c436-37c3-4536-bdf9-08aed3ed94bd",
        "id": "f25d13cd-18cc-4e73-822c-c4f849322623",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.10.1"
    },
    "data_stream": {
        "dataset": "fireeye.nx",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "address": "ff02:0000:0000:0000:0000:0000:0000:0001",
        "bytes": 0,
        "ip": "ff02:0000:0000:0000:0000:0000:0000:0001",
        "packets": 0,
        "port": 10001
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "f25d13cd-18cc-4e73-822c-c4f849322623",
        "snapshot": false,
        "version": "8.10.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "fireeye.nx",
        "ingested": "2023-09-25T20:05:32Z",
        "original": "{\"rawmsg\":\"{\\\"timestamp\\\":\\\"2020-09-22T08:34:44.991339+0000\\\",\\\"flow_id\\\":721570461162990,\\\"event_type\\\":\\\"flow\\\",\\\"src_ip\\\":\\\"fe80:0000:0000:0000:feec:daff:fe31:b706\\\",\\\"src_port\\\":45944,\\\"dest_ip\\\":\\\"ff02:0000:0000:0000:0000:0000:0000:0001\\\",\\\"dest_port\\\":10001,\\\"proto\\\":\\\"UDP\\\",\\\"proto_number\\\":17,\\\"ip_tc\\\":0,\\\"app_proto\\\":\\\"failed\\\",\\\"flow\\\":{\\\"pkts_toserver\\\":8,\\\"pkts_toclient\\\":0,\\\"bytes_toserver\\\":1680,\\\"bytes_toclient\\\":0,\\\"start\\\":\\\"2020-09-22T08:34:12.761326+0000\\\",\\\"end\\\":\\\"2020-09-22T08:34:12.761348+0000\\\",\\\"age\\\":0,\\\"state\\\":\\\"new\\\",\\\"reason\\\":\\\"timeout\\\",\\\"alerted\\\":false}}\\n\",\"meta_sip4\":\"192.168.1.99\",\"meta_oml\":520,\"deviceid\":\"860665216674\",\"meta_cbname\":\"fireeye-7e0de1\"}",
        "timezone": "+00:00",
        "type": [
            "info"
        ]
    },
    "fireeye": {
        "nx": {
            "flow": {
                "age": 0,
                "alerted": false,
                "endtime": "2020-09-22T08:34:12.761348+0000",
                "reason": "timeout",
                "starttime": "2020-09-22T08:34:12.761326+0000",
                "state": "new"
            },
            "flow_id": 721570461162990
        }
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
        "id": "28da52b32df94b50aff67dfb8f1be3d6",
        "ip": [
            "192.168.80.5"
        ],
        "mac": [
            "02-42-C0-A8-50-05"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.104-linuxkit",
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
            "path": "/tmp/service_logs/fireeye-nx.log"
        },
        "offset": 0
    },
    "network": {
        "community_id": "1:McNAQcsUcKZYOHHZYm0sD8JiBLc=",
        "iana_number": "17",
        "protocol": "failed",
        "transport": "udp"
    },
    "observer": {
        "product": "NX",
        "vendor": "Fireeye"
    },
    "related": {
        "ip": [
            "fe80:0000:0000:0000:feec:daff:fe31:b706",
            "ff02:0000:0000:0000:0000:0000:0000:0001"
        ]
    },
    "source": {
        "address": "fe80:0000:0000:0000:feec:daff:fe31:b706",
        "bytes": 1680,
        "ip": "fe80:0000:0000:0000:feec:daff:fe31:b706",
        "packets": 8,
        "port": 45944
    },
    "tags": [
        "fireeye-nx"
    ]
}

```