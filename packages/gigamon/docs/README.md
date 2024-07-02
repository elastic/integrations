# Gigamon Integration

Gigamon leverages deep packet inspection (DPI) to extract over 7500+ app related metadata attributes from the raw packets in the network. With Elastic  integration, it delivers intelligent security analytics and threat intelligence across the enterprise, and you get a single solution for attack detection, threat visibility, proactive hunting and threat response.

## Compatibility

## Data streams

The Gigamon integration currently provides a single
data stream: `ami`.

## Requirements

- Elastic Agent must be installed.
- You can install only one Elastic Agent per host.

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to
define, configure, and manage your agents in a central location. We recommend
using Fleet management because it makes the management and upgrade of your
agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent
locally on the system where it is installed. You are responsible for managing
and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or
standalone. Docker images for all versions of Elastic Agent are available
from the Elastic Docker registry, and we provide deployment manifests for
running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more
information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

The minimum **kibana.version** required is **8.12.0**.


### Setup

## Gigamon setup


**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| gigamon.ami.app_id |  | long |
| gigamon.ami.app_name |  | keyword |
| gigamon.ami.device_inbound_interface |  | keyword |
| gigamon.ami.dns_ancount |  | long |
| gigamon.ami.dns_class |  | keyword |
| gigamon.ami.dns_flags |  | keyword |
| gigamon.ami.dns_host |  | keyword |
| gigamon.ami.dns_host_addr |  | keyword |
| gigamon.ami.dns_host_class |  | keyword |
| gigamon.ami.dns_host_raw |  | keyword |
| gigamon.ami.dns_host_type |  | keyword |
| gigamon.ami.dns_name |  | keyword |
| gigamon.ami.dns_opcode |  | keyword |
| gigamon.ami.dns_qdcount |  | long |
| gigamon.ami.dns_query |  | keyword |
| gigamon.ami.dns_query_type |  | keyword |
| gigamon.ami.dns_reply_code |  | keyword |
| gigamon.ami.dns_response_time |  | double |
| gigamon.ami.dns_transaction_id |  | long |
| gigamon.ami.dns_ttl |  | long |
| gigamon.ami.dst_bytes |  | long |
| gigamon.ami.dst_ip |  | ip |
| gigamon.ami.dst_mac |  | keyword |
| gigamon.ami.dst_packets |  | long |
| gigamon.ami.dst_port |  | long |
| gigamon.ami.egress_intf_id |  | keyword |
| gigamon.ami.end_reason |  | keyword |
| gigamon.ami.end_time |  | date |
| gigamon.ami.eventType |  | keyword |
| gigamon.ami.generator |  | keyword |
| gigamon.ami.http_code |  | long |
| gigamon.ami.http_content_len |  | long |
| gigamon.ami.http_content_type |  | keyword |
| gigamon.ami.http_host |  | keyword |
| gigamon.ami.http_method |  | keyword |
| gigamon.ami.http_mime_type |  | keyword |
| gigamon.ami.http_request_size |  | long |
| gigamon.ami.http_rtt |  | keyword |
| gigamon.ami.http_server |  | keyword |
| gigamon.ami.http_server_agent |  | keyword |
| gigamon.ami.http_uri |  | keyword |
| gigamon.ami.http_uri_decoded |  | keyword |
| gigamon.ami.http_uri_full |  | keyword |
| gigamon.ami.http_uri_path |  | keyword |
| gigamon.ami.http_uri_path_decoded |  | keyword |
| gigamon.ami.http_uri_raw |  | keyword |
| gigamon.ami.http_user_agent |  | keyword |
| gigamon.ami.http_version |  | keyword |
| gigamon.ami.id |  | keyword |
| gigamon.ami.intf_name |  | keyword |
| gigamon.ami.ip_version |  | keyword |
| gigamon.ami.protocol |  | keyword |
| gigamon.ami.seq_num |  | long |
| gigamon.ami.src_bytes |  | long |
| gigamon.ami.src_ip |  | ip |
| gigamon.ami.src_mac |  | keyword |
| gigamon.ami.src_packets |  | long |
| gigamon.ami.src_port |  | long |
| gigamon.ami.ssl_cert_ext_authority_key_id |  | keyword |
| gigamon.ami.ssl_cert_ext_subject_key_id |  | keyword |
| gigamon.ami.ssl_cert_extension_oid |  | keyword |
| gigamon.ami.ssl_certif_md5 |  | keyword |
| gigamon.ami.ssl_certif_sha1 |  | keyword |
| gigamon.ami.ssl_certificate_dn_issuer |  | keyword |
| gigamon.ami.ssl_certificate_dn_subject |  | keyword |
| gigamon.ami.ssl_certificate_issuer_c |  | keyword |
| gigamon.ami.ssl_certificate_issuer_cn |  | keyword |
| gigamon.ami.ssl_certificate_issuer_l |  | keyword |
| gigamon.ami.ssl_certificate_issuer_o |  | keyword |
| gigamon.ami.ssl_certificate_issuer_ou |  | keyword |
| gigamon.ami.ssl_certificate_issuer_st |  | keyword |
| gigamon.ami.ssl_certificate_subject_c |  | keyword |
| gigamon.ami.ssl_certificate_subject_cn |  | keyword |
| gigamon.ami.ssl_certificate_subject_key_algo_oid |  | keyword |
| gigamon.ami.ssl_certificate_subject_key_size |  | long |
| gigamon.ami.ssl_certificate_subject_l |  | keyword |
| gigamon.ami.ssl_certificate_subject_o |  | keyword |
| gigamon.ami.ssl_certificate_subject_ou |  | keyword |
| gigamon.ami.ssl_certificate_subject_st |  | keyword |
| gigamon.ami.ssl_cipher_suite_id |  | keyword |
| gigamon.ami.ssl_cipher_suite_list |  | keyword |
| gigamon.ami.ssl_client_hello_extension_len |  | long |
| gigamon.ami.ssl_client_hello_extension_type |  | keyword |
| gigamon.ami.ssl_common_name |  | keyword |
| gigamon.ami.ssl_compression_method |  | keyword |
| gigamon.ami.ssl_content_type |  | keyword |
| gigamon.ami.ssl_declassify_override |  | keyword |
| gigamon.ami.ssl_ext_sig_algorithm_hash |  | keyword |
| gigamon.ami.ssl_ext_sig_algorithm_scheme |  | keyword |
| gigamon.ami.ssl_ext_sig_algorithm_sig |  | keyword |
| gigamon.ami.ssl_ext_sig_algorithms_len |  | long |
| gigamon.ami.ssl_fingerprint_ja3 |  | keyword |
| gigamon.ami.ssl_fingerprint_ja3s |  | keyword |
| gigamon.ami.ssl_handshake_type |  | keyword |
| gigamon.ami.ssl_index |  | keyword |
| gigamon.ami.ssl_issuer |  | keyword |
| gigamon.ami.ssl_nb_compression_methods |  | keyword |
| gigamon.ami.ssl_organization_name |  | keyword |
| gigamon.ami.ssl_protocol_version |  | keyword |
| gigamon.ami.ssl_request_size |  | long |
| gigamon.ami.ssl_serial_number |  | keyword |
| gigamon.ami.ssl_server_hello_extension_len |  | long |
| gigamon.ami.ssl_server_hello_extension_type |  | keyword |
| gigamon.ami.ssl_session_id |  | keyword |
| gigamon.ami.ssl_signalization_override |  | keyword |
| gigamon.ami.ssl_validity_not_after |  | date |
| gigamon.ami.ssl_validity_not_before |  | date |
| gigamon.ami.start_time |  | date |
| gigamon.ami.sys_up_time_first |  | long |
| gigamon.ami.sys_up_time_last |  | long |
| gigamon.ami.tcp_flags |  | keyword |
| gigamon.ami.ts |  | date |
| gigamon.ami.vendor |  | keyword |
| gigamon.ami.version |  | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| tags | User defined tags. | keyword |


An example event for `ami` looks as following:

```json
{
    "@timestamp": "2023-05-16T15:25:25.000Z",
    "agent": {
        "ephemeral_id": "f5a167c5-f74e-4bb8-9409-365de6ad522b",
        "id": "3c45130b-2cfb-4c98-9cdb-9d70a0115914",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.2"
    },
    "data_stream": {
        "dataset": "gigamon.ami",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "3c45130b-2cfb-4c98-9cdb-9d70a0115914",
        "snapshot": false,
        "version": "8.12.2"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "gigamon.ami",
        "ingested": "2024-06-25T07:07:50Z",
        "original": "{\"app_id\":\"32\",\"app_name\":\"dns\",\"device_inbound_interface\":\"0\",\"dns_class\":\"1\",\"dns_flags\":\"0\",\"dns_host\":\"pnstrex-83816.local\",\"dns_host_addr\":\"10.114.82.101\",\"dns_host_class\":\"1\",\"dns_host_raw\":\"706e73747265782d38333831362e6c6f63616c\",\"dns_host_type\":\"PTR\",\"dns_name\":\"a.b.2.b.9.6.c.2.3.9.3.e.6.2.6.a.0.8.0.1.1.0.0.0.0.1.0.0.b.a.c.f. i:p6.arpa\",\"dns_opcode\":\"0\",\"dns_qdcount\":\"4\",\"dns_query\":\"f.7.5.2.e.7.6.2.4.c.1.c.e.c.6.1.0.8.0.2.1.0.1.0.0.0.0.0.b.a.c.f. ip6.arpa\",\"dns_query_type\":\"255\",\"dns_transaction_id\":\"0\",\"dns_ttl\":\"120\",\"dst_bytes\":\"0\",\"dst_ip\":\"67.43.156.0\",\"dst_mac\":\"01:00:4e:00:00:fg\",\"dst_packets\":\"0\",\"dst_port\":\"5353\",\"egress_intf_id\":\"0\",\"end_reason\":\"1\",\"end_time\":\"2023:12:13 15:25:11.181\",\"generator\":\"gs_apps_appInst16_423722da-33ec-1556-b24b-cda2e74a53f6\",\"id\":\"679408454713072647\",\"intf_name\":\"0\",\"ip_version\":\"4\",\"protocol\":\"17\",\"seq_num\":\"656\",\"src_bytes\":\"337\",\"src_ip\":\"89.160.20.128\",\"src_mac\":\"00:50:46:8d:79:41\",\"src_packets\":\"1\",\"src_port\":\"5353\",\"start_time\":\"2023:12:13 15:25:11.181\",\"sys_up_time_first\":\"3497355275\",\"sys_up_time_last\":\"3497355275\",\"ts\":\"Thu May 16 15:25:25 2023\",\"vendor\":\"Gigamon\",\"version\":\"6.5.00\"}"
    },
    "gigamon": {
        "ami": {
            "app_id": 32,
            "app_name": "dns",
            "device_inbound_interface": "0",
            "dns_class": "1",
            "dns_flags": "0",
            "dns_host": "pnstrex-83816.local",
            "dns_host_addr": "10.114.82.101",
            "dns_host_class": "1",
            "dns_host_raw": "706e73747265782d38333831362e6c6f63616c",
            "dns_host_type": "PTR",
            "dns_name": "a.b.2.b.9.6.c.2.3.9.3.e.6.2.6.a.0.8.0.1.1.0.0.0.0.1.0.0.b.a.c.f. i:p6.arpa",
            "dns_opcode": "0",
            "dns_qdcount": 4,
            "dns_query": "f.7.5.2.e.7.6.2.4.c.1.c.e.c.6.1.0.8.0.2.1.0.1.0.0.0.0.0.b.a.c.f. ip6.arpa",
            "dns_query_type": "255",
            "dns_transaction_id": 0,
            "dns_ttl": 120,
            "dst_bytes": 0,
            "dst_ip": "67.43.156.0",
            "dst_mac": "01:00:4e:00:00:fg",
            "dst_packets": 0,
            "dst_port": 5353,
            "egress_intf_id": "0",
            "end_reason": "1",
            "end_time": "2023-12-13T15:25:11.181Z",
            "generator": "gs_apps_appInst16_423722da-33ec-1556-b24b-cda2e74a53f6",
            "id": "679408454713072647",
            "intf_name": "0",
            "ip_version": "4",
            "protocol": "17",
            "seq_num": 656,
            "src_bytes": 337,
            "src_ip": "89.160.20.128",
            "src_mac": "00:50:46:8d:79:41",
            "src_packets": 1,
            "src_port": 5353,
            "start_time": "2023-12-13T15:25:11.181Z",
            "sys_up_time_first": 3497355275,
            "sys_up_time_last": 3497355275,
            "ts": "Thu May 16 15:25:25 2023",
            "vendor": "Gigamon",
            "version": "6.5.00"
        }
    },
    "input": {
        "type": "http_endpoint"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "gigamon-ami"
    ]
}
```
