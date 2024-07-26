:# Gigamon Integration

Gigamon leverages deep packet inspection (DPI) to extract over 7500+ app related metadata attributes from the raw packets in the network. Gigamon Elastic Integration delivers intelligent security analytics and threat intelligence across the enterprise, and you get a single solution for attack detection, threat visibility, proactive hunting, and threat response.

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

To export data to Gigamon Elastic Integration.

1. From Fabric Manager, Deploy an AMX node with traffic acquisition method as "Customer Orchestrated Source".

2. Create an Monitoring Session with (Rep In ----> AMX ---> Rep Out).



To add AMX application:

1. Drag and drop Application Metadata Exporter from APPLICATIONS to the graphical workspace. The Application quick view appears.
2. Enter the Alias for the application. Enter a port number for the Cloud Tool Ingestor Port. Then, click the Add button for Cloud Tool Exports.
3. You can export your Application Metadata Intelligence output to cloud tools. Enter the following details for the Cloud tool export in the Application quick view:

Alias             Enter the alias name for the cloud tool export.

Cloud Tool        Select the Cloud tool from the drop-down menu.If it is not available click "others".

Endpoint          Give the URL of the cloud tool instance with the correct port number in which the port is listening.

Headers           Enter the secret header and enable secure keys

Enable Export     Enable the box to export the Application Metadata Intelligence output in JSON format.

Zip               Enable the box to compress the output file.

Interval          The time interval (in seconds) in which the data should be uploaded periodically. The recommended minimum time interval is 10 seconds and the maximum time interval is 30 minutes.

Parallel Writer   Specifies the number of simultaneous JSON exports done.

Export Retries    The number of times the application tries to export the entries to Cloud Tool. The recommended minimum value is 4 and the maximum is 10.

Maximum Entries   The number of JSON entries in a file. The maximum number of allowed entries is 5000 and the minimum is 10, however 1000 is the default value.

Labels             Click Add. Enter the following details:

			o	Enter the Key .
			o	Enter the Value.


4. Click Deploy to deploy the monitoring session. The Select nodes to deploy the Monitoring Session dialog box appears. Select the GigaVUE V Series Node for which you wish to deploy the monitoring session.
5. After selecting the V Series Node, select the interfaces for the REPs deployed in the monitoring session from the drop-down menu. Then, click Deploy.

## Logs Reference

### ami

This is the `ami` dataset.

#### Example

An example event for `ami` looks as following:

```json
{
    "@timestamp": "2023-05-16T15:25:25.000Z",
    "agent": {
        "ephemeral_id": "e9655c22-84f2-4b27-a24b-2b4f8538a2fb",
        "id": "0eb83218-5f40-45bd-8fb3-9423008f7b6f",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.14.3"
    },
    "data_stream": {
        "dataset": "gigamon.ami",
        "namespace": "89903",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "0eb83218-5f40-45bd-8fb3-9423008f7b6f",
        "snapshot": false,
        "version": "8.14.3"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "gigamon.ami",
        "ingested": "2024-07-26T08:18:53Z",
        "original": "{\"app_id\":\"32\",\"app_name\":\"dns\",\"device_inbound_interface\":\"0\",\"dns_class\":\"1\",\"dns_flags\":\"0\",\"dns_host\":\"pnstrex-83816.local\",\"dns_host_addr\":\"10.114.82.101\",\"dns_host_class\":\"1\",\"dns_host_raw\":\"706e73747265782d38333831362e6c6f63616c\",\"dns_host_type\":\"PTR\",\"dns_name\":\"a.b.2.b.9.6.c.2.3.9.3.d.6.2.6.a.0.8.0.2.1.0.0.0.0.0.0.0.b.a.c.f. i:p6.arpa\",\"dns_opcode\":\"0\",\"dns_qdcount\":\"4\",\"dns_query\":\"f.7.5.2.e.7.6.2.4.c.1.c.4.c.6.1.0.8.0.2.1.0.0.0.0.0.0.0.b.a.c.f. ip6.arpa\",\"dns_query_type\":\"255\",\"dns_transaction_id\":\"0\",\"dns_ttl\":\"120\",\"dst_bytes\":\"0\",\"dst_ip\":\"224.0.0.251\",\"dst_mac\":\"01:00:5e:00:00:fb\",\"dst_packets\":\"0\",\"dst_port\":\"5353\",\"egress_intf_id\":\"0\",\"end_reason\":\"1\",\"end_time\":\"2023:12:13 15:25:11.181\",\"generator\":\"gs_apps_appInst16_423722da-33ec-1556-b24b-cda2e74a53f6\",\"id\":\"679408454713072647\",\"intf_name\":\"0\",\"ip_version\":\"4\",\"protocol\":\"17\",\"seq_num\":\"656\",\"src_bytes\":\"337\",\"src_ip\":\"10.114.82.101\",\"src_mac\":\"00:50:56:8d:89:41\",\"src_packets\":\"1\",\"src_port\":\"5353\",\"start_time\":\"2023:12:13 15:25:11.181\",\"sys_up_time_first\":\"3497355275\",\"sys_up_time_last\":\"3497355275\",\"ts\":\"Thu May 16 15:25:25 2023\",\"vendor\":\"Gigamon\",\"version\":\"6.5.00\"}"
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
            "dns_name": "a.b.2.b.9.6.c.2.3.9.3.d.6.2.6.a.0.8.0.2.1.0.0.0.0.0.0.0.b.a.c.f. i:p6.arpa",
            "dns_opcode": "0",
            "dns_qdcount": 4,
            "dns_query": "f.7.5.2.e.7.6.2.4.c.1.c.4.c.6.1.0.8.0.2.1.0.0.0.0.0.0.0.b.a.c.f. ip6.arpa",
            "dns_query_type": "255",
            "dns_transaction_id": 0,
            "dns_ttl": 120,
            "dst_bytes": 0,
            "dst_ip": "224.0.0.251",
            "dst_mac": "01:00:5e:00:00:fb",
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
            "src_ip": "10.114.82.101",
            "src_mac": "00:50:56:8d:89:41",
            "src_packets": 1,
            "src_port": 5353,
            "start_time": "2023-12-13T15:25:11.181Z",
            "sys_up_time_first": 3497355275,
            "sys_up_time_last": 3497355275,
            "ts": "2023-05-16T15:25:25.000Z",
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

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| gigamon.ami.app_id |  | long |
| gigamon.ami.app_name |  | keyword |
| gigamon.ami.device_inbound_interface |  | keyword |
| gigamon.ami.dns_ancount |  | long |
| gigamon.ami.dns_arcount |  | long |
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
| gigamon.ami.dns_reverse_addr |  | ip |
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


