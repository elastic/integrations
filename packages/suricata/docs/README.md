# Suricata Integration

This integration is for [Suricata](https://suricata-ids.org/). It reads the EVE
JSON output file. The EVE output writes alerts, anomalies, metadata, file info
and protocol specific records as JSON.

## Compatibility

This module has been developed against Suricata v4.0.4, but is expected to work
with other versions of Suricata.

## EVE

An example event for `eve` looks as following:

```json
{
    "@timestamp": "2018-07-05T19:01:09.820Z",
    "agent": {
        "ephemeral_id": "58adcb6e-5d0e-4822-98a4-8d93557f8f2e",
        "id": "0a5c1566-c6fd-4e91-b96d-4083445a000e",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.9.0"
    },
    "data_stream": {
        "dataset": "suricata.eve",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "address": "192.168.253.112",
        "ip": "192.168.253.112",
        "port": 22
    },
    "ecs": {
        "version": "8.9.0"
    },
    "elastic_agent": {
        "id": "0a5c1566-c6fd-4e91-b96d-4083445a000e",
        "snapshot": false,
        "version": "8.9.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "created": "2023-08-08T15:09:13.171Z",
        "dataset": "suricata.eve",
        "ingested": "2023-08-08T15:09:14Z",
        "kind": "event",
        "type": [
            "protocol"
        ]
    },
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/eve-small.ndjson"
        },
        "offset": 0
    },
    "network": {
        "community_id": "1:NLm1MbaBR6humQxEQI2Ai7h/XiI=",
        "protocol": "ssh",
        "transport": "tcp"
    },
    "related": {
        "ip": [
            "192.168.86.85",
            "192.168.253.112"
        ]
    },
    "source": {
        "address": "192.168.86.85",
        "ip": "192.168.86.85",
        "port": 55406
    },
    "suricata": {
        "eve": {
            "event_type": "ssh",
            "flow_id": "298824096901438",
            "in_iface": "en0",
            "ssh": {
                "client": {
                    "proto_version": "2.0",
                    "software_version": "OpenSSH_7.6"
                },
                "server": {
                    "proto_version": "2.0",
                    "software_version": "libssh_0.7.0"
                }
            }
        }
    },
    "tags": [
        "forwarded",
        "suricata-eve"
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
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| suricata.eve.alert.affected_product |  | keyword |
| suricata.eve.alert.attack_target |  | keyword |
| suricata.eve.alert.capec_id |  | keyword |
| suricata.eve.alert.category |  | keyword |
| suricata.eve.alert.classtype |  | keyword |
| suricata.eve.alert.created_at |  | date |
| suricata.eve.alert.cve |  | keyword |
| suricata.eve.alert.cvss_v2_base |  | keyword |
| suricata.eve.alert.cvss_v2_temporal |  | keyword |
| suricata.eve.alert.cvss_v3_base |  | keyword |
| suricata.eve.alert.cvss_v3_temporal |  | keyword |
| suricata.eve.alert.cwe_id |  | keyword |
| suricata.eve.alert.deployment |  | keyword |
| suricata.eve.alert.former_category |  | keyword |
| suricata.eve.alert.gid |  | long |
| suricata.eve.alert.hostile |  | keyword |
| suricata.eve.alert.infected |  | keyword |
| suricata.eve.alert.malware |  | keyword |
| suricata.eve.alert.metadata |  | flattened |
| suricata.eve.alert.mitre_tool_id |  | keyword |
| suricata.eve.alert.performance_impact |  | keyword |
| suricata.eve.alert.priority |  | keyword |
| suricata.eve.alert.protocols |  | keyword |
| suricata.eve.alert.rev |  | long |
| suricata.eve.alert.rule_source |  | keyword |
| suricata.eve.alert.sid |  | keyword |
| suricata.eve.alert.signature |  | keyword |
| suricata.eve.alert.signature_id |  | long |
| suricata.eve.alert.signature_severity |  | keyword |
| suricata.eve.alert.tag |  | keyword |
| suricata.eve.alert.updated_at |  | date |
| suricata.eve.app_proto_expected |  | keyword |
| suricata.eve.app_proto_orig |  | keyword |
| suricata.eve.app_proto_tc |  | keyword |
| suricata.eve.app_proto_ts |  | keyword |
| suricata.eve.dns.id |  | long |
| suricata.eve.dns.rcode |  | keyword |
| suricata.eve.dns.rdata |  | keyword |
| suricata.eve.dns.rrname |  | keyword |
| suricata.eve.dns.rrtype |  | keyword |
| suricata.eve.dns.ttl |  | long |
| suricata.eve.dns.tx_id |  | long |
| suricata.eve.dns.type |  | keyword |
| suricata.eve.email.status |  | keyword |
| suricata.eve.event_type |  | keyword |
| suricata.eve.fileinfo.gaps |  | boolean |
| suricata.eve.fileinfo.md5 |  | keyword |
| suricata.eve.fileinfo.sha1 |  | keyword |
| suricata.eve.fileinfo.sha256 |  | keyword |
| suricata.eve.fileinfo.state |  | keyword |
| suricata.eve.fileinfo.stored |  | boolean |
| suricata.eve.fileinfo.tx_id |  | long |
| suricata.eve.flow.age |  | long |
| suricata.eve.flow.alerted |  | boolean |
| suricata.eve.flow.end |  | date |
| suricata.eve.flow.reason |  | keyword |
| suricata.eve.flow.state |  | keyword |
| suricata.eve.flow_id |  | keyword |
| suricata.eve.http.http_content_type |  | keyword |
| suricata.eve.http.http_port |  | long |
| suricata.eve.http.protocol |  | keyword |
| suricata.eve.http.redirect |  | keyword |
| suricata.eve.icmp_code |  | long |
| suricata.eve.icmp_type |  | long |
| suricata.eve.in_iface |  | keyword |
| suricata.eve.pcap_cnt |  | long |
| suricata.eve.smtp.helo |  | keyword |
| suricata.eve.smtp.mail_from |  | keyword |
| suricata.eve.smtp.rcpt_to |  | keyword |
| suricata.eve.ssh.client.proto_version |  | keyword |
| suricata.eve.ssh.client.software_version |  | keyword |
| suricata.eve.ssh.server.proto_version |  | keyword |
| suricata.eve.ssh.server.software_version |  | keyword |
| suricata.eve.stats.app_layer.flow.dcerpc_tcp |  | long |
| suricata.eve.stats.app_layer.flow.dcerpc_udp |  | long |
| suricata.eve.stats.app_layer.flow.dns_tcp |  | long |
| suricata.eve.stats.app_layer.flow.dns_udp |  | long |
| suricata.eve.stats.app_layer.flow.failed_tcp |  | long |
| suricata.eve.stats.app_layer.flow.failed_udp |  | long |
| suricata.eve.stats.app_layer.flow.ftp |  | long |
| suricata.eve.stats.app_layer.flow.http |  | long |
| suricata.eve.stats.app_layer.flow.imap |  | long |
| suricata.eve.stats.app_layer.flow.msn |  | long |
| suricata.eve.stats.app_layer.flow.smb |  | long |
| suricata.eve.stats.app_layer.flow.smtp |  | long |
| suricata.eve.stats.app_layer.flow.ssh |  | long |
| suricata.eve.stats.app_layer.flow.tls |  | long |
| suricata.eve.stats.app_layer.tx.dcerpc_tcp |  | long |
| suricata.eve.stats.app_layer.tx.dcerpc_udp |  | long |
| suricata.eve.stats.app_layer.tx.dns_tcp |  | long |
| suricata.eve.stats.app_layer.tx.dns_udp |  | long |
| suricata.eve.stats.app_layer.tx.ftp |  | long |
| suricata.eve.stats.app_layer.tx.http |  | long |
| suricata.eve.stats.app_layer.tx.smb |  | long |
| suricata.eve.stats.app_layer.tx.smtp |  | long |
| suricata.eve.stats.app_layer.tx.ssh |  | long |
| suricata.eve.stats.app_layer.tx.tls |  | long |
| suricata.eve.stats.capture.kernel_drops |  | long |
| suricata.eve.stats.capture.kernel_ifdrops |  | long |
| suricata.eve.stats.capture.kernel_packets |  | long |
| suricata.eve.stats.decoder.avg_pkt_size |  | long |
| suricata.eve.stats.decoder.bytes |  | long |
| suricata.eve.stats.decoder.dce.pkt_too_small |  | long |
| suricata.eve.stats.decoder.erspan |  | long |
| suricata.eve.stats.decoder.ethernet |  | long |
| suricata.eve.stats.decoder.gre |  | long |
| suricata.eve.stats.decoder.icmpv4 |  | long |
| suricata.eve.stats.decoder.icmpv6 |  | long |
| suricata.eve.stats.decoder.ieee8021ah |  | long |
| suricata.eve.stats.decoder.invalid |  | long |
| suricata.eve.stats.decoder.ipraw.invalid_ip_version |  | long |
| suricata.eve.stats.decoder.ipv4 |  | long |
| suricata.eve.stats.decoder.ipv4_in_ipv6 |  | long |
| suricata.eve.stats.decoder.ipv6 |  | long |
| suricata.eve.stats.decoder.ipv6_in_ipv6 |  | long |
| suricata.eve.stats.decoder.ltnull.pkt_too_small |  | long |
| suricata.eve.stats.decoder.ltnull.unsupported_type |  | long |
| suricata.eve.stats.decoder.max_pkt_size |  | long |
| suricata.eve.stats.decoder.mpls |  | long |
| suricata.eve.stats.decoder.null |  | long |
| suricata.eve.stats.decoder.pkts |  | long |
| suricata.eve.stats.decoder.ppp |  | long |
| suricata.eve.stats.decoder.pppoe |  | long |
| suricata.eve.stats.decoder.raw |  | long |
| suricata.eve.stats.decoder.sctp |  | long |
| suricata.eve.stats.decoder.sll |  | long |
| suricata.eve.stats.decoder.tcp |  | long |
| suricata.eve.stats.decoder.teredo |  | long |
| suricata.eve.stats.decoder.udp |  | long |
| suricata.eve.stats.decoder.vlan |  | long |
| suricata.eve.stats.decoder.vlan_qinq |  | long |
| suricata.eve.stats.defrag.ipv4.fragments |  | long |
| suricata.eve.stats.defrag.ipv4.reassembled |  | long |
| suricata.eve.stats.defrag.ipv4.timeouts |  | long |
| suricata.eve.stats.defrag.ipv6.fragments |  | long |
| suricata.eve.stats.defrag.ipv6.reassembled |  | long |
| suricata.eve.stats.defrag.ipv6.timeouts |  | long |
| suricata.eve.stats.defrag.max_frag_hits |  | long |
| suricata.eve.stats.detect.alert |  | long |
| suricata.eve.stats.dns.memcap_global |  | long |
| suricata.eve.stats.dns.memcap_state |  | long |
| suricata.eve.stats.dns.memuse |  | long |
| suricata.eve.stats.file_store.open_files |  | long |
| suricata.eve.stats.flow.emerg_mode_entered |  | long |
| suricata.eve.stats.flow.emerg_mode_over |  | long |
| suricata.eve.stats.flow.icmpv4 |  | long |
| suricata.eve.stats.flow.icmpv6 |  | long |
| suricata.eve.stats.flow.memcap |  | long |
| suricata.eve.stats.flow.memuse |  | long |
| suricata.eve.stats.flow.spare |  | long |
| suricata.eve.stats.flow.tcp |  | long |
| suricata.eve.stats.flow.tcp_reuse |  | long |
| suricata.eve.stats.flow.udp |  | long |
| suricata.eve.stats.flow_mgr.bypassed_pruned |  | long |
| suricata.eve.stats.flow_mgr.closed_pruned |  | long |
| suricata.eve.stats.flow_mgr.est_pruned |  | long |
| suricata.eve.stats.flow_mgr.flows_checked |  | long |
| suricata.eve.stats.flow_mgr.flows_notimeout |  | long |
| suricata.eve.stats.flow_mgr.flows_removed |  | long |
| suricata.eve.stats.flow_mgr.flows_timeout |  | long |
| suricata.eve.stats.flow_mgr.flows_timeout_inuse |  | long |
| suricata.eve.stats.flow_mgr.new_pruned |  | long |
| suricata.eve.stats.flow_mgr.rows_busy |  | long |
| suricata.eve.stats.flow_mgr.rows_checked |  | long |
| suricata.eve.stats.flow_mgr.rows_empty |  | long |
| suricata.eve.stats.flow_mgr.rows_maxlen |  | long |
| suricata.eve.stats.flow_mgr.rows_skipped |  | long |
| suricata.eve.stats.http.memcap |  | long |
| suricata.eve.stats.http.memuse |  | long |
| suricata.eve.stats.tcp.insert_data_normal_fail |  | long |
| suricata.eve.stats.tcp.insert_data_overlap_fail |  | long |
| suricata.eve.stats.tcp.insert_list_fail |  | long |
| suricata.eve.stats.tcp.invalid_checksum |  | long |
| suricata.eve.stats.tcp.memuse |  | long |
| suricata.eve.stats.tcp.no_flow |  | long |
| suricata.eve.stats.tcp.overlap |  | long |
| suricata.eve.stats.tcp.overlap_diff_data |  | long |
| suricata.eve.stats.tcp.pseudo |  | long |
| suricata.eve.stats.tcp.pseudo_failed |  | long |
| suricata.eve.stats.tcp.reassembly_gap |  | long |
| suricata.eve.stats.tcp.reassembly_memuse |  | long |
| suricata.eve.stats.tcp.rst |  | long |
| suricata.eve.stats.tcp.segment_memcap_drop |  | long |
| suricata.eve.stats.tcp.sessions |  | long |
| suricata.eve.stats.tcp.ssn_memcap_drop |  | long |
| suricata.eve.stats.tcp.stream_depth_reached |  | long |
| suricata.eve.stats.tcp.syn |  | long |
| suricata.eve.stats.tcp.synack |  | long |
| suricata.eve.stats.uptime |  | long |
| suricata.eve.tcp.ack |  | boolean |
| suricata.eve.tcp.fin |  | boolean |
| suricata.eve.tcp.psh |  | boolean |
| suricata.eve.tcp.rst |  | boolean |
| suricata.eve.tcp.state |  | keyword |
| suricata.eve.tcp.syn |  | boolean |
| suricata.eve.tcp.tcp_flags |  | keyword |
| suricata.eve.tcp.tcp_flags_tc |  | keyword |
| suricata.eve.tcp.tcp_flags_ts |  | keyword |
| suricata.eve.tls.fingerprint |  | keyword |
| suricata.eve.tls.issuerdn |  | keyword |
| suricata.eve.tls.ja3.hash |  | keyword |
| suricata.eve.tls.ja3.string |  | keyword |
| suricata.eve.tls.ja3s.hash |  | keyword |
| suricata.eve.tls.ja3s.string |  | keyword |
| suricata.eve.tls.notafter |  | date |
| suricata.eve.tls.notbefore |  | date |
| suricata.eve.tls.serial |  | keyword |
| suricata.eve.tls.session_resumed |  | boolean |
| suricata.eve.tls.sni |  | keyword |
| suricata.eve.tls.subject |  | keyword |
| suricata.eve.tls.version |  | keyword |
| suricata.eve.tx_id |  | long |
| tags | User defined tags. | keyword |

