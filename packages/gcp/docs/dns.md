# DNS

## Logs

The `dns` dataset collects queries that name servers resolve for your Virtual Private Cloud (VPC) networks, as well as queries from an external entity directly to a public zone.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

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
| gcp.dns.auth_answer | Authoritative answer. | boolean |
| gcp.dns.destination_ip | Destination IP address, only applicable for forwarding cases. | ip |
| gcp.dns.egress_error | Egress proxy error. | keyword |
| gcp.dns.flattened | Contains the full dns document as sent by GCP. | flattened |
| gcp.dns.protocol | Protocol TCP or UDP. | keyword |
| gcp.dns.query_name | DNS query name. | keyword |
| gcp.dns.query_type | DNS query type. | keyword |
| gcp.dns.rdata | DNS answer in presentation format, truncated to 260 bytes. | keyword |
| gcp.dns.response_code | Response code. | keyword |
| gcp.dns.server_latency | Server latency. | integer |
| gcp.dns.source_ip | Source IP address of the query. | ip |
| gcp.dns.source_network | Source network of the query. | keyword |
| gcp.dns.source_type | Type of source generating the DNS query: private-zone, public-zone, forwarding-zone, forwarding-policy, peering-zone, internal, external, internet | keyword |
| gcp.dns.target_type | Type of target resolving the DNS query: private-zone, public-zone, forwarding-zone, forwarding-policy, peering-zone, internal, external, internet | keyword |
| gcp.dns.vm_instance_id | Compute Engine VM instance ID, only applicable to queries initiated by Compute Engine VMs. | keyword |
| gcp.dns.vm_instance_name | Compute Engine VM instance name, only applicable to queries initiated by Compute Engine VMs. | keyword |
| gcp.dns.vm_project_id | Google Cloud project ID, only applicable to queries initiated by Compute Engine VMs. | keyword |
| gcp.dns.vm_zone_name | Google Cloud VM zone, only applicable to queries initiated by Compute Engine VMs. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |


An example event for `dns` looks as following:

```json
{
    "@timestamp": "2021-12-12T15:59:40.446Z",
    "agent": {
        "ephemeral_id": "fd6c4189-cbc6-493a-acfb-c9e7b2b7588c",
        "id": "c6b95057-2f5d-4b8f-b4b5-37cbdb995dec",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.7.1"
    },
    "cloud": {
        "project": {
            "id": "key-reference-123456"
        },
        "provider": "gcp",
        "region": "global"
    },
    "data_stream": {
        "dataset": "gcp.dns",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "address": "216.239.32.106",
        "ip": "216.239.32.106"
    },
    "dns": {
        "answers": [
            {
                "class": "IN",
                "data": "67.43.156.13",
                "name": "asdf.gcp.example.com.",
                "ttl": 300,
                "type": "A"
            }
        ],
        "question": {
            "name": "asdf.gcp.example.com",
            "registered_domain": "example.com",
            "subdomain": "asdf.gcp",
            "top_level_domain": "com",
            "type": "A"
        },
        "resolved_ip": [
            "67.43.156.13"
        ],
        "response_code": "NOERROR"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "c6b95057-2f5d-4b8f-b4b5-37cbdb995dec",
        "snapshot": false,
        "version": "8.7.1"
    },
    "event": {
        "action": "dns-query",
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "created": "2023-10-25T04:19:40.300Z",
        "dataset": "gcp.dns",
        "id": "zir4wud11tm",
        "ingested": "2023-10-25T04:19:41Z",
        "kind": "event",
        "outcome": "success"
    },
    "gcp": {
        "dns": {
            "auth_answer": true,
            "destination_ip": "216.239.32.106",
            "protocol": "UDP",
            "query_name": "asdf.gcp.example.com.",
            "query_type": "A",
            "response_code": "NOERROR",
            "server_latency": 0,
            "source_type": "internet",
            "target_type": "public-zone"
        }
    },
    "input": {
        "type": "gcp-pubsub"
    },
    "log": {
        "level": "INFO",
        "logger": "projects/key-reference-123456/logs/dns.googleapis.com%2Fdns_queries"
    },
    "network": {
        "iana_number": "17",
        "protocol": "dns",
        "transport": "udp"
    },
    "related": {
        "hosts": [
            "asdf.gcp.example.com"
        ],
        "ip": [
            "67.43.156.13",
            "216.239.32.106"
        ]
    },
    "tags": [
        "forwarded",
        "gcp-dns"
    ]
}
```