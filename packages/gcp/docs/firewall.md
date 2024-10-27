# Firewall

## Logs

The `firewall` dataset collects logs from Firewall Rules in your Virtual Private Cloud (VPC) networks.

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
| gcp.destination.instance.project_id | ID of the project containing the VM. | keyword |
| gcp.destination.instance.region | Region of the VM. | keyword |
| gcp.destination.instance.zone | Zone of the VM. | keyword |
| gcp.destination.vpc.project_id | ID of the project containing the VM. | keyword |
| gcp.destination.vpc.subnetwork_name | Subnetwork on which the VM is operating. | keyword |
| gcp.destination.vpc.vpc_name | VPC on which the VM is operating. | keyword |
| gcp.firewall.flattened | Contains the full firewall document as sent by GCP. | flattened |
| gcp.firewall.rule_details.action | Action that the rule performs on match. | keyword |
| gcp.firewall.rule_details.destination_range | List of destination ranges that the firewall applies to. | keyword |
| gcp.firewall.rule_details.direction | Direction of traffic that matches this rule. | keyword |
| gcp.firewall.rule_details.ip_port_info | List of ip protocols and applicable port ranges for rules. | nested |
| gcp.firewall.rule_details.priority | The priority for the firewall rule. | long |
| gcp.firewall.rule_details.reference | Reference to the firewall rule. | keyword |
| gcp.firewall.rule_details.source_range | List of source ranges that the firewall rule applies to. | keyword |
| gcp.firewall.rule_details.source_service_account | List of all the source service accounts that the firewall rule applies to. | keyword |
| gcp.firewall.rule_details.source_tag | List of all the source tags that the firewall rule applies to. | keyword |
| gcp.firewall.rule_details.target_service_account | List of all the target service accounts that the firewall rule applies to. | keyword |
| gcp.firewall.rule_details.target_tag | List of all the target tags that the firewall rule applies to. | keyword |
| gcp.source.instance.project_id | ID of the project containing the VM. | keyword |
| gcp.source.instance.region | Region of the VM. | keyword |
| gcp.source.instance.zone | Zone of the VM. | keyword |
| gcp.source.vpc.project_id | ID of the project containing the VM. | keyword |
| gcp.source.vpc.subnetwork_name | Subnetwork on which the VM is operating. | keyword |
| gcp.source.vpc.vpc_name | VPC on which the VM is operating. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |


An example event for `firewall` looks as following:

```json
{
    "@timestamp": "2019-10-30T13:52:42.191Z",
    "agent": {
        "ephemeral_id": "175ae0b3-355c-4ca7-87ea-d5f1ee34102e",
        "id": "c6b95057-2f5d-4b8f-b4b5-37cbdb995dec",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.7.1"
    },
    "cloud": {
        "availability_zone": "us-east1-b",
        "project": {
            "id": "test-beats"
        },
        "provider": "gcp",
        "region": "us-east1"
    },
    "data_stream": {
        "dataset": "gcp.firewall",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "address": "10.42.0.2",
        "domain": "test-windows",
        "ip": "10.42.0.2",
        "port": 3389
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
        "action": "firewall-rule",
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "created": "2023-10-25T04:20:37.182Z",
        "dataset": "gcp.firewall",
        "id": "1f21ciqfpfssuo",
        "ingested": "2023-10-25T04:20:41Z",
        "kind": "event",
        "type": [
            "allowed",
            "connection"
        ]
    },
    "gcp": {
        "destination": {
            "instance": {
                "project_id": "test-beats",
                "region": "us-east1",
                "zone": "us-east1-b"
            },
            "vpc": {
                "project_id": "test-beats",
                "subnetwork_name": "windows-isolated",
                "vpc_name": "windows-isolated"
            }
        },
        "firewall": {
            "rule_details": {
                "action": "ALLOW",
                "direction": "INGRESS",
                "ip_port_info": [
                    {
                        "ip_protocol": "TCP",
                        "port_range": [
                            "3389"
                        ]
                    }
                ],
                "priority": 1000,
                "source_range": [
                    "0.0.0.0/0"
                ],
                "target_tag": [
                    "allow-rdp"
                ]
            }
        }
    },
    "input": {
        "type": "gcp-pubsub"
    },
    "log": {
        "logger": "projects/test-beats/logs/compute.googleapis.com%2Ffirewall"
    },
    "network": {
        "community_id": "1:OdLB9eXsBDLz8m97ao4LepX6q+4=",
        "direction": "inbound",
        "iana_number": "6",
        "name": "windows-isolated",
        "transport": "tcp",
        "type": "ipv4"
    },
    "related": {
        "ip": [
            "192.168.2.126",
            "10.42.0.2"
        ]
    },
    "rule": {
        "name": "network:windows-isolated/firewall:windows-isolated-allow-rdp"
    },
    "source": {
        "address": "192.168.2.126",
        "geo": {
            "continent_name": "Asia",
            "country_name": "omn"
        },
        "ip": "192.168.2.126",
        "port": 64853
    },
    "tags": [
        "forwarded",
        "gcp-firewall"
    ]
}
```