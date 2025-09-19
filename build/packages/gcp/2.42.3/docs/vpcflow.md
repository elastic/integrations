# VPC Flow

## Logs

The `vpcflow` dataset collects logs sent from and received by VM instances, including instances used as GKE nodes.

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
| gcp.source.instance.project_id | ID of the project containing the VM. | keyword |
| gcp.source.instance.region | Region of the VM. | keyword |
| gcp.source.instance.zone | Zone of the VM. | keyword |
| gcp.source.vpc.project_id | ID of the project containing the VM. | keyword |
| gcp.source.vpc.subnetwork_name | Subnetwork on which the VM is operating. | keyword |
| gcp.source.vpc.vpc_name | VPC on which the VM is operating. | keyword |
| gcp.vpcflow.flattened | Contains the full vpcflow document as sent by GCP. | flattened |
| gcp.vpcflow.reporter | The side which reported the flow. Can be either 'SRC' or 'DEST'. | keyword |
| gcp.vpcflow.rtt.ms | Latency as measured (for TCP flows only) during the time interval. This is the time elapsed between sending a SEQ and receiving a corresponding ACK and it contains the network RTT as well as the application related delay. | long |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |


An example event for `vpcflow` looks as following:

```json
{
    "@timestamp": "2019-06-14T03:50:10.845Z",
    "agent": {
        "ephemeral_id": "0b8165a2-0e25-4e9a-bb68-271697e0993f",
        "id": "c6b95057-2f5d-4b8f-b4b5-37cbdb995dec",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.7.1"
    },
    "cloud": {
        "availability_zone": "us-east1-b",
        "instance": {
            "name": "kibana"
        },
        "project": {
            "id": "my-sample-project"
        },
        "provider": "gcp",
        "region": "us-east1"
    },
    "data_stream": {
        "dataset": "gcp.vpcflow",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "address": "10.139.99.242",
        "domain": "elasticsearch",
        "ip": "10.139.99.242",
        "port": 9200
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
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "created": "2023-10-25T04:21:42.006Z",
        "dataset": "gcp.vpcflow",
        "end": "2019-06-14T03:49:51.821056075Z",
        "id": "ut8lbrffooxz5",
        "ingested": "2023-10-25T04:21:43Z",
        "kind": "event",
        "start": "2019-06-14T03:40:20.510622432Z",
        "type": [
            "connection"
        ]
    },
    "gcp": {
        "destination": {
            "instance": {
                "project_id": "my-sample-project",
                "region": "us-east1",
                "zone": "us-east1-b"
            },
            "vpc": {
                "project_id": "my-sample-project",
                "subnetwork_name": "default",
                "vpc_name": "default"
            }
        },
        "source": {
            "instance": {
                "project_id": "my-sample-project",
                "region": "us-east1",
                "zone": "us-east1-b"
            },
            "vpc": {
                "project_id": "my-sample-project",
                "subnetwork_name": "default",
                "vpc_name": "default"
            }
        },
        "vpcflow": {
            "reporter": "DEST",
            "rtt": {
                "ms": 201
            }
        }
    },
    "input": {
        "type": "gcp-pubsub"
    },
    "log": {
        "logger": "projects/my-sample-project/logs/compute.googleapis.com%2Fvpc_flows"
    },
    "network": {
        "bytes": 11773,
        "community_id": "1:FYaJFSEAKLcBCMFoT6sR5TMHf/s=",
        "direction": "internal",
        "iana_number": "6",
        "name": "default",
        "packets": 94,
        "transport": "tcp",
        "type": "ipv4"
    },
    "related": {
        "ip": [
            "67.43.156.13",
            "10.139.99.242"
        ]
    },
    "source": {
        "address": "67.43.156.13",
        "as": {
            "number": 35908
        },
        "bytes": 11773,
        "domain": "kibana",
        "geo": {
            "continent_name": "Asia",
            "country_iso_code": "BT",
            "country_name": "Bhutan",
            "location": {
                "lat": 27.5,
                "lon": 90.5
            }
        },
        "ip": "67.43.156.13",
        "packets": 94,
        "port": 33576
    },
    "tags": [
        "forwarded",
        "gcp-vpcflow"
    ]
}
```