# ecs

## Metrics

An example event for `ecs` looks as following:

```json
{
    "agent": {
        "name": "4b4f1fd6f3ff",
        "id": "8c424f1d-e9b1-4aab-8ce5-77dceb4becfb",
        "type": "metricbeat",
        "ephemeral_id": "0c23896b-0bfe-469f-bf76-7203a2d52568",
        "version": "8.1.0"
    },
    "elastic_agent": {
        "id": "8c424f1d-e9b1-4aab-8ce5-77dceb4becfb",
        "version": "8.1.0",
        "snapshot": false
    },
    "cloud": {
        "provider": "aws",
        "region": "eu-west-1",
        "account": {
            "name": "elastic-observability",
            "id": "627286350134"
        }
    },
    "@timestamp": "2022-07-26T08:59:00.000Z",
    "ecs": {
        "version": "8.0.0"
    },
    "service": {
        "type": "aws"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "aws.ecs_metrics"
    },
    "host": {
        "hostname": "4b4f1fd6f3ff",
        "os": {
            "kernel": "5.10.104-linuxkit",
            "codename": "focal",
            "name": "Ubuntu",
            "family": "debian",
            "type": "linux",
            "version": "20.04.3 LTS (Focal Fossa)",
            "platform": "ubuntu"
        },
        "containerized": false,
        "ip": [
            "172.19.0.4"
        ],
        "name": "4b4f1fd6f3ff",
        "mac": [
            "02:42:ac:13:00:04"
        ],
        "architecture": "aarch64"
    },
    "metricset": {
        "period": 300000,
        "name": "cloudwatch"
    },
    "aws": {
        "ecs": {
            "metrics": {
                "CPUUtilization": {
                    "avg": 100.040084913373
                },
                "MemoryUtilization": {
                    "avg": 9.195963541666666
                }
            }
        },
        "cloudwatch": {
            "namespace": "AWS/ECS"
        },
        "dimensions": {
            "ServiceName": "integration-service-1",
            "ClusterName": "integration-cluster-1"
        }
    },
    "event": {
        "duration": 1862196584,
        "agent_id_status": "verified",
        "ingested": "2022-07-26T09:04:12Z",
        "module": "aws",
        "dataset": "aws.ecs_metrics"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.cloudwatch.namespace | The namespace specified when query cloudwatch api. | keyword |
| aws.dimensions.\* | Metric dimensions. | object |
| aws.dimensions.ClusterName | This dimension filters the data that you request for all resources in a specified cluster. All Amazon ECS metrics are filtered by ClusterName. | keyword |
| aws.dimensions.ServiceName | This dimension filters the data that you request for all resources in a specified service within a specified cluster. | keyword |
| aws.ecs.metrics.CPUReservation.avg | The percentage of CPU units that are reserved by running tasks in the cluster. | double |
| aws.ecs.metrics.CPUUtilization.avg | The percentage of CPU units that are used in the cluster or service. | double |
| aws.ecs.metrics.GPUReservation.avg | The percentage of total available GPUs that are reserved by running tasks in the cluster. | double |
| aws.ecs.metrics.MemoryReservation.avg | The percentage of memory that is reserved by running tasks in the cluster. | double |
| aws.ecs.metrics.MemoryUtilization.avg | The percentage of memory that is used in the cluster or service. | double |
| aws.s3.bucket.name | Name of a S3 bucket. | keyword |
| aws.tags.\* | Tag key value pairs from aws resources. | object |
| cloud | Fields related to the cloud or infrastructure the events are coming from. | group |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.account.name | The cloud account name or alias used to identify different entities in a multi-tenant environment. Examples: AWS account name, Google Cloud ORG display name. | keyword |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host, resource, or service is located. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error | These fields can represent errors of any kind. Use them for errors that happen while fetching events or in cases where the event itself contains an error. | group |
| error.message | Error message. | match_only_text |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.cpu.pct | Percent CPU used. This value is normalized by the number of CPU cores and it ranges from 0 to 1. | scaled_float |
| host.disk.read.bytes | The total number of bytes read successfully in a given period of time. | long |
| host.disk.write.bytes | The total number of bytes write successfully in a given period of time. | long |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.network.in.bytes | The number of bytes received on all network interfaces by the host in a given period of time. | long |
| host.network.in.packets | The number of packets received on all network interfaces by the host in a given period of time. | long |
| host.network.out.bytes | The number of bytes sent out on all network interfaces by the host in a given period of time. | long |
| host.network.out.packets | The number of packets sent out on all network interfaces by the host in a given period of time. | long |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
