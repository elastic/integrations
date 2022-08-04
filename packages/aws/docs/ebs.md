# ebs

## Metrics

An example event for `ebs` looks as following:

```json
{
    "agent": {
        "name": "docker-fleet-agent",
        "id": "618e6f72-9eef-4992-b60e-12515d538189",
        "ephemeral_id": "2e8fed31-76b5-4efe-9893-947fd2346abd",
        "type": "metricbeat",
        "version": "8.2.0"
    },
    "elastic_agent": {
        "id": "618e6f72-9eef-4992-b60e-12515d538189",
        "version": "8.2.0",
        "snapshot": false
    },
    "cloud": {
        "provider": "aws",
        "region": "us-east-2"
    },
    "@timestamp": "2022-08-03T12:21:00.000Z",
    "ecs": {
        "version": "8.0.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "aws.ebs"
    },
    "service": {
        "type": "aws"
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "5.18.11-200.fc36.x86_64",
            "codename": "focal",
            "name": "Ubuntu",
            "type": "linux",
            "family": "debian",
            "version": "20.04.4 LTS (Focal Fossa)",
            "platform": "ubuntu"
        },
        "containerized": false,
        "ip": [
            "172.18.0.7"
        ],
        "name": "docker-fleet-agent",
        "mac": [
            "02:42:ac:12:00:07"
        ],
        "architecture": "x86_64"
    },
    "metricset": {
        "period": 300000,
        "name": "cloudwatch"
    },
    "aws": {
        "ebs": {
            "metrics": {
                "VolumeQueueLength": {
                    "avg": 0
                },
                "BurstBalance": {
                    "avg": 100
                },
                "VolumeTotalWriteTime": {
                    "sum": 0.062
                },
                "VolumeWriteBytes": {
                    "avg": 5643.130434782609
                },
                "VolumeWriteOps": {
                    "avg": 23
                },
                "VolumeReadOps": {
                    "avg": 0
                },
                "VolumeIdleTime": {
                    "sum": 239.87
                }
            }
        },
        "cloudwatch": {
            "namespace": "AWS/EBS"
        },
        "dimensions": {
            "VolumeId": "vol-015d88f45122510a5"
        }
    },
    "event": {
        "duration": 1320126957,
        "agent_id_status": "verified",
        "ingested": "2022-08-03T12:25:46Z",
        "module": "aws",
        "dataset": "aws.ebs"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.cloudwatch.namespace | The namespace specified when query cloudwatch api. | keyword |
| aws.dimensions.\* | Metric dimensions. | object |
| aws.dimensions.VolumeId | Amazon EBS volume ID | keyword |
| aws.ebs.metrics.BurstBalance.avg | Used with General Purpose SSD (gp2), Throughput Optimized HDD (st1), and Cold HDD (sc1) volumes only. Provides information about the percentage of I/O credits (for gp2) or throughput credits (for st1 and sc1) remaining in the burst bucket. | double |
| aws.ebs.metrics.VolumeConsumedReadWriteOps.avg | The total amount of read and write operations (normalized to 256K capacity units) consumed in a specified period of time. Used with Provisioned IOPS SSD volumes only. | double |
| aws.ebs.metrics.VolumeIdleTime.sum | The total number of seconds in a specified period of time when no read or write operations were submitted. | double |
| aws.ebs.metrics.VolumeQueueLength.avg | The number of read and write operation requests waiting to be completed in a specified period of time. | double |
| aws.ebs.metrics.VolumeReadBytes.avg | Average size of each read operation during the period, except on volumes attached to a Nitro-based instance, where the average represents the average over the specified period. | double |
| aws.ebs.metrics.VolumeReadOps.avg | The total number of read operations in a specified period of time. | double |
| aws.ebs.metrics.VolumeThroughputPercentage.avg | The percentage of I/O operations per second (IOPS) delivered of the total IOPS provisioned for an Amazon EBS volume. Used with Provisioned IOPS SSD volumes only. | double |
| aws.ebs.metrics.VolumeTotalReadTime.sum | The total number of seconds spent by all read operations that completed in a specified period of time. | double |
| aws.ebs.metrics.VolumeTotalWriteTime.sum | The total number of seconds spent by all write operations that completed in a specified period of time. | double |
| aws.ebs.metrics.VolumeWriteBytes.avg | Average size of each write operation during the period, except on volumes attached to a Nitro-based instance, where the average represents the average over the specified period. | double |
| aws.ebs.metrics.VolumeWriteOps.avg | The total number of write operations in a specified period of time. | double |
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
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
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
