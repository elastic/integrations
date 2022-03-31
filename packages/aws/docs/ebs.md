# ebs

## Metrics

An example event for `ebs` looks as following:

```json
{
    "@timestamp": "2020-05-28T17:57:22.450Z",
    "service": {
        "type": "aws"
    },
    "aws": {
        "ebs": {
            "metrics": {
                "VolumeReadOps": {
                    "avg": 0
                },
                "VolumeQueueLength": {
                    "avg": 0.0000666666666666667
                },
                "VolumeWriteOps": {
                    "avg": 29
                },
                "VolumeTotalWriteTime": {
                    "sum": 0.02
                },
                "BurstBalance": {
                    "avg": 100
                },
                "VolumeWriteBytes": {
                    "avg": 14406.620689655172
                },
                "VolumeIdleTime": {
                    "sum": 299.98
                }
            }
        },
        "cloudwatch": {
            "namespace": "AWS/EBS"
        },
        "dimensions": {
            "VolumeId": "vol-03370a204cc8b0a2f"
        }
    },
    "agent": {
        "name": "MacBook-Elastic.local",
        "type": "metricbeat",
        "version": "8.0.0",
        "ephemeral_id": "17803f33-b617-4ce9-a9ac-e218c02aeb4b",
        "id": "12f376ef-5186-4e8b-a175-70f1140a8f30"
    },
    "ecs": {
        "version": "1.5.0"
    },
    "cloud": {
        "provider": "aws",
        "region": "eu-central-1",
        "account": {
            "id": "428152502467",
            "name": "elastic-beats"
        }
    },
    "event": {
        "dataset": "aws.ebs",
        "module": "aws",
        "duration": 10488314037
    },
    "metricset": {
        "period": 300000,
        "name": "ebs"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.\*.metrics.\*.\* | Metrics that returned from Cloudwatch API query. | object |
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
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
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
