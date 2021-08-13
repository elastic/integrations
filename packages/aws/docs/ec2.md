# ec2

## Logs

The `ec2` dataset is specifically for EC2 logs stored in AWS CloudWatch. Export logs
from log groups to Amazon S3 bucket which has SQS notification setup already.
With this dataset, EC2 logs will be parsed into fields like  `ip_address`
and `process.name`. For logs from other services, please use `cloudwatch` dataset.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.ec2.ip_address | The internet address of the requester. | keyword |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | text |
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
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | text |
| process.name | Process name. | keyword |
| tags | List of keywords used to tag each event. | keyword |


## Metrics

An example event for `ec2` looks as following:

```json
{
    "@timestamp": "2020-05-28T17:56:37.255Z",
    "aws": {
        "ec2": {
            "network": {
                "in": {
                    "packets": 448.4,
                    "bytes_per_sec": 103.10266666666666,
                    "packets_per_sec": 1.4946666666666666,
                    "bytes": 30930.8
                },
                "out": {
                    "packets": 233.6,
                    "bytes_per_sec": 51.754666666666665,
                    "packets_per_sec": 0.7786666666666666,
                    "bytes": 15526.4
                }
            },
            "status": {
                "check_failed": 0,
                "check_failed_instance": 0,
                "check_failed_system": 0
            },
            "cpu": {
                "credit_usage": 0.004566,
                "credit_balance": 144,
                "surplus_credit_balance": 0,
                "surplus_credits_charged": 0,
                "total": {
                    "pct": 0.0999999999997574
                }
            },
            "diskio": {
                "read": {
                    "bytes_per_sec": 0,
                    "count_per_sec": 0,
                    "bytes": 0,
                    "count": 0
                },
                "write": {
                    "count": 0,
                    "bytes_per_sec": 0,
                    "count_per_sec": 0,
                    "bytes": 0
                }
            },
            "instance": {
                "core": {
                    "count": 1
                },
                "threads_per_core": 1,
                "public": {
                    "ip": "3.122.204.80",
                    "dns_name": ""
                },
                "private": {
                    "ip": "10.0.0.122",
                    "dns_name": "ip-10-0-0-122.eu-central-1.compute.internal"
                },
                "image": {
                    "id": "ami-0b418580298265d5c"
                },
                "state": {
                    "name": "running",
                    "code": 16
                },
                "monitoring": {
                    "state": "disabled"
                }
            }
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
    "event": {
        "module": "aws",
        "duration": 23217499283,
        "dataset": "aws.ec2_metrics"
    },
    "metricset": {
        "period": 300000,
        "name": "ec2"
    },
    "service": {
        "type": "aws"
    },
    "cloud": {
        "provider": "aws",
        "region": "eu-central-1",
        "account": {
            "name": "elastic-beats",
            "id": "428152502467"
        },
        "instance": {
            "id": "i-04c1a32c2aace6b40"
        },
        "machine": {
            "type": "t2.micro"
        },
        "availability_zone": "eu-central-1a"
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
| aws.dimensions.AutoScalingGroupName | An Auto Scaling group is a collection of instances you define if you're using Auto Scaling. | keyword |
| aws.dimensions.ImageId | This dimension filters the data you request for all instances running this Amazon EC2 Amazon Machine Image (AMI) | keyword |
| aws.dimensions.InstanceId | Amazon EC2 instance ID | keyword |
| aws.dimensions.InstanceType | This dimension filters the data you request for all instances running with this specified instance type. | keyword |
| aws.ec2.cpu.credit_balance | The number of earned CPU credits that an instance has accrued since it was launched or started. | long |
| aws.ec2.cpu.credit_usage | The number of CPU credits spent by the instance for CPU utilization. | long |
| aws.ec2.cpu.surplus_credit_balance | The number of surplus credits that have been spent by an unlimited instance when its CPUCreditBalance value is zero. | long |
| aws.ec2.cpu.surplus_credits_charged | The number of spent surplus credits that are not paid down by earned CPU credits, and which thus incur an additional charge. | long |
| aws.ec2.cpu.total.pct | The percentage of allocated EC2 compute units that are currently in use on the instance. | scaled_float |
| aws.ec2.diskio.read.bytes | Bytes read from all instance store volumes available to the instance. | long |
| aws.ec2.diskio.read.bytes_per_sec | Bytes read per second from all instance store volumes available to the instance. | long |
| aws.ec2.diskio.read.count | Completed read operations from all instance store volumes available to the instance in a specified period of time. | long |
| aws.ec2.diskio.read.count_per_sec | Completed read operations per second from all instance store volumes available to the instance in a specified period of time. | long |
| aws.ec2.diskio.write.bytes | Bytes written to all instance store volumes available to the instance. | long |
| aws.ec2.diskio.write.bytes_per_sec | Bytes written per second to all instance store volumes available to the instance. | long |
| aws.ec2.diskio.write.count | Completed write operations to all instance store volumes available to the instance in a specified period of time. | long |
| aws.ec2.diskio.write.count_per_sec | Completed write operations per second to all instance store volumes available to the instance in a specified period of time. | long |
| aws.ec2.instance.core.count | The number of CPU cores for the instance. | integer |
| aws.ec2.instance.image.id | The ID of the image used to launch the instance. | keyword |
| aws.ec2.instance.monitoring.state | Indicates whether detailed monitoring is enabled. | keyword |
| aws.ec2.instance.private.dns_name | The private DNS name of the network interface. | keyword |
| aws.ec2.instance.private.ip | The private IPv4 address associated with the network interface. | ip |
| aws.ec2.instance.public.dns_name | The public DNS name of the instance. | keyword |
| aws.ec2.instance.public.ip | The address of the Elastic IP address (IPv4) bound to the network interface. | ip |
| aws.ec2.instance.state.code | The state of the instance, as a 16-bit unsigned integer. | integer |
| aws.ec2.instance.state.name | The state of the instance (pending | running | shutting-down | terminated | stopping | stopped). | keyword |
| aws.ec2.instance.threads_per_core | The number of threads per CPU core. | integer |
| aws.ec2.network.in.bytes | The number of bytes received on all network interfaces by the instance. | long |
| aws.ec2.network.in.bytes_per_sec | The number of bytes per second received on all network interfaces by the instance. | long |
| aws.ec2.network.in.packets | The number of packets received on all network interfaces by the instance. | long |
| aws.ec2.network.in.packets_per_sec | The number of packets per second sent out on all network interfaces by the instance. | long |
| aws.ec2.network.out.bytes | The number of bytes sent out on all network interfaces by the instance. | long |
| aws.ec2.network.out.bytes_per_sec | The number of bytes per second sent out on all network interfaces by the instance. | long |
| aws.ec2.network.out.packets | The number of packets sent out on all network interfaces by the instance. | long |
| aws.ec2.network.out.packets_per_sec | The number of packets per second sent out on all network interfaces by the instance. | long |
| aws.ec2.status.check_failed | Reports whether the instance has passed both the instance status check and the system status check in the last minute. | long |
| aws.ec2.status.check_failed_instance | Reports whether the instance has passed the instance status check in the last minute. | long |
| aws.ec2.status.check_failed_system | Reports whether the instance has passed the system status check in the last minute. | long |
| aws.s3.bucket.name | Name of a S3 bucket. | keyword |
| aws.tags.\* | Tag key value pairs from aws resources. | object |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.account.name | The cloud account name or alias used to identify different entities in a multi-tenant environment. Examples: AWS account name, Google Cloud ORG display name. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. | keyword |
| error.message | Error message. | text |
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
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| service.type | Service type | keyword |
