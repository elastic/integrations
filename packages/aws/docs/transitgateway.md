# transitgateway

## Metrics

An example event for `transitgateway` looks as following:

```json
{
    "@timestamp": "2020-05-28T20:10:20.953Z",
    "cloud": {
        "provider": "aws",
        "region": "us-west-2",
        "account": {
            "name": "elastic-beats",
            "id": "428152502467"
        }
    },
    "aws": {
        "transitgateway": {
            "metrics": {
                "PacketsIn": {
                    "sum": 0
                },
                "BytesIn": {
                    "sum": 0
                },
                "BytesOut": {
                    "sum": 0
                },
                "PacketsOut": {
                    "sum": 0
                },
                "PacketDropCountBlackhole": {
                    "sum": 0
                },
                "PacketDropCountNoRoute": {
                    "sum": 0
                }
            }
        },
        "cloudwatch": {
            "namespace": "AWS/TransitGateway"
        },
        "dimensions": {
            "TransitGateway": "tgw-0630672a32f12808a"
        }
    },
    "ecs": {
        "version": "1.5.0"
    },
    "agent": {
        "id": "12f376ef-5186-4e8b-a175-70f1140a8f30",
        "name": "MacBook-Elastic.local",
        "type": "metricbeat",
        "version": "8.0.0",
        "ephemeral_id": "17803f33-b617-4ce9-a9ac-e218c02aeb4b"
    },
    "event": {
        "dataset": "aws.transitgateway",
        "module": "aws",
        "duration": 12762825681
    },
    "metricset": {
        "period": 60000,
        "name": "transitgateway"
    },
    "service": {
        "type": "aws"
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
| aws.dimensions.TransitGateway | Filters the metric data by transit gateway. | keyword |
| aws.dimensions.TransitGatewayAttachment | Filters the metric data by transit gateway attachment. | keyword |
| aws.s3.bucket.name | Name of a S3 bucket. | keyword |
| aws.tags.\* | Tag key value pairs from aws resources. | object |
| aws.transitgateway.metrics.BytesIn.sum | The number of bytes received by the transit gateway. | long |
| aws.transitgateway.metrics.BytesOut.sum | The number of bytes sent from the transit gateway. | long |
| aws.transitgateway.metrics.PacketDropCountBlackhole.sum | The number of packets dropped because they matched a blackhole route. | long |
| aws.transitgateway.metrics.PacketDropCountNoRoute.sum | The number of packets dropped because they did not match a route. | long |
| aws.transitgateway.metrics.PacketsIn.sum | The number of packets received by the transit gateway. | long |
| aws.transitgateway.metrics.PacketsOut.sum | The number of packets sent by the transit gateway. | long |
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
| service.type | Service type | keyword |

