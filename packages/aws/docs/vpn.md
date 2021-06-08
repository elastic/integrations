# vpn

## Metrics

An example event for `vpn` looks as following:

```json
{
    "@timestamp": "2020-05-28T17:58:27.154Z",
    "service": {
        "type": "aws"
    },
    "ecs": {
        "version": "1.5.0"
    },
    "aws": {
        "vpn": {
            "metrics": {
                "TunnelState": {
                    "avg": 0
                },
                "TunnelDataIn": {
                    "sum": 0
                },
                "TunnelDataOut": {
                    "sum": 0
                }
            }
        },
        "cloudwatch": {
            "namespace": "AWS/VPN"
        }
    },
    "event": {
        "dataset": "aws.vpn",
        "module": "aws",
        "duration": 10418157072
    },
    "metricset": {
        "period": 60000,
        "name": "vpn"
    },
    "cloud": {
        "region": "us-west-2",
        "account": {
            "name": "elastic-beats",
            "id": "428152502467"
        },
        "provider": "aws"
    },
    "agent": {
        "version": "8.0.0",
        "ephemeral_id": "17803f33-b617-4ce9-a9ac-e218c02aeb4b",
        "id": "12f376ef-5186-4e8b-a175-70f1140a8f30",
        "name": "MacBook-Elastic.local",
        "type": "metricbeat"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.*.metrics.*.* | Metrics that returned from Cloudwatch API query. | object |
| aws.cloudwatch.namespace | The namespace specified when query cloudwatch api. | keyword |
| aws.dimensions.* | Metric dimensions. | object |
| aws.dimensions.TunnelIpAddress | Filters the metric data by the IP address of the tunnel for the virtual private gateway. | keyword |
| aws.dimensions.VpnId | Filters the metric data by the Site-to-Site VPN connection ID. | keyword |
| aws.s3.bucket.name | Name of a S3 bucket. | keyword |
| aws.tags.* | Tag key value pairs from aws resources. | object |
| aws.vpn.metrics.TunnelDataIn.sum | The bytes received through the VPN tunnel. | double |
| aws.vpn.metrics.TunnelDataOut.sum | The bytes sent through the VPN tunnel. | double |
| aws.vpn.metrics.TunnelState.avg | The state of the tunnel. For static VPNs, 0 indicates DOWN and 1 indicates UP. For BGP VPNs, 1 indicates ESTABLISHED and 0 is used for all other states. | double |
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

