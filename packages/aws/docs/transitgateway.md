# AWS Transit Gateway

The AWS Transit Gateway integration allows you to monitor [AWS Transit Gateway](https://aws.amazon.com/transit-gateway)—a service that connects networks to a single gateway.

Use the AWS Transit Gateway integration collect metrics related to traffic routed between VPCs and on-premises networks. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference metrics when troubleshooting an issue.

For example, you could use this integration to track the number of packets dropped because they did not match a route. Then set up anomaly detection to alert when the number of packets dropped spikes.

## Data streams

The AWS Transit Gateway integration collects one type of data: metrics.

**Metrics** give you insight into the state of AWS Transit Gateway.
Metrics collected by the AWS Transit Gateway integration include the number of bytes sent from the transit gateway, the number of bytes received from the transit gateway, the number of packets dropped because they did not match a route, and more. See more details in the [Metrics reference](#metrics-reference).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Before using any AWS integration you will need:

* **AWS Credentials** to connect with your AWS account.
* **AWS Permissions** to make sure the user you're using to connect has permission to share the relevant data.

For more details about these requirements, see the **AWS** integration documentation.

## Setup

Use this integration if you only need to collect data from the AWS Transit Gateway service.

If you want to collect data from two or more AWS services, consider using the **AWS** integration.
When you configure the AWS integration, you can collect data from as many AWS services as you'd like.

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Metrics reference

An example event for `transitgateway` looks as following:

```json
{
    "agent": {
        "name": "a20ad158868c",
        "id": "ac8c5411-b1d9-486a-baf7-a719744b13e5",
        "ephemeral_id": "d43b281f-9a3e-48be-a7b2-e70c0d0b9acd",
        "type": "metricbeat",
        "version": "8.1.0"
    },
    "elastic_agent": {
        "id": "ac8c5411-b1d9-486a-baf7-a719744b13e5",
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
    "@timestamp": "2022-07-26T21:58:00.000Z",
    "ecs": {
        "version": "8.0.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "aws.transitgateway"
    },
    "service": {
        "type": "aws"
    },
    "host": {
        "hostname": "a20ad158868c",
        "os": {
            "kernel": "5.10.104-linuxkit",
            "codename": "focal",
            "name": "Ubuntu",
            "type": "linux",
            "family": "debian",
            "version": "20.04.3 LTS (Focal Fossa)",
            "platform": "ubuntu"
        },
        "containerized": false,
        "ip": [
            "172.20.0.7"
        ],
        "name": "a20ad158868c",
        "mac": [
            "02:42:ac:14:00:07"
        ],
        "architecture": "aarch64"
    },
    "metricset": {
        "period": 60000,
        "name": "cloudwatch"
    },
    "aws": {
        "cloudwatch": {
            "namespace": "AWS/TransitGateway"
        },
        "transitgateway": {
            "metrics": {
                "PacketsOut": {
                    "sum": 0
                },
                "BytesDropCountNoRoute": {
                    "sum": 0
                },
                "PacketDropCountNoRoute": {
                    "sum": 0
                },
                "BytesOut": {
                    "sum": 0
                },
                "BytesIn": {
                    "sum": 0
                },
                "PacketsIn": {
                    "sum": 0
                },
                "BytesDropCountBlackhole": {
                    "sum": 0
                },
                "PacketDropCountBlackhole": {
                    "sum": 0
                }
            }
        },
        "dimensions": {
            "TransitGateway": "tgw-04653af6191a63891"
        }
    },
    "event": {
        "duration": 1614567042,
        "agent_id_status": "verified",
        "ingested": "2022-07-26T21:59:04Z",
        "module": "aws",
        "dataset": "aws.transitgateway"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.cloudwatch.namespace | The namespace specified when query cloudwatch api. | keyword |
| aws.dimensions.\* | Metric dimensions. | object |
| aws.dimensions.TransitGateway | Filters the metric data by transit gateway. | keyword |
| aws.dimensions.TransitGatewayAttachment | Filters the metric data by transit gateway attachment. | keyword |
| aws.s3.bucket.name | Name of a S3 bucket. | keyword |
| aws.tags.\* | Tag key value pairs from aws resources. | object |
| aws.transitgateway.metrics.BytesDropCountBlackhole.sum | The number of bytes dropped because they matched a blackhole route. | long |
| aws.transitgateway.metrics.BytesDropCountNoRoute.sum | The number of bytes dropped because they did not match a route. | long |
| aws.transitgateway.metrics.BytesIn.sum | The number of bytes received by the transit gateway. | long |
| aws.transitgateway.metrics.BytesOut.sum | The number of bytes sent from the transit gateway. | long |
| aws.transitgateway.metrics.PacketDropCountBlackhole.sum | The number of packets dropped because they matched a blackhole route. | long |
| aws.transitgateway.metrics.PacketDropCountNoRoute.sum | The number of packets dropped because they did not match a route. | long |
| aws.transitgateway.metrics.PacketsIn.sum | The number of packets received by the transit gateway. | long |
| aws.transitgateway.metrics.PacketsOut.sum | The number of packets sent by the transit gateway. | long |
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
