# AWS Billing

The AWS Billing integration allows you to monitor your [AWS spending](https://aws.amazon.com/aws-cost-management/aws-billing/).

Use the AWS Billing integration to collect metrics related to your monthly AWS bills. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference metrics when troubleshooting an issue.

For example, you could use this data to easily view your total estimated charges or billing by service. Then you can alert the relevant budget holder about those costs by email.

## Data streams

The AWS Billing integration collects one type of data: metrics.

**Metrics** give you insight into the state of your AWS spending, including the estimated costs for various AWS services. Metrics are gathered with the AWS [Cost Explorer API](https://docs.aws.amazon.com/cost-management/latest/userguide/ce-api.html)).

See more details in the [Metrics reference](#metrics-reference).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Before using any AWS integration you will need:

* **AWS Credentials** to connect with your AWS account.
* **AWS Permissions** to make sure the user you're using to connect has permission to share the relevant data.

For more details about these requirements, see the **AWS** integration documentation.

## Setup

Use this integration if you only need to collect billing data from AWS.

If you want to collect data from two or more AWS services, consider using the **AWS** integration. When you configure the AWS integration, you can collect data from as many AWS services as you'd like.

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Metrics reference

The `billing` data stream collects billing metrics from AWS.

An example event for `billing` looks as following:

An example event for `billing` looks as following:

```json
{
    "@timestamp": "2020-05-28T17:17:06.212Z",
    "cloud": {
        "provider": "aws",
        "region": "us-east-1",
        "account": {
            "id": "428152502467",
            "name": "elastic-beats"
        }
    },
    "event": {
        "dataset": "aws.billing",
        "module": "aws",
        "duration": 1938760247
    },
    "metricset": {
        "name": "billing",
        "period": 43200000
    },
    "ecs": {
        "version": "1.5.0"
    },
    "aws": {
        "billing": {
            "Currency": "USD",
            "EstimatedCharges": 39.26,
            "ServiceName": "AmazonEKS",
            "AmortizedCost": {
                "amount": 51.6,
                "unit": "USD"
            },
            "BlendedCost": {
                "amount": 51.6,
                "unit": "USD"
            },
            "NormalizedUsageAmount": {
                "amount": 672,
                "unit": "N/A"
            },
            "UnblendedCost": {
                "amount": 51.6,
                "unit": "USD"
            },
            "UsageQuantity": {
                "amount": 168,
                "unit": "N/A"
            }
        }
    },
    "service": {
        "type": "aws"
    },
    "agent": {
        "id": "12f376ef-5186-4e8b-a175-70f1140a8f30",
        "name": "MacBook-Elastic.local",
        "type": "metricbeat",
        "version": "8.0.0",
        "ephemeral_id": "17803f33-b617-4ce9-a9ac-e218c02aeb4b"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.\*.metrics.\*.\* | Metrics that returned from Cloudwatch API query. | object |
| aws.billing.AmortizedCost.amount | Amortized cost amount. | double |
| aws.billing.AmortizedCost.unit | Amortized cost unit. | keyword |
| aws.billing.BlendedCost.amount | Blended cost amount. | double |
| aws.billing.BlendedCost.unit | Blended cost unit. | keyword |
| aws.billing.Currency | Currency name. | keyword |
| aws.billing.EstimatedCharges | Maximum estimated charges for AWS acccount. | long |
| aws.billing.NormalizedUsageAmount.amount | Normalized usage amount. | double |
| aws.billing.NormalizedUsageAmount.unit | Normalized usage amount unit. | keyword |
| aws.billing.ServiceName | AWS service name. | keyword |
| aws.billing.UnblendedCost.amount | Unblended cost amount. | double |
| aws.billing.UnblendedCost.unit | Unblended cost unit. | keyword |
| aws.billing.UsageQuantity.amount | Usage quantity amount. | double |
| aws.billing.UsageQuantity.unit | Usage quantity unit. | keyword |
| aws.billing.end_date | End date for retrieving AWS costs. | keyword |
| aws.billing.group_by | Cost explorer group by key values. | object |
| aws.billing.group_definition.key | The string that represents a key for a specified group. | keyword |
| aws.billing.group_definition.type | The string that represents the type of group. | keyword |
| aws.billing.start_date | Start date for retrieving AWS costs. | keyword |
| aws.cloudwatch.namespace | The namespace specified when query cloudwatch api. | keyword |
| aws.dimensions.\* | Metric dimensions. | object |
| aws.linked_account.id | ID used to identify linked account. | keyword |
| aws.linked_account.name | Name or alias used to identify linked account. | keyword |
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
| cloud.project.id | The cloud project identifier. Examples: Google Cloud Project id, Azure Project id. | keyword |
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
| host.mac | Host MAC addresses. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | match_only_text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |

