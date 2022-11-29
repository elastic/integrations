# AWS SQS

The AWS SQS integration allows you to monitor [Amazon Simple Queue Service (Amazon SQS)](https://aws.amazon.com/sqs/)—a managed message queuing service.

Use the AWS SQS integration to view metrics on messages sent, stored, and received via Amazon SQS. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference metrics when troubleshooting an issue.

For example, you could track the number of messages in the queue that are delayed and not available for reading immediately. Then create an alert to be notified if the queue reaches a certain size.

## Data streams

The SQS integration collects one type of data: metrics.

**Metrics** give you insight into the state of AWS SQS.
Metrics collected by the AWS SQS integration include the number of messages that are in flight, the number of ReceiveMessage API calls that did not return a message, and more. See more details in the [Metrics reference](#metrics-reference).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Before using any AWS integration you will need:

* **AWS Credentials** to connect with your AWS account.
* **AWS Permissions** to make sure the user you're using to connect has permission to share the relevant data.

For more details about these requirements, see the **AWS** integration documentation.

## Setup

Use this integration if you only need to collect data from the AWS SQS service.

If you want to collect data from two or more AWS services, consider using the **AWS** integration.
When you configure the AWS integration, you can collect data from as many AWS services as you'd like.

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Metrics reference

An example event for `sqs` looks as following:

```json
{
    "@timestamp": "2022-07-26T21:43:00.000Z",
    "agent": {
        "name": "docker-fleet-agent",
        "id": "2d4b09d0-cdb6-445e-ac3f-6415f87b9864",
        "type": "metricbeat",
        "ephemeral_id": "cdaaaabb-be7e-432f-816b-bda019fd7c15",
        "version": "8.3.2"
    },
    "elastic_agent": {
        "id": "2d4b09d0-cdb6-445e-ac3f-6415f87b9864",
        "version": "8.3.2",
        "snapshot": false
    },
    "cloud": {
        "provider": "aws",
        "region": "eu-central-1",
        "account": {
            "name": "elastic-beats",
            "id": "428152502467"
        }
    },
    "ecs": {
        "version": "8.0.0"
    },
    "service": {
        "type": "aws"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "aws.sqs"
    },
    "metricset": {
        "period": 300000,
        "name": "cloudwatch"
    },
    "aws": {
        "sqs": {
            "messages": {
                "visible": 1518.4,
                "deleted": 0,
                "not_visible": 0,
                "delayed": 0,
                "received": 0,
                "sent": 0.16666666666666666
            },
            "empty_receives": 0,
            "sent_message_size": {
                "bytes": 1002
            },
            "oldest_message_age": {
                "sec": 345605.6
            },
            "queue": {
                "name": "filebeat-aws-elb-test"
            }
        },
        "cloudwatch": {
            "namespace": "AWS/SQS"
        },
        "dimensions": {
            "QueueName": "filebeat-aws-elb-test"
        },
        "tags": {
            "created-by": "kaiyan"
        }
    },
    "event": {
        "duration": 11576777300,
        "agent_id_status": "verified",
        "ingested": "2022-07-26T21:47:48Z",
        "module": "aws",
        "dataset": "aws.sqs"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.cloudwatch.namespace | The namespace specified when query cloudwatch api. | keyword |
| aws.dimensions.\* | Metric dimensions. | object |
| aws.dimensions.QueueName | SQS queue name | keyword |
| aws.s3.bucket.name | Name of a S3 bucket. | keyword |
| aws.sqs.empty_receives | The number of ReceiveMessage API calls that did not return a message. | long |
| aws.sqs.messages.delayed | TThe number of messages in the queue that are delayed and not available for reading immediately. | long |
| aws.sqs.messages.deleted | The number of messages deleted from the queue. | long |
| aws.sqs.messages.not_visible | The number of messages that are in flight. | long |
| aws.sqs.messages.received | The number of messages returned by calls to the ReceiveMessage action. | long |
| aws.sqs.messages.sent | The number of messages added to a queue. | long |
| aws.sqs.messages.visible | The number of messages available for retrieval from the queue. | long |
| aws.sqs.oldest_message_age.sec | The approximate age of the oldest non-deleted message in the queue. | long |
| aws.sqs.queue.name | SQS queue name | keyword |
| aws.sqs.sent_message_size.bytes | The size of messages added to a queue. | long |
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
