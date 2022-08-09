# Amazon Kinesis

The Amazon Kinesis integration allows you to monitor [Amazon Kinesis](https://aws.amazon.com/kinesis/)—a streaming data processor.

Use the Amazon Kinesis integration to monitor Amazon Kinesis. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference metrics when troubleshooting an issue.

## Data streams

The Amazon Kinesis integration collects one type of data: metrics.

**Metrics** give you insight into the state of Amazon Kinesis.
Metrics collected by this integration include information about operations related to Amazon Kinesis records, shards, and more. See more details in the [Metrics reference](#metrics-reference).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Before using any AWS integration you will need:

* **AWS Credentials** to connect with your AWS account.
* **AWS Permissions** to make sure the user you're using to connect has permission to share the relevant data.

For more details about these requirements, see the **AWS** integration documentation.

## Setup

Use this integration if you only need to collect data from the Amazon Kinesis service.

If you want to collect data from two or more AWS services, consider using the **AWS** integration.
When you configure the AWS integration, you can collect data from as many AWS services as you'd like.

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Metrics

An example event for `kinesis` looks as following:

```json
{
    "@timestamp": "2022-07-27T20:56:00.000Z",
    "agent": {
        "name": "docker-fleet-agent",
        "id": "2d4b09d0-cdb6-445e-ac3f-6415f87b9864",
        "ephemeral_id": "51866723-6dfa-4a72-a68e-f439d5de7f53",
        "type": "metricbeat",
        "version": "8.3.2"
    },
    "elastic_agent": {
        "id": "2d4b09d0-cdb6-445e-ac3f-6415f87b9864",
        "version": "8.3.2",
        "snapshot": false
    },
    "cloud": {
        "provider": "aws",
        "region": "us-east-1",
        "account": {
            "name": "elastic-beats",
            "id": "428152502467"
        }
    },
    "ecs": {
        "version": "8.0.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "aws.kinesis"
    },
    "service": {
        "type": "aws"
    },
    "metricset": {
        "period": 300000,
        "name": "cloudwatch"
    },
    "aws": {
        "cloudwatch": {
            "namespace": "AWS/Kinesis"
        },
        "dimensions": {
            "StreamName": "fb-test"
        },
        "kinesis": {
            "metrics": {
                "GetRecords_Bytes": {
                    "avg": 0
                },
                "GetRecords_IteratorAgeMilliseconds": {
                    "avg": 0
                },
                "GetRecords_Latency": {
                    "avg": 9.46
                },
                "GetRecords_Records": {
                    "sum": 0
                },
                "GetRecords_Success": {
                    "sum": 150
                },
                "ReadProvisionedThroughputExceeded": {
                    "avg": 0
                }
            }
        }
    },
    "event": {
        "duration": 10483932100,
        "agent_id_status": "verified",
        "ingested": "2022-07-27T20:56:00.000Z",
        "module": "aws",
        "dataset": "aws.kinesis"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.cloudwatch.namespace | The namespace specified when query cloudwatch api. | keyword |
| aws.dimensions.\* | Metric dimensions. | object |
| aws.dimensions.StreamName | The name of the Kinesis stream. All available statistics are filtered by StreamName. | keyword |
| aws.kinesis.metrics.GetRecords_Bytes.avg | The average number of bytes retrieved from the Kinesis stream, measured over the specified time period. | double |
| aws.kinesis.metrics.GetRecords_IteratorAgeMilliseconds.avg | The age of the last record in all GetRecords calls made against a Kinesis stream, measured over the specified time period. Age is the difference between the current time and when the last record of the GetRecords call was written to the stream. | double |
| aws.kinesis.metrics.GetRecords_Latency.avg | The time taken per GetRecords operation, measured over the specified time period. | double |
| aws.kinesis.metrics.GetRecords_Records.sum | The number of records retrieved from the shard, measured over the specified time period. | long |
| aws.kinesis.metrics.GetRecords_Success.sum | The number of successful GetRecords operations per stream, measured over the specified time period. | long |
| aws.kinesis.metrics.IncomingBytes.avg | The number of bytes successfully put to the Kinesis stream over the specified time period. This metric includes bytes from PutRecord and PutRecords operations. | double |
| aws.kinesis.metrics.IncomingRecords.avg | The number of records successfully put to the Kinesis stream over the specified time period. This metric includes record counts from PutRecord and PutRecords operations. | double |
| aws.kinesis.metrics.PutRecord_Bytes.avg | The number of bytes put to the Kinesis stream using the PutRecord operation over the specified time period. | double |
| aws.kinesis.metrics.PutRecord_Latency.avg | The time taken per PutRecord operation, measured over the specified time period. | double |
| aws.kinesis.metrics.PutRecord_Success.avg | The percentage of successful writes to a Kinesis stream, measured over the specified time period. | double |
| aws.kinesis.metrics.PutRecords_Bytes.avg | The average number of bytes put to the Kinesis stream using the PutRecords operation over the specified time period. | double |
| aws.kinesis.metrics.PutRecords_FailedRecords.sum | The number of records rejected due to internal failures in a PutRecords operation per Kinesis data stream, measured over the specified time period. | long |
| aws.kinesis.metrics.PutRecords_Latency.avg | The average time taken per PutRecords operation, measured over the specified time period. | double |
| aws.kinesis.metrics.PutRecords_Success.avg | The total number of PutRecords operations where at least one record succeeded, per Kinesis stream, measured over the specified time period. | long |
| aws.kinesis.metrics.PutRecords_SuccessfulRecords.sum | The number of successful records in a PutRecords operation per Kinesis data stream, measured over the specified time period. | long |
| aws.kinesis.metrics.PutRecords_ThrottledRecords.sum | The number of records rejected due to throttling in a PutRecords operation per Kinesis data stream, measured over the specified time period. | long |
| aws.kinesis.metrics.PutRecords_TotalRecords.sum | The total number of records sent in a PutRecords operation per Kinesis data stream, measured over the specified time period. | long |
| aws.kinesis.metrics.ReadProvisionedThroughputExceeded.avg | The number of GetRecords calls throttled for the stream over the specified time period. | long |
| aws.kinesis.metrics.SubscribeToShardEvent_Bytes.avg | The number of bytes received from the shard, measured over the specified time period. | long |
| aws.kinesis.metrics.SubscribeToShardEvent_MillisBehindLatest.avg | The difference between the current time and when the last record of the SubscribeToShard event was written to the stream. | long |
| aws.kinesis.metrics.SubscribeToShardEvent_Records.sum | The number of records received from the shard, measured over the specified time period. | long |
| aws.kinesis.metrics.SubscribeToShardEvent_Success.avg | This metric is emitted every time an event is published successfully. It is only emitted when there's an active subscription. | long |
| aws.kinesis.metrics.SubscribeToShard_RateExceeded.avg | This metric is emitted when a new subscription attempt fails because there already is an active subscription by the same consumer or if you exceed the number of calls per second allowed for this operation. | long |
| aws.kinesis.metrics.SubscribeToShard_Success.avg | This metric records whether the SubscribeToShard subscription was successfully established. | long |
| aws.kinesis.metrics.WriteProvisionedThroughputExceeded.avg | The number of records rejected due to throttling for the stream over the specified time period. This metric includes throttling from PutRecord and PutRecords operations. | long |
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
| host.cpu.pct | Percent CPU used. This value is normalized by the number of CPU cores and it ranges from 0 to 1. | scaled_float |
| host.disk.read.bytes | The total number of bytes read successfully in a given period of time. | long |
| host.disk.write.bytes | The total number of bytes write successfully in a given period of time. | long |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host MAC addresses. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
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
| host.os.name.text | Multi-field of `host.os.name`. | match_only_text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
