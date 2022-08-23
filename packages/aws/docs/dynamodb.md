# Amazon DynamoDB

The Amazon DynamoDB integration allows you to monitor [Amazon DynamoDB](https://aws.amazon.com/dynamodb/)—a key-value NoSQL database.

Use the Amazon DynamoDB integration to collect metrics related to your Amazon DynamoDB databases.
Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference metrics when troubleshooting an issue.

For example, you could use this data to visualize consumed read and write capacity units. You can then create alerts based on used or unused capacity, so that the relevant users can better scale their provisioned throughput capacity. This might mean they increase the capacity to provide more resources, or reduce capacity to save on costs.

## Data streams

The Amazon DynamoDB integration collects one type of data: metrics.

**Metrics** give you insight into the state of Amazon DynamoDB.
Metrics collected by the Amazon DynamoDB integration include the maximum number of read and write capacity units that can be used by an account, consume capacity units, throttle events, and more. See more details in the [Metrics reference](#metrics-reference).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Before using any AWS integration you will need:

* **AWS Credentials** to connect with your AWS account.
* **AWS Permissions** to make sure the user you're using to connect has permission to share the relevant data.

For more details about these requirements, see the **AWS** integration documentation.

## Setup

Use this integration if you only need to collect data from AWS DynamoDB.

If you want to collect data from two or more AWS services, consider using the **AWS** integration.
When you configure the AWS integration, you can collect data from as many AWS services as you'd like.

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Metrics reference

The `dynamodb` data stream collects DynamoDB metrics from AWS.
An example event for `dynamodb` looks like this:

An example event for `dynamodb` looks as following:

```json
{
    "@timestamp": "2022-07-25T21:53:00.000Z",
    "agent": {
        "name": "docker-fleet-agent",
        "id": "2d4b09d0-cdb6-445e-ac3f-6415f87b9864",
        "type": "metricbeat",
        "ephemeral_id": "64a12b83-a4f1-487c-8d2c-9581fda6ca2a",
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
        "dataset": "aws.dynamodb"
    },
    "metricset": {
        "period": 300000,
        "name": "dynamodb"
    },
    "event": {
        "duration": 10586366300,
        "agent_id_status": "verified",
        "ingested": "2022-07-25T21:57:51Z",
        "module": "aws",
        "dataset": "aws.dynamodb"
    },
    "aws": {
        "cloudwatch": {
            "namespace": "AWS/DynamoDB"
        },
        "dynamodb": {
            "metrics": {
                "AccountProvisionedWriteCapacityUtilization": {
                    "avg": 0.01
                },
                "MaxProvisionedTableWriteCapacityUtilization": {
                    "max": 0.01
                },
                "MaxProvisionedTableReadCapacityUtilization": {
                    "max": 0.01
                },
                "AccountMaxTableLevelReads": {
                    "max": 40000
                },
                "AccountMaxReads": {
                    "max": 80000
                },
                "AccountProvisionedReadCapacityUtilization": {
                    "avg": 0.01
                },
                "AccountMaxWrites": {
                    "max": 80000
                },
                "AccountMaxTableLevelWrites": {
                    "max": 40000
                }
            }
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.cloudwatch.namespace | The namespace specified when query cloudwatch api. | keyword |
| aws.dimensions.\* | Metric dimensions. | object |
| aws.dimensions.DelegatedOperation | This dimension limits the data to operations DynamoDB performs on your behalf. | keyword |
| aws.dimensions.GlobalSecondaryIndexName | This dimension limits the data to a global secondary index on a table. | keyword |
| aws.dimensions.Operation | This dimension limits the data to one of the DynamoDB operations, such as PutItem, DeleteItem, UpdateItem, etc. | keyword |
| aws.dimensions.OperationType | This dimension limits the data to operation type Read and Write. | keyword |
| aws.dimensions.ReceivingRegion | This dimension limits the data to a particular AWS region. | keyword |
| aws.dimensions.StreamLabel | This dimension limits the data to a specific stream label. | keyword |
| aws.dimensions.TableName | This dimension limits the data to a specific table. | keyword |
| aws.dimensions.Verb | This dimension limits the data to one of the DynamoDB PartiQL verbs. | keyword |
| aws.dynamodb.metrics.AccountMaxReads.max | The maximum number of read capacity units that can be used by an account. This limit does not apply to on-demand tables or global secondary indexes. | long |
| aws.dynamodb.metrics.AccountMaxTableLevelReads.max | The maximum number of read capacity units that can be used by a table or global secondary index of an account. For on-demand tables this limit caps the maximum read request units a table or a global secondary index can use. | long |
| aws.dynamodb.metrics.AccountMaxTableLevelWrites.max | The maximum number of write capacity units that can be used by a table or global secondary index of an account. For on-demand tables this limit caps the maximum write request units a table or a global secondary index can use. | long |
| aws.dynamodb.metrics.AccountMaxWrites.max | The maximum number of write capacity units that can be used by an account. This limit does not apply to on-demand tables or global secondary indexes. | long |
| aws.dynamodb.metrics.AccountProvisionedReadCapacityUtilization.avg | The average percentage of provisioned read capacity units utilized by the account. | double |
| aws.dynamodb.metrics.AccountProvisionedWriteCapacityUtilization.avg | The average percentage of provisioned write capacity units utilized by the account. | double |
| aws.dynamodb.metrics.ConditionalCheckFailedRequests.sum | The number of failed attempts to perform conditional writes. | long |
| aws.dynamodb.metrics.ConsumedReadCapacityUnits.avg |  | double |
| aws.dynamodb.metrics.ConsumedReadCapacityUnits.sum |  | long |
| aws.dynamodb.metrics.ConsumedWriteCapacityUnits.avg |  | double |
| aws.dynamodb.metrics.ConsumedWriteCapacityUnits.sum |  | long |
| aws.dynamodb.metrics.MaxProvisionedTableReadCapacityUtilization.max | The percentage of provisioned read capacity units utilized by the highest provisioned read table or global secondary index of an account. | double |
| aws.dynamodb.metrics.MaxProvisionedTableWriteCapacityUtilization.max | The percentage of provisioned write capacity utilized by the highest provisioned write table or global secondary index of an account. | double |
| aws.dynamodb.metrics.OnlineIndexPercentageProgress.avg | The percentage of completion when a new global secondary index is being added to a table. | double |
| aws.dynamodb.metrics.PendingReplicationCount.sum | The number of item updates that are written to one replica table, but that have not yet been written to another replica in the global table. | long |
| aws.dynamodb.metrics.ProvisionedReadCapacityUnits.avg | The number of provisioned read capacity units for a table or a global secondary index. | double |
| aws.dynamodb.metrics.ProvisionedWriteCapacityUnits.avg | The number of provisioned write capacity units for a table or a global secondary index. | double |
| aws.dynamodb.metrics.ReadThrottleEvents.sum | Requests to DynamoDB that exceed the provisioned read capacity units for a table or a global secondary index. | long |
| aws.dynamodb.metrics.ReplicationLatency.avg |  | double |
| aws.dynamodb.metrics.ReplicationLatency.max |  | double |
| aws.dynamodb.metrics.SuccessfulRequestLatency.avg |  | double |
| aws.dynamodb.metrics.SuccessfulRequestLatency.max |  | double |
| aws.dynamodb.metrics.SystemErrors.sum | The requests to DynamoDB or Amazon DynamoDB Streams that generate an HTTP 500 status code during the specified time period. | long |
| aws.dynamodb.metrics.ThrottledRequests.sum | Requests to DynamoDB that exceed the provisioned throughput limits on a resource (such as a table or an index). | long |
| aws.dynamodb.metrics.TransactionConflict.avg |  | double |
| aws.dynamodb.metrics.TransactionConflict.sum |  | long |
| aws.dynamodb.metrics.WriteThrottleEvents.sum | Requests to DynamoDB that exceed the provisioned write capacity units for a table or a global secondary index. | long |
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
| cloud.region | Region in which this host is running. | keyword |
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
