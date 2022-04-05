# lambda

## Metrics

An example event for `lambda` looks as following:

```json
{
    "@timestamp": "2020-05-28T17:17:08.666Z",
    "agent": {
        "ephemeral_id": "17803f33-b617-4ce9-a9ac-e218c02aeb4b",
        "id": "12f376ef-5186-4e8b-a175-70f1140a8f30",
        "name": "MacBook-Elastic.local",
        "type": "metricbeat",
        "version": "8.0.0"
    },
    "event": {
        "dataset": "aws.lambda",
        "module": "aws",
        "duration": 10266182336
    },
    "service": {
        "type": "aws"
    },
    "ecs": {
        "version": "1.5.0"
    },
    "cloud": {
        "account": {
            "name": "elastic-beats",
            "id": "428152502467"
        },
        "provider": "aws",
        "region": "eu-central-1"
    },
    "aws": {
        "cloudwatch": {
            "namespace": "AWS/Lambda"
        },
        "dimensions": {
            "FunctionName": "ec2-owner-tagger-serverless",
            "Resource": "ec2-owner-tagger-serverless"
        },
        "lambda": {
            "metrics": {
                "Duration": {
                    "avg": 8218.073333333334
                },
                "Errors": {
                    "avg": 1
                },
                "Invocations": {
                    "avg": 1
                },
                "Throttles": {
                    "avg": 0
                }
            }
        }
    },
    "metricset": {
        "name": "dynamodb",
        "period": 300000
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
| aws.dimensions.ExecutedVersion | Use the ExecutedVersion dimension to compare error rates for two versions of a function that are both targets of a weighted alias. | keyword |
| aws.dimensions.FunctionName | Lambda function name. | keyword |
| aws.dimensions.Resource | Resource name. | keyword |
| aws.lambda.metrics.ConcurrentExecutions.avg | The number of function instances that are processing events. | double |
| aws.lambda.metrics.DeadLetterErrors.avg | For asynchronous invocation, the number of times Lambda attempts to send an event to a dead-letter queue but fails. | double |
| aws.lambda.metrics.DestinationDeliveryFailures.avg | For asynchronous invocation, the number of times Lambda attempts to send an event to a destination but fails. | double |
| aws.lambda.metrics.Duration.avg | The amount of time that your function code spends processing an event. | double |
| aws.lambda.metrics.Errors.avg | The number of invocations that result in a function error. | double |
| aws.lambda.metrics.Invocations.avg | The number of times your function code is executed, including successful executions and executions that result in a function error. | double |
| aws.lambda.metrics.IteratorAge.avg | For event source mappings that read from streams, the age of the last record in the event. | double |
| aws.lambda.metrics.ProvisionedConcurrencyInvocations.sum | The number of times your function code is executed on provisioned concurrency. | long |
| aws.lambda.metrics.ProvisionedConcurrencySpilloverInvocations.sum | The number of times your function code is executed on standard concurrency when all provisioned concurrency is in use. | long |
| aws.lambda.metrics.ProvisionedConcurrencyUtilization.max | For a version or alias, the value of ProvisionedConcurrentExecutions divided by the total amount of provisioned concurrency allocated. | long |
| aws.lambda.metrics.ProvisionedConcurrentExecutions.max | The number of function instances that are processing events on provisioned concurrency. | long |
| aws.lambda.metrics.Throttles.avg | The number of invocation requests that are throttled. | double |
| aws.lambda.metrics.UnreservedConcurrentExecutions.avg | For an AWS Region, the number of events that are being processed by functions that don't have reserved concurrency. | double |
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
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |

