# AWS Lambda

The AWS Lambda integration allows you to monitor [AWS Lambda](https://aws.amazon.com/lambda/)—a serverless compute service.

Use the AWS Lambda integration to collect metrics related to your [Lambda functions](https://aws.amazon.com/lambda/faqs/#AWS_Lambda_functions). Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference metrics when troubleshooting an issue.

For example, you could use this integration to track throttled lambda functions, alert the relevant project manager, and then increase your account's concurrency limit.

## Data streams

The AWS Lambda integration collects one type of data: metrics.

**Metrics** give you insight into the state of AWS Lambda.
Metrics collected by the AWS Lambda integration include the number of times your function code is executed, the amount of time that your function code spends processing an event, the number of invocations that result in a function error, and more. See more details in the [Metrics reference](#metrics-reference).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Before using any AWS integration you will need:

* **AWS Credentials** to connect with your AWS account.
* **AWS Permissions** to make sure the user you're using to connect has permission to share the relevant data.

For more details about these requirements, see the **AWS** integration documentation.

## Setup

Use this integration if you only need to collect data from the AWS Lambda service.

If you want to collect data from two or more AWS services, consider using the **AWS** integration.
When you configure the AWS integration, you can collect data from as many AWS services as you'd like.

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Metrics reference

An example event for `lambda` looks as following:

```json
{
    "@timestamp": "2022-07-19T22:40:00.000Z",
    "agent": {
        "name": "docker-fleet-agent",
        "id": "2d4b09d0-cdb6-445e-ac3f-6415f87b9864",
        "type": "metricbeat",
        "ephemeral_id": "ed2abfa1-df5e-4c3e-9c2b-143edcc0e111",
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
            "name": "elastic-observability",
            "id": "627286350134"
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
        "dataset": "aws.lambda"
    },
    "metricset": {
        "period": 300000,
        "name": "cloudwatch"
    },
    "aws": {
        "lambda": {
            "metrics": {
                "Errors": {
                    "avg": 0
                },
                "ConcurrentExecutions": {
                    "avg": 1
                },
                "Invocations": {
                    "avg": 1
                },
                "UnreservedConcurrentExecutions": {
                    "avg": 1
                },
                "Duration": {
                    "avg": 130.97
                },
                "Throttles": {
                    "avg": 0
                }
            }
        },
        "cloudwatch": {
            "namespace": "AWS/Lambda"
        }
    },
    "event": {
        "duration": 11364562400,
        "agent_id_status": "verified",
        "ingested": "2022-07-26T22:40:40Z",
        "module": "aws",
        "dataset": "aws.lambda"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
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
