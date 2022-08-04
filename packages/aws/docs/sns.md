# sns

## Metrics

An example event for `sns` looks as following:

```json
{
    "@timestamp": "2022-07-26T21:56:00.000Z",
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
        "dataset": "aws.sns"
    },
    "service": {
        "type": "aws"
    },
    "metricset": {
        "period": 300000,
        "name": "cloudwatch"
    },
    "aws": {
        "sns": {
            "metrics": {
                "NumberOfNotificationsDelivered": {
                    "sum": 5
                },
                "NumberOfMessagesPublished": {
                    "sum": 6
                },
                "PublishSize": {
                    "avg": 905
                },
                "NumberOfNotificationsFailed": {
                    "sum": 0
                }
            }
        },
        "cloudwatch": {
            "namespace": "AWS/SNS"
        },
        "dimensions": {
            "TopicName": "vpc-flow-logs-sns-topic"
        }
    },
    "event": {
        "duration": 10483932100,
        "agent_id_status": "verified",
        "ingested": "2022-07-26T22:01:00Z",
        "module": "aws",
        "dataset": "aws.sns"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.cloudwatch.namespace | The namespace specified when query cloudwatch api. | keyword |
| aws.dimensions.\* | Metric dimensions. | object |
| aws.dimensions.Application | Filters on application objects, which represent an app and device registered with one of the supported push notification services, such as APNs and FCM. | keyword |
| aws.dimensions.Country | Filters on the destination country or region of an SMS message. | keyword |
| aws.dimensions.Platform | Filters on platform objects for the push notification services, such as APNs and FCM. | keyword |
| aws.dimensions.SMSType | Filters on the message type of SMS message. | keyword |
| aws.dimensions.TopicName | Filters on Amazon SNS topic names. | keyword |
| aws.s3.bucket.name | Name of a S3 bucket. | keyword |
| aws.sns.metrics.NumberOfMessagesPublished.sum | The number of messages published to your Amazon SNS topics. | long |
| aws.sns.metrics.NumberOfNotificationsDelivered.sum | The number of messages successfully delivered from your Amazon SNS topics to subscribing endpoints. | long |
| aws.sns.metrics.NumberOfNotificationsFailed.sum | The number of messages that Amazon SNS failed to deliver. | long |
| aws.sns.metrics.NumberOfNotificationsFailedToRedriveToDlq.sum | The number of messages that couldn't be moved to a dead-letter queue. | long |
| aws.sns.metrics.NumberOfNotificationsFilteredOut-InvalidAttributes.sum | The number of messages that were rejected by subscription filter policies because the messages' attributes are invalid - for example, because the attribute JSON is incorrectly formatted. | long |
| aws.sns.metrics.NumberOfNotificationsFilteredOut-NoMessageAttributes.sum | The number of messages that were rejected by subscription filter policies because the messages have no attributes. | long |
| aws.sns.metrics.NumberOfNotificationsFilteredOut.sum | The number of messages that were rejected by subscription filter policies. | long |
| aws.sns.metrics.NumberOfNotificationsRedrivenToDlq.sum | The number of messages that have been moved to a dead-letter queue. | long |
| aws.sns.metrics.PublishSize.avg | The size of messages published. | double |
| aws.sns.metrics.SMSMonthToDateSpentUSD.sum | The charges you have accrued since the start of the current calendar month for sending SMS messages. | long |
| aws.sns.metrics.SMSSuccessRate.avg | The rate of successful SMS message deliveries. | double |
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
