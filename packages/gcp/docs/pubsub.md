# Pub Sub

## Metrics

This is the `pubsub` dataset.

An example event for `pubsub` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "cloud": {
        "account": {
            "id": "elastic-observability"
        },
        "provider": "gcp"
    },
    "event": {
        "dataset": "gcp.pubsub",
        "duration": 115000,
        "module": "gcp"
    },
    "gcp": {
        "labels": {
            "resource": {
                "subscription_id": "test-subscription-1"
            }
        },
        "pubsub": {
            "subscription": {
                "backlog_bytes": {
                    "value": 0
                }
            }
        }
    },
    "metricset": {
        "name": "pubsub",
        "period": 10000
    },
    "service": {
        "type": "gcp"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
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
| gcp.pubsub.snapshot.backlog_bytes.value | Total byte size of the messages retained in a snapshot. | long |
| gcp.pubsub.snapshot.backlog_bytes_by_region.value | Total byte size of the messages retained in a snapshot, broken down by Cloud region. | long |
| gcp.pubsub.snapshot.config_updates_count.value | Cumulative count of configuration changes, grouped by operation type and result. | long |
| gcp.pubsub.snapshot.num_messages.value | Number of messages retained in a snapshot. | long |
| gcp.pubsub.snapshot.num_messages_by_region.value | Number of messages retained in a snapshot, broken down by Cloud region. | long |
| gcp.pubsub.snapshot.oldest_message_age.value | Age (in seconds) of the oldest message retained in a snapshot. | long |
| gcp.pubsub.snapshot.oldest_message_age_by_region.value | Age (in seconds) of the oldest message retained in a snapshot, broken down by Cloud region. | long |
| gcp.pubsub.subscription.ack_message_count.value | Cumulative count of messages acknowledged by Acknowledge requests, grouped by delivery type. | long |
| gcp.pubsub.subscription.backlog_bytes.value | Total byte size of the unacknowledged messages (a.k.a. backlog messages) in a subscription. | long |
| gcp.pubsub.subscription.byte_cost.value | Cumulative cost of operations, measured in bytes. This is used to measure quota utilization. | long |
| gcp.pubsub.subscription.config_updates_count.value | Cumulative count of configuration changes for each subscription, grouped by operation type and result. | long |
| gcp.pubsub.subscription.dead_letter_message_count.value | Cumulative count of messages published to dead letter topic, grouped by result. | long |
| gcp.pubsub.subscription.mod_ack_deadline_message_count.value | Cumulative count of messages whose deadline was updated by ModifyAckDeadline requests, grouped by delivery type. | long |
| gcp.pubsub.subscription.mod_ack_deadline_message_operation_count.value | Cumulative count of ModifyAckDeadline message operations, grouped by result. | long |
| gcp.pubsub.subscription.mod_ack_deadline_request_count.value | Cumulative count of ModifyAckDeadline requests, grouped by result. | long |
| gcp.pubsub.subscription.num_outstanding_messages.value | Number of messages delivered to a subscription's push endpoint, but not yet acknowledged. | long |
| gcp.pubsub.subscription.num_undelivered_messages.value | Number of unacknowledged messages (a.k.a. backlog messages) in a subscription. | long |
| gcp.pubsub.subscription.oldest_retained_acked_message_age.value | Age (in seconds) of the oldest acknowledged message retained in a subscription. | long |
| gcp.pubsub.subscription.oldest_retained_acked_message_age_by_region.value | Age (in seconds) of the oldest acknowledged message retained in a subscription, broken down by Cloud region. | long |
| gcp.pubsub.subscription.oldest_unacked_message_age.value | Age (in seconds) of the oldest unacknowledged message (a.k.a. backlog message) in a subscription. | long |
| gcp.pubsub.subscription.oldest_unacked_message_age_by_region.value | Age (in seconds) of the oldest unacknowledged message in a subscription, broken down by Cloud region. | long |
| gcp.pubsub.subscription.pull_ack_message_operation_count.value | Cumulative count of acknowledge message operations, grouped by result. For a definition of message operations, see Cloud Pub/Sub metric subscription/mod_ack_deadline_message_operation_count. | long |
| gcp.pubsub.subscription.pull_ack_request_count.value | Cumulative count of acknowledge requests, grouped by result. | long |
| gcp.pubsub.subscription.pull_message_operation_count.value | Cumulative count of pull message operations, grouped by result. For a definition of message operations, see Cloud Pub/Sub metric subscription/mod_ack_deadline_message_operation_count. | long |
| gcp.pubsub.subscription.pull_request_count.value | Cumulative count of pull requests, grouped by result. | long |
| gcp.pubsub.subscription.push_request_count.value | Cumulative count of push attempts, grouped by result. Unlike pulls, the push server implementation does not batch user messages. So each request only contains one user message. The push server retries on errors, so a given user message can appear multiple times. | long |
| gcp.pubsub.subscription.push_request_latencies.value | Distribution of push request latencies (in microseconds), grouped by result. | long |
| gcp.pubsub.subscription.retained_acked_bytes.value | Total byte size of the acknowledged messages retained in a subscription. | long |
| gcp.pubsub.subscription.retained_acked_bytes_by_region.value | Total byte size of the acknowledged messages retained in a subscription, broken down by Cloud region. | long |
| gcp.pubsub.subscription.seek_request_count.value | Cumulative count of seek attempts, grouped by result. | long |
| gcp.pubsub.subscription.sent_message_count.value | Cumulative count of messages sent by Cloud Pub/Sub to subscriber clients, grouped by delivery type. | long |
| gcp.pubsub.subscription.streaming_pull_ack_message_operation_count.value | Cumulative count of StreamingPull acknowledge message operations, grouped by result. For a definition of message operations, see Cloud Pub/Sub metric subscription/mod_ack_deadline_message_operation_count. | long |
| gcp.pubsub.subscription.streaming_pull_ack_request_count.value | Cumulative count of streaming pull requests with non-empty acknowledge ids, grouped by result. | long |
| gcp.pubsub.subscription.streaming_pull_message_operation_count.value | Cumulative count of streaming pull message operations, grouped by result. For a definition of message operations, see Cloud Pub/Sub metric \<code\>subscription/mod_ack_deadline_message_operation_count | long |
| gcp.pubsub.subscription.streaming_pull_mod_ack_deadline_message_operation_count.value | Cumulative count of StreamingPull ModifyAckDeadline operations, grouped by result. | long |
| gcp.pubsub.subscription.streaming_pull_mod_ack_deadline_request_count.value | Cumulative count of streaming pull requests with non-empty ModifyAckDeadline fields, grouped by result. | long |
| gcp.pubsub.subscription.streaming_pull_response_count.value | Cumulative count of streaming pull responses, grouped by result. | long |
| gcp.pubsub.subscription.unacked_bytes_by_region.value | Total byte size of the unacknowledged messages in a subscription, broken down by Cloud region. | long |
| gcp.pubsub.topic.byte_cost.value | Cost of operations, measured in bytes. This is used to measure utilization for quotas. | long |
| gcp.pubsub.topic.config_updates_count.value | Cumulative count of configuration changes, grouped by operation type and result. | long |
| gcp.pubsub.topic.message_sizes.value | Distribution of publish message sizes (in bytes) | long |
| gcp.pubsub.topic.oldest_retained_acked_message_age_by_region.value | Age (in seconds) of the oldest acknowledged message retained in a topic, broken down by Cloud region. | long |
| gcp.pubsub.topic.oldest_unacked_message_age_by_region.value | Age (in seconds) of the oldest unacknowledged message in a topic, broken down by Cloud region. | long |
| gcp.pubsub.topic.retained_acked_bytes_by_region.value | Total byte size of the acknowledged messages retained in a topic, broken down by Cloud region. | long |
| gcp.pubsub.topic.send_message_operation_count.value | Cumulative count of publish message operations, grouped by result. For a definition of message operations, see Cloud Pub/Sub metric subscription/mod_ack_deadline_message_operation_count. | long |
| gcp.pubsub.topic.send_request_count.value | Cumulative count of publish requests, grouped by result. | long |
| gcp.pubsub.topic.streaming_pull_response_count.value | Cumulative count of streaming pull responses, grouped by result. | long |
| gcp.pubsub.topic.unacked_bytes_by_region.value | Total byte size of the unacknowledged messages in a topic, broken down by Cloud region. | long |
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
