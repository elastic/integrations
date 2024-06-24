# PubSub

## Metrics

The `pubsub` dataset fetches metrics from [PubSub](https://cloud.google.com/pubsub/) in Google Cloud Platform. It contains all metrics exported from the [GCP PubSub Monitoring API](https://cloud.google.com/monitoring/api/metrics_gcp#gcp-pubsub).

You can specify a single region to fetch metrics like `us-central1`. Be aware that GCP PubSub does not use zones so `us-central1-a` will return nothing. If no region is specified, it will return metrics from all buckets.

## Sample Event
    
An example event for `pubsub` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "cloud": {
        "account": {
            "id": "elastic-obs-integrations-dev",
            "name": "elastic-obs-integrations-dev"
        },
        "instance": {
            "id": "4751091017865185079",
            "name": "gke-cluster-1-default-pool-6617a8aa-5clh"
        },
        "machine": {
            "type": "e2-medium"
        },
        "provider": "gcp",
        "availability_zone": "us-central1-c",
        "region": "us-central1"
    },
    "event": {
        "dataset": "gcp.pubsub",
        "duration": 115000,
        "module": "gcp"
    },
    "gcp": {
        "pubsub": {
            "subscription": {
                "backlog": {
                    "bytes": 0
                }
            }
        },
        "labels": {
            "user": {
                "goog-gke-node": ""
            }
        }
    },
    "host": {
        "id": "4751091017865185079",
        "name": "gke-cluster-1-default-pool-6617a8aa-5clh"
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

## Exported fields

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |
| cloud | Fields related to the cloud or infrastructure the events are coming from. | group |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| error | These fields can represent errors of any kind. Use them for errors that happen while fetching events or in cases where the event itself contains an error. | group |  |
| event.dataset | Event dataset | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| gcp.labels.metadata.\* |  | object |  |
| gcp.labels.metrics.\* |  | object |  |
| gcp.labels.resource.\* |  | object |  |
| gcp.labels.system.\* |  | object |  |
| gcp.labels.user.\* |  | object |  |
| gcp.labels_fingerprint | Hashed value of the labels field. | keyword |  |
| gcp.metrics.\*.\*.\*.\* | Metrics that returned from Google Cloud API query. | object |  |
| gcp.pubsub.snapshot.backlog.bytes | Total byte size of the messages retained in a snapshot. | long | gauge |
| gcp.pubsub.snapshot.backlog_bytes_by_region.bytes | Total byte size of the messages retained in a snapshot, broken down by Cloud region. | long | gauge |
| gcp.pubsub.snapshot.config_updates.count | Delta of the cumulative count of configuration changes, grouped by operation type and result. | long | gauge |
| gcp.pubsub.snapshot.num_messages.value | Number of messages retained in a snapshot. | long | gauge |
| gcp.pubsub.snapshot.num_messages_by_region.value | Number of messages retained in a snapshot, broken down by Cloud region. | long | gauge |
| gcp.pubsub.snapshot.oldest_message_age.sec | Age (in seconds) of the oldest message retained in a snapshot. | long | gauge |
| gcp.pubsub.snapshot.oldest_message_age_by_region.sec | Age (in seconds) of the oldest message retained in a snapshot, broken down by Cloud region. | long | gauge |
| gcp.pubsub.subscription.ack_latencies.value | Distribution of ack latencies in milliseconds. The ack latency is the time between when Cloud Pub/Sub sends a message to a subscriber client and when Cloud Pub/Sub receives an Acknowledge request for that message. | object |  |
| gcp.pubsub.subscription.ack_message.count | Delta of the cumulative count of messages acknowledged by Acknowledge requests, grouped by delivery type. | long | gauge |
| gcp.pubsub.subscription.backlog.bytes | Total byte size of the unacknowledged messages (a.k.a. backlog messages) in a subscription. | long | gauge |
| gcp.pubsub.subscription.byte_cost.bytes | Delta of the cumulative cost of operations, measured in bytes. This is used to measure quota utilization. | long | gauge |
| gcp.pubsub.subscription.config_updates.count | Delta of the cumulative count of configuration changes for each subscription, grouped by operation type and result. | long | gauge |
| gcp.pubsub.subscription.dead_letter_message.count | Delta of the cumulative count of messages published to dead letter topic, grouped by result. | long | gauge |
| gcp.pubsub.subscription.mod_ack_deadline_message.count | Delta of the cumulative count of messages whose deadline was updated by ModifyAckDeadline requests, grouped by delivery type. | long | gauge |
| gcp.pubsub.subscription.mod_ack_deadline_message_operation.count | Delta of the cumulative count of ModifyAckDeadline message operations, grouped by result. | long | gauge |
| gcp.pubsub.subscription.mod_ack_deadline_request.count | Delta of the cumulative count of ModifyAckDeadline requests, grouped by result. | long | gauge |
| gcp.pubsub.subscription.num_outstanding_messages.value | Number of messages delivered to a subscription's push endpoint, but not yet acknowledged. | long | gauge |
| gcp.pubsub.subscription.num_undelivered_messages.value | Number of unacknowledged messages (a.k.a. backlog messages) in a subscription. | long | gauge |
| gcp.pubsub.subscription.oldest_retained_acked_message_age.sec | Age (in seconds) of the oldest acknowledged message retained in a subscription. | long | gauge |
| gcp.pubsub.subscription.oldest_retained_acked_message_age_by_region.value | Age (in seconds) of the oldest acknowledged message retained in a subscription, broken down by Cloud region. | long | gauge |
| gcp.pubsub.subscription.oldest_unacked_message_age.sec | Age (in seconds) of the oldest unacknowledged message (a.k.a. backlog message) in a subscription. | long | gauge |
| gcp.pubsub.subscription.oldest_unacked_message_age_by_region.value | Age (in seconds) of the oldest unacknowledged message in a subscription, broken down by Cloud region. | long | gauge |
| gcp.pubsub.subscription.pull_ack_message_operation.count | Delta of the cumulative count of acknowledge message operations, grouped by result. For a definition of message operations, see Cloud Pub/Sub metric subscription/mod_ack_deadline_message_operation_count. | long | gauge |
| gcp.pubsub.subscription.pull_ack_request.count | Delta of the cumulative count of acknowledge requests, grouped by result. | long | gauge |
| gcp.pubsub.subscription.pull_message_operation.count | Delta of the cumulative count of pull message operations, grouped by result. For a definition of message operations, see Cloud Pub/Sub metric subscription/mod_ack_deadline_message_operation_count. | long | gauge |
| gcp.pubsub.subscription.pull_request.count | Delta of the cumulative count of pull requests, grouped by result. | long | gauge |
| gcp.pubsub.subscription.push_request.count | Delta of the cumulative count of push attempts, grouped by result. Unlike pulls, the push server implementation does not batch user messages. So each request only contains one user message. The push server retries on errors, so a given user message can appear multiple times. | long | gauge |
| gcp.pubsub.subscription.push_request_latencies.value | Distribution of push request latencies (in microseconds), grouped by result. | object |  |
| gcp.pubsub.subscription.retained_acked.bytes | Total byte size of the acknowledged messages retained in a subscription. | long | gauge |
| gcp.pubsub.subscription.retained_acked_bytes_by_region.bytes | Total byte size of the acknowledged messages retained in a subscription, broken down by Cloud region. | long | gauge |
| gcp.pubsub.subscription.seek_request.count | Delta of the cumulative count of seek attempts, grouped by result. | long | gauge |
| gcp.pubsub.subscription.sent_message.count | Delta of the cumulative count of messages sent by Cloud Pub/Sub to subscriber clients, grouped by delivery type. | long | gauge |
| gcp.pubsub.subscription.streaming_pull_ack_message_operation.count | Delta of the cumulative count of StreamingPull acknowledge message operations, grouped by result. For a definition of message operations, see Cloud Pub/Sub metric subscription/mod_ack_deadline_message_operation_count. | long | gauge |
| gcp.pubsub.subscription.streaming_pull_ack_request.count | Delta of the cumulative count of streaming pull requests with non-empty acknowledge ids, grouped by result. | long | gauge |
| gcp.pubsub.subscription.streaming_pull_message_operation.count | Delta of the cumulative count of streaming pull message operations, grouped by result. For a definition of message operations, see Cloud Pub/Sub metric \<code\>subscription/mod_ack_deadline_message_operation_count | long | gauge |
| gcp.pubsub.subscription.streaming_pull_mod_ack_deadline_message_operation.count | Delta of the cumulative count of StreamingPull ModifyAckDeadline operations, grouped by result. | long | gauge |
| gcp.pubsub.subscription.streaming_pull_mod_ack_deadline_request.count | Delta of the cumulative count of streaming pull requests with non-empty ModifyAckDeadline fields, grouped by result. | long | gauge |
| gcp.pubsub.subscription.streaming_pull_response.count | Delta of the cumulative count of streaming pull responses, grouped by result. | long | gauge |
| gcp.pubsub.subscription.unacked_bytes_by_region.bytes | Total byte size of the unacknowledged messages in a subscription, broken down by Cloud region. | long | gauge |
| gcp.pubsub.topic.byte_cost.bytes | Delta of the cost of operations, measured in bytes. This is used to measure utilization for quotas. | long | gauge |
| gcp.pubsub.topic.config_updates.count | Delta of the cumulative count of configuration changes, grouped by operation type and result. | long | gauge |
| gcp.pubsub.topic.message_sizes.bytes | Distribution of publish message sizes (in bytes) | object |  |
| gcp.pubsub.topic.oldest_retained_acked_message_age_by_region.value | Age (in seconds) of the oldest acknowledged message retained in a topic, broken down by Cloud region. | long | gauge |
| gcp.pubsub.topic.oldest_unacked_message_age_by_region.value | Age (in seconds) of the oldest unacknowledged message in a topic, broken down by Cloud region. | long | gauge |
| gcp.pubsub.topic.retained_acked_bytes_by_region.bytes | Total byte size of the acknowledged messages retained in a topic, broken down by Cloud region. | long | gauge |
| gcp.pubsub.topic.send_message_operation.count | Delta of the cumulative count of publish message operations, grouped by result. For a definition of message operations, see Cloud Pub/Sub metric subscription/mod_ack_deadline_message_operation_count. | long | gauge |
| gcp.pubsub.topic.send_request.count | Delta of the cumulative count of publish requests, grouped by result. | long | gauge |
| gcp.pubsub.topic.streaming_pull_response.count | Delta of the cumulative count of streaming pull responses, grouped by result. | long | gauge |
| gcp.pubsub.topic.unacked_bytes_by_region.bytes | Total byte size of the unacknowledged messages in a topic, broken down by Cloud region. | long | gauge |
| host.containerized | If the host is a container. | boolean |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
