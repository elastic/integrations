# STAN integration

This integration is used to collect logs and metrics from [STAN servers](https://github.com/nats-io/stan.go).
The integration collects metrics from [STAN monitoring server APIs](https://github.com/nats-io/nats-streaming-server/blob/master/server/monitor.go).


## Compatibility

The STAN package is tested with Stan 0.15.1

## Logs

### log

The `log` dataset collects the STAN logs.

An example event for `log` looks as following:

```$json
{}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.ip | IP address of the client. | ip |
| client.port | Port of the client. | long |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version | keyword |
| error.message | Error message. | text |
| event.created | Time when the event was first read by an agent or by your pipeline. | date |
| event.kind | The kind of the event. The highest categorization field in the hierarchy. | keyword |
| event.type | Event type. The third categorization field in the hierarchy. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.path | Full path to the log file this event came from. | keyword |
| log.level | Log level of the log event. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | text |
| nats.log.client.id | The id of the client | integer |
| nats.log.msg.bytes | Size of the payload in bytes | long |
| nats.log.msg.error.message | Details about the error occurred | text |
| nats.log.msg.max_messages | An optional number of messages to wait for before automatically unsubscribing | integer |
| nats.log.msg.queue_group | The queue group which subscriber will join | text |
| nats.log.msg.reply_to | The inbox subject on which the publisher is listening for responses | keyword |
| nats.log.msg.sid | The unique alphanumeric subscription ID of the subject | integer |
| nats.log.msg.subject | Subject name this message was received on | keyword |
| nats.log.msg.type | The protocol message type | keyword |
| network.direction | Direction of the network traffic. Recommended values are:   * inbound   * outbound   * internal   * external   * unknown  When mapping events from a host-based monitoring context, populate this field from the host's point of view. When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of your network perimeter. | keyword |
| process.pid | Process id. | long |
| related.ip | All of the IPs seen on your event. | ip |


## Metrics

The default datasets are `stats`, `channels`, and `subscriptions`.

### stats

This is the `stats` dataset of the STAN package, in charge of retrieving generic
metrics from a STAN instance.

An example event for `stats` looks as following:

```$json
{}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| stan.cluster.id | The cluster ID | keyword |
| stan.server.id | The server ID | keyword |
| stan.stats.bytes | Number of bytes consumed across all STAN queues | long |
| stan.stats.channels | The number of STAN channels | integer |
| stan.stats.clients | The number of STAN clients | integer |
| stan.stats.messages | Number of messages across all STAN queues | long |
| stan.stats.role | If clustered, role of this node in the cluster (Leader, Follower, Candidate) | keyword |
| stan.stats.state | The cluster / streaming configuration state (STANDALONE, CLUSTERED) | keyword |
| stan.stats.subscriptions | The number of STAN streaming subscriptions | integer |


### channels

This is the `channels` dataset of the STAN package, in charge of retrieving
metrics about channels from a STAN instance.

An example event for `channels` looks as following:

```$json
{}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| stan.channels.bytes | The number of STAN bytes in the channel | long |
| stan.channels.depth | Queue depth based upon current sequence number and highest reported subscriber sequence number | long |
| stan.channels.first_seq | First sequence number stored in the channel. If first_seq > min([seq in subscriptions]) data loss has possibly occurred | long |
| stan.channels.last_seq | Last sequence number stored in the channel | long |
| stan.channels.messages | The number of STAN streaming messages | long |
| stan.channels.name | The name of the STAN streaming channel | keyword |
| stan.cluster.id | The cluster ID | keyword |
| stan.server.id | The server ID | keyword |


### subscriptions

This is the `subscriptions` dataset of the STAN package, in charge of retrieving
metrics about subscriptions from a STAN instance.

An example event for `subscriptions` looks as following:

```$json
{}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| stan.cluster.id | The cluster ID | keyword |
| stan.server.id | The server ID | keyword |
| stan.subscriptions.channel | The name of the STAN channel the subscription is associated with | keyword |
| stan.subscriptions.id | The name of the STAN channel subscription (client_id) | keyword |
| stan.subscriptions.last_sent | Last known sequence number of the subscription that was acked | long |
| stan.subscriptions.offline | Is the subscriber marked as offline? | boolean |
| stan.subscriptions.pending | Number of pending messages from / to the subscriber | long |
| stan.subscriptions.queue | The name of the NATS queue that the STAN channel subscription is associated with, if any | keyword |
| stan.subscriptions.stalled | Is the subscriber known to be stalled? | boolean |
