# STAN integration

This integration is used to collect logs and metrics from [STAN servers](https://github.com/nats-io/stan.go).
The integration collects metrics from [STAN monitoring server APIs](https://github.com/nats-io/nats-streaming-server/blob/master/server/monitor.go).


## Compatibility

The STAN package is tested with Stan 0.15.1.

## Logs

### log

The `log` dataset collects the STAN logs.

An example event for `log` looks as following:

```json
{
    "@timestamp": "2022-01-12T04:11:35.529Z",
    "agent": {
        "ephemeral_id": "8d87b679-d308-4954-a88f-fdac22706bb7",
        "id": "9878d192-22ad-49b6-a6c2-9959b0815d04",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0-beta1"
    },
    "data_stream": {
        "dataset": "stan.log",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "9878d192-22ad-49b6-a6c2-9959b0815d04",
        "snapshot": false,
        "version": "8.0.0-beta1"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2022-01-12T04:11:50.063Z",
        "dataset": "stan.log",
        "ingested": "2022-01-12T04:11:50Z",
        "kind": "event",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/stan.log"
        },
        "level": "info",
        "offset": 0
    },
    "message": "STREAM: Starting nats-streaming-server[test-cluster] version 0.15.1",
    "process": {
        "pid": 7
    },
    "stan": {
        "log": {
            "msg": {}
        }
    },
    "tags": [
        "forwarded",
        "stan-log"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| client.port | Port of the client. | long |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.path | Full path to the log file this event came from. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| network.direction | Direction of the network traffic. Recommended values are:   \* ingress   \* egress   \* inbound   \* outbound   \* internal   \* external   \* unknown  When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| process.pid | Process id. | long |
| related.ip | All of the IPs seen on your event. | ip |
| stan.log.client.id | The id of the client | integer |
| stan.log.msg.bytes | Size of the payload in bytes | long |
| stan.log.msg.error.message | Details about the error occurred | text |
| stan.log.msg.max_messages | An optional number of messages to wait for before automatically unsubscribing | integer |
| stan.log.msg.queue_group | The queue group which subscriber will join | text |
| stan.log.msg.reply_to | The inbox subject on which the publisher is listening for responses | keyword |
| stan.log.msg.sid | The unique alphanumeric subscription ID of the subject | integer |
| stan.log.msg.subject | Subject name this message was received on | keyword |
| stan.log.msg.type | The protocol message type | keyword |
| tags | List of keywords used to tag each event. | keyword |


## Metrics

The default datasets are `stats`, `channels`, and `subscriptions`.

### stats

This is the `stats` dataset of the STAN package, in charge of retrieving generic
metrics from a STAN instance.

An example event for `stats` looks as following:

```json
{
    "@timestamp": "2022-01-12T04:12:59.760Z",
    "agent": {
        "ephemeral_id": "6e4beb8a-ccda-438d-b3f4-e89b98e870d8",
        "id": "9878d192-22ad-49b6-a6c2-9959b0815d04",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.0.0-beta1"
    },
    "data_stream": {
        "dataset": "stan.stats",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "1.12.0"
    },
    "elastic_agent": {
        "id": "9878d192-22ad-49b6-a6c2-9959b0815d04",
        "snapshot": false,
        "version": "8.0.0-beta1"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "stan.stats",
        "duration": 15794254,
        "ingested": "2022-01-12T04:13:00Z",
        "module": "stan"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "4ccba669f0df47fa3f57a9e4169ae7f1",
        "ip": [
            "172.18.0.4"
        ],
        "mac": [
            "02:42:ac:12:00:04"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "Core",
            "family": "redhat",
            "kernel": "5.11.0-44-generic",
            "name": "CentOS Linux",
            "platform": "centos",
            "type": "linux",
            "version": "7 (Core)"
        }
    },
    "metricset": {
        "name": "stats",
        "period": 60000
    },
    "service": {
        "address": "http://elastic-package-service-stan-1:8222/streaming/serverz",
        "type": "stan"
    },
    "stan": {
        "cluster": {
            "id": "test-cluster"
        },
        "server": {
            "id": "JQCbrpPJGBxuQGsQ9Yx4Xs"
        },
        "stats": {
            "bytes": 0,
            "channels": 1,
            "clients": 100,
            "messages": 0,
            "state": "STANDALONE",
            "subscriptions": 100
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
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

```json
{
    "@timestamp": "2022-01-12T04:11:05.571Z",
    "agent": {
        "ephemeral_id": "02c989d8-8cf2-4e65-bf07-a8e93785fdaa",
        "id": "9878d192-22ad-49b6-a6c2-9959b0815d04",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.0.0-beta1"
    },
    "data_stream": {
        "dataset": "stan.channels",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "1.12.0"
    },
    "elastic_agent": {
        "id": "9878d192-22ad-49b6-a6c2-9959b0815d04",
        "snapshot": false,
        "version": "8.0.0-beta1"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "stan.channels",
        "duration": 22264899,
        "ingested": "2022-01-12T04:11:06Z",
        "module": "stan"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "4ccba669f0df47fa3f57a9e4169ae7f1",
        "ip": [
            "172.18.0.4"
        ],
        "mac": [
            "02:42:ac:12:00:04"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "Core",
            "family": "redhat",
            "kernel": "5.11.0-44-generic",
            "name": "CentOS Linux",
            "platform": "centos",
            "type": "linux",
            "version": "7 (Core)"
        }
    },
    "metricset": {
        "name": "channels",
        "period": 60000
    },
    "service": {
        "address": "http://elastic-package-service-stan-1:8222/streaming/channelsz?subs=1",
        "type": "stan"
    },
    "stan": {
        "channels": {
            "bytes": 0,
            "depth": 0,
            "first_seq": 0,
            "last_seq": 0,
            "messages": 0,
            "name": "foo"
        },
        "cluster": {
            "id": "test-cluster"
        },
        "server": {
            "id": "dEvzTKomxEioLU6oP1VuXM"
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| stan.channels.bytes | The number of STAN bytes in the channel | long |
| stan.channels.depth | Queue depth based upon current sequence number and highest reported subscriber sequence number | long |
| stan.channels.first_seq | First sequence number stored in the channel. If first_seq \> min([seq in subscriptions]) data loss has possibly occurred | long |
| stan.channels.last_seq | Last sequence number stored in the channel | long |
| stan.channels.messages | The number of STAN streaming messages | long |
| stan.channels.name | The name of the STAN streaming channel | keyword |
| stan.cluster.id | The cluster ID | keyword |
| stan.server.id | The server ID | keyword |


### subscriptions

This is the `subscriptions` dataset of the STAN package, in charge of retrieving
metrics about subscriptions from a STAN instance.

An example event for `subscriptions` looks as following:

```json
{
    "@timestamp": "2022-01-12T04:13:52.133Z",
    "agent": {
        "ephemeral_id": "edb669a5-3b36-43d7-8190-d485d6517f69",
        "id": "9878d192-22ad-49b6-a6c2-9959b0815d04",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.0.0-beta1"
    },
    "data_stream": {
        "dataset": "stan.subscriptions",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "1.12.0"
    },
    "elastic_agent": {
        "id": "9878d192-22ad-49b6-a6c2-9959b0815d04",
        "snapshot": false,
        "version": "8.0.0-beta1"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "stan.subscriptions",
        "duration": 6243276,
        "ingested": "2022-01-12T04:13:53Z",
        "module": "stan"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "4ccba669f0df47fa3f57a9e4169ae7f1",
        "ip": [
            "172.18.0.4"
        ],
        "mac": [
            "02:42:ac:12:00:04"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "Core",
            "family": "redhat",
            "kernel": "5.11.0-44-generic",
            "name": "CentOS Linux",
            "platform": "centos",
            "type": "linux",
            "version": "7 (Core)"
        }
    },
    "metricset": {
        "name": "subscriptions",
        "period": 60000
    },
    "service": {
        "address": "http://elastic-package-service-stan-1:8222/streaming/channelsz?subs=1",
        "type": "stan"
    },
    "stan": {
        "cluster": {
            "id": "test-cluster"
        },
        "server": {
            "id": "NevWjtY7nB1yzea8TtJaGb"
        },
        "subscriptions": {
            "channel": "foo",
            "id": "benchmark-sub-25",
            "last_sent": 0,
            "offline": false,
            "pending": 0,
            "queue": "T",
            "stalled": false
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| stan.cluster.id | The cluster ID | keyword |
| stan.server.id | The server ID | keyword |
| stan.subscriptions.channel | The name of the STAN channel the subscription is associated with | keyword |
| stan.subscriptions.id | The name of the STAN channel subscription (client_id) | keyword |
| stan.subscriptions.last_sent | Last known sequence number of the subscription that was acked | long |
| stan.subscriptions.offline | Is the subscriber marked as offline? | boolean |
| stan.subscriptions.pending | Number of pending messages from / to the subscriber | long |
| stan.subscriptions.queue | The name of the NATS queue that the STAN channel subscription is associated with, if any | keyword |
| stan.subscriptions.stalled | Is the subscriber known to be stalled? | boolean |
