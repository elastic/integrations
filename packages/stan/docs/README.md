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
    "agent": {
        "hostname": "4d0d8c0f4097",
        "name": "4d0d8c0f4097",
        "id": "10a38439-cfb3-4e2f-b4a3-b06707eed149",
        "type": "filebeat",
        "ephemeral_id": "39abf1ff-8ee3-41b5-a553-0af2f121da94",
        "version": "7.11.0"
    },
    "process": {
        "pid": 7
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/stan.log"
        },
        "offset": 2064548,
        "level": "trace"
    },
    "elastic_agent": {
        "id": "d5178560-572f-11eb-a5fc-9bbf29f84abb",
        "version": "7.11.0",
        "snapshot": true
    },
    "network": {
        "direction": "inbound"
    },
    "input": {
        "type": "log"
    },
    "@timestamp": "2021-01-15T13:12:07.170Z",
    "ecs": {
        "version": "1.6.0"
    },
    "related": {
        "ip": [
            "127.0.0.1"
        ]
    },
    "data_stream": {
        "namespace": "default",
        "type": "logs",
        "dataset": "stan.log"
    },
    "host": {
        "hostname": "4d0d8c0f4097",
        "os": {
            "kernel": "4.9.184-linuxkit",
            "codename": "Core",
            "name": "CentOS Linux",
            "family": "redhat",
            "version": "7 (Core)",
            "platform": "centos"
        },
        "containerized": true,
        "ip": [
            "172.21.0.6"
        ],
        "name": "4d0d8c0f4097",
        "id": "88c3c3ec3afebed7631b44a69754359e",
        "mac": [
            "02:42:ac:15:00:06"
        ],
        "architecture": "x86_64"
    },
    "stan": {
        "log": {
            "msg": {
                "reply_to": "_INBOX.1wOArhLwRni1eXXhnUaD8i.LMRmCG50",
                "bytes": 79,
                "subject": "_STAN.discover.test-cluster",
                "type": "publish"
            },
            "client": {
                "id": "930"
            }
        }
    },
    "client": {
        "port": 50558,
        "ip": "127.0.0.1"
    },
    "event": {
        "ingested": "2021-01-15T13:12:08.891587159Z",
        "created": "2021-01-15T13:12:07.260Z",
        "kind": "event",
        "type": [
            "info"
        ],
        "dataset": "stan.log"
    }
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
| error.message | Error message. | text |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.path | Full path to the log file this event came from. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | text |
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
    "@timestamp": "2021-01-15T12:26:32.467Z",
    "service": {
        "address": "http://elastic-package-service_stan_1:8222/streaming/serverz",
        "type": "stan"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "stan.stats"
    },
    "ecs": {
        "version": "1.7.0"
    },
    "host": {
        "mac": [
            "02:42:ac:13:00:05"
        ],
        "name": "ec072aa02d8b",
        "hostname": "ec072aa02d8b",
        "architecture": "x86_64",
        "os": {
            "version": "7 (Core)",
            "family": "redhat",
            "name": "CentOS Linux",
            "kernel": "4.9.184-linuxkit",
            "codename": "Core",
            "platform": "centos"
        },
        "id": "88c3c3ec3afebed7631b44a69754359e",
        "containerized": true,
        "ip": [
            "172.19.0.5"
        ]
    },
    "agent": {
        "version": "7.11.0",
        "hostname": "ec072aa02d8b",
        "ephemeral_id": "8d73aff0-201b-4260-9e89-cd519348de03",
        "id": "67b9c377-7d0c-4a69-9351-2befe6386fbd",
        "name": "ec072aa02d8b",
        "type": "metricbeat"
    },
    "event": {
        "dataset": "stan.stats",
        "module": "stan",
        "duration": 1252350
    },
    "metricset": {
        "name": "stats",
        "period": 60000
    },
    "stan": {
        "cluster": {
            "id": "test-cluster"
        },
        "stats": {
            "subscriptions": 4,
            "channels": 4,
            "messages": 4990,
            "bytes": 5214423,
            "state": "STANDALONE",
            "clients": 100
        },
        "server": {
            "id": "kvQEpbFak88fHAnWCZxZDL"
        }
    },
    "elastic_agent": {
        "id": "df58bff0-5714-11eb-b094-915beebb3c66",
        "snapshot": true,
        "version": "7.11.0"
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
| ecs.version | ECS version | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| service.address | Service address | keyword |
| service.type | Service type | keyword |
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
    "@timestamp": "2021-01-15T12:23:32.592Z",
    "service": {
        "address": "http://elastic-package-service_stan_1:8222/streaming/channelsz?subs=1",
        "type": "stan"
    },
    "event": {
        "duration": 8406132380,
        "dataset": "stan.channels",
        "module": "stan"
    },
    "metricset": {
        "name": "channels",
        "period": 60000
    },
    "stan": {
        "cluster": {
            "id": "test-cluster"
        },
        "server": {
            "id": "kvQEpbFak88fHAnWCZxZDL"
        },
        "channels": {
            "depth": 3966,
            "name": "bar",
            "messages": 4990,
            "bytes": 5214423,
            "first_seq": 1,
            "last_seq": 4990
        }
    },
    "elastic_agent": {
        "version": "7.11.0",
        "id": "df58bff0-5714-11eb-b094-915beebb3c66",
        "snapshot": true
    },
    "ecs": {
        "version": "1.7.0"
    },
    "data_stream": {
        "type": "metrics",
        "dataset": "stan.channels",
        "namespace": "default"
    },
    "host": {
        "architecture": "x86_64",
        "os": {
            "kernel": "4.9.184-linuxkit",
            "codename": "Core",
            "platform": "centos",
            "version": "7 (Core)",
            "family": "redhat",
            "name": "CentOS Linux"
        },
        "id": "88c3c3ec3afebed7631b44a69754359e",
        "name": "ec072aa02d8b",
        "containerized": true,
        "ip": [
            "172.19.0.5"
        ],
        "mac": [
            "02:42:ac:13:00:05"
        ],
        "hostname": "ec072aa02d8b"
    },
    "agent": {
        "version": "7.11.0",
        "hostname": "ec072aa02d8b",
        "ephemeral_id": "8d73aff0-201b-4260-9e89-cd519348de03",
        "id": "67b9c377-7d0c-4a69-9351-2befe6386fbd",
        "name": "ec072aa02d8b",
        "type": "metricbeat"
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
| ecs.version | ECS version | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| service.address | Service address | keyword |
| service.type | Service type | keyword |
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
    "@timestamp": "2021-01-15T12:25:32.509Z",
    "ecs": {
        "version": "1.7.0"
    },
    "agent": {
        "ephemeral_id": "8d73aff0-201b-4260-9e89-cd519348de03",
        "id": "67b9c377-7d0c-4a69-9351-2befe6386fbd",
        "name": "ec072aa02d8b",
        "type": "metricbeat",
        "version": "7.11.0",
        "hostname": "ec072aa02d8b"
    },
    "metricset": {
        "name": "subscriptions",
        "period": 60000
    },
    "data_stream": {
        "type": "metrics",
        "dataset": "stan.subscriptions",
        "namespace": "default"
    },
    "elastic_agent": {
        "version": "7.11.0",
        "id": "df58bff0-5714-11eb-b094-915beebb3c66",
        "snapshot": true
    },
    "host": {
        "architecture": "x86_64",
        "name": "ec072aa02d8b",
        "os": {
            "kernel": "4.9.184-linuxkit",
            "codename": "Core",
            "platform": "centos",
            "version": "7 (Core)",
            "family": "redhat",
            "name": "CentOS Linux"
        },
        "id": "88c3c3ec3afebed7631b44a69754359e",
        "containerized": true,
        "ip": [
            "172.19.0.5"
        ],
        "mac": [
            "02:42:ac:13:00:05"
        ],
        "hostname": "ec072aa02d8b"
    },
    "event": {
        "dataset": "stan.subscriptions",
        "module": "stan",
        "duration": 935334325
    },
    "service": {
        "address": "http://elastic-package-service_stan_1:8222/streaming/channelsz?subs=1",
        "type": "stan"
    },
    "stan": {
        "subscriptions": {
            "stalled": true,
            "pending": 1024,
            "id": "benchmark-sub-1",
            "channel": "bar",
            "last_sent": 1024,
            "offline": true
        },
        "server": {
            "id": "kvQEpbFak88fHAnWCZxZDL"
        },
        "cluster": {
            "id": "test-cluster"
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
| ecs.version | ECS version | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| service.address | Service address | keyword |
| service.type | Service type | keyword |
| stan.cluster.id | The cluster ID | keyword |
| stan.server.id | The server ID | keyword |
| stan.subscriptions.channel | The name of the STAN channel the subscription is associated with | keyword |
| stan.subscriptions.id | The name of the STAN channel subscription (client_id) | keyword |
| stan.subscriptions.last_sent | Last known sequence number of the subscription that was acked | long |
| stan.subscriptions.offline | Is the subscriber marked as offline? | boolean |
| stan.subscriptions.pending | Number of pending messages from / to the subscriber | long |
| stan.subscriptions.queue | The name of the NATS queue that the STAN channel subscription is associated with, if any | keyword |
| stan.subscriptions.stalled | Is the subscriber known to be stalled? | boolean |
