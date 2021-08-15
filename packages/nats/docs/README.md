# NATS integration

This integration is used to collect logs and metrics from [NATS servers](https://nats.io/).
The integration collects metrics from [NATS monitoring server APIs](https://nats.io/documentation/managing_the_server/monitoring/).


## Compatibility

The Nats package is tested with Nats 1.3.0, 2.0.4 and 2.1.4

## Logs

### log

The `log` dataset collects the NATS logs.

An example event for `log` looks as following:

```json
{
    "nats": {
        "log": {
            "msg": {
                "type": "payload"
            },
            "client": {
                "id": "86"
            }
        }
    },
    "agent": {
        "hostname": "5706c620a165",
        "name": "5706c620a165",
        "id": "25c804ef-d8c8-4a2e-9228-64213daef566",
        "type": "filebeat",
        "ephemeral_id": "4f1426bb-db10-4b5d-9e1c-ba6da401dc34",
        "version": "7.11.0"
    },
    "process": {
        "pid": 6
    },
    "log": {
        "file": {
            "path": "/var/log/nats/nats.log"
        },
        "offset": 36865655,
        "level": "trace"
    },
    "elastic_agent": {
        "id": "5a7b52c1-66ae-47ce-ad18-70dadf1bedfa",
        "version": "7.11.0",
        "snapshot": true
    },
    "network": {
        "direction": "inbound"
    },
    "input": {
        "type": "log"
    },
    "@timestamp": "2020-11-25T11:50:17.759Z",
    "ecs": {
        "version": "1.6.0"
    },
    "related": {
        "ip": [
            "192.168.192.3"
        ]
    },
    "data_stream": {
        "namespace": "default",
        "type": "logs",
        "dataset": "nats.log"
    },
    "host": {
        "hostname": "5706c620a165",
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
            "192.168.192.8"
        ],
        "name": "5706c620a165",
        "id": "06c26569966fd125c15acac5d7feffb6",
        "mac": [
            "02:42:c0:a8:c0:08"
        ],
        "architecture": "x86_64"
    },
    "client": {
        "port": 53482,
        "ip": "192.168.192.3"
    },
    "event": {
        "ingested": "2020-11-25T11:53:10.021181400Z",
        "created": "2020-11-25T11:53:04.192Z",
        "kind": "event",
        "type": [
            "info"
        ],
        "dataset": "nats.log"
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
| nats.log.client.id | The id of the client | integer |
| nats.log.msg.bytes | Size of the payload in bytes | long |
| nats.log.msg.error.message | Details about the error occurred | text |
| nats.log.msg.max_messages | An optional number of messages to wait for before automatically unsubscribing | integer |
| nats.log.msg.queue_group | The queue group which subscriber will join | text |
| nats.log.msg.reply_to | The inbox subject on which the publisher is listening for responses | keyword |
| nats.log.msg.sid | The unique alphanumeric subscription ID of the subject | integer |
| nats.log.msg.subject | Subject name this message was received on | keyword |
| nats.log.msg.type | The protocol message type | keyword |
| network.direction | Direction of the network traffic. Recommended values are:   \* ingress   \* egress   \* inbound   \* outbound   \* internal   \* external   \* unknown  When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| process.pid | Process id. | long |
| related.ip | All of the IPs seen on your event. | ip |
| tags | List of keywords used to tag each event. | keyword |


## Metrics

The default datasets are `stats`, `connections`, `routes` and `subscriptions` while `connection` and `route`
datasets can be enabled to collect detailed metrics per connection/route.

### stats

This is the `stats` dataset of the Nats package, in charge of retrieving generic
metrics from a Nats instance.


An example event for `stats` looks as following:

```json
{
    "@timestamp": "2020-11-25T11:55:12.889Z",
    "agent": {
        "version": "7.11.0",
        "hostname": "5706c620a165",
        "ephemeral_id": "faba036b-68bf-4ea8-a1f1-78c6e61dce6c",
        "id": "5f6fe0bb-58aa-43bb-99ef-385eb36c0e8a",
        "name": "5706c620a165",
        "type": "metricbeat"
    },
    "ecs": {
        "version": "1.6.0"
    },
    "host": {
        "ip": [
            "192.168.192.8"
        ],
        "mac": [
            "02:42:c0:a8:c0:08"
        ],
        "hostname": "5706c620a165",
        "architecture": "x86_64",
        "os": {
            "version": "7 (Core)",
            "family": "redhat",
            "name": "CentOS Linux",
            "kernel": "4.9.184-linuxkit",
            "codename": "Core",
            "platform": "centos"
        },
        "id": "06c26569966fd125c15acac5d7feffb6",
        "name": "5706c620a165",
        "containerized": true
    },
    "metricset": {
        "name": "stats",
        "period": 10000
    },
    "nats": {
        "stats": {
            "cores": 8,
            "cpu": 0,
            "total_connections": 158,
            "out": {
                "messages": 0,
                "bytes": 0
            },
            "in": {
                "messages": 136883,
                "bytes": 2190128
            },
            "slow_consumers": 0,
            "mem": {
                "bytes": 12308480
            },
            "uptime": 780,
            "remotes": 1,
            "http": {
                "req_stats": {
                    "uri": {
                        "subsz": 65,
                        "varz": 65,
                        "root": 0,
                        "connz": 130,
                        "routez": 130
                    }
                }
            }
        },
        "server": {
            "id": "NAOMPZQ3UW6A57N3UKBKFVTZLNWZCCS6OUGV3XXEQPFZ5BE5M52CDGVL",
            "time": "2020-11-25T11:55:12.8894258Z"
        }
    },
    "elastic_agent": {
        "version": "7.11.0",
        "id": "5a7b52c1-66ae-47ce-ad18-70dadf1bedfa",
        "snapshot": true
    },
    "event": {
        "dataset": "nats.stats",
        "module": "nats",
        "duration": 1323200
    },
    "service": {
        "address": "http://nats:8222/varz",
        "type": "nats"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "nats.stats"
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
| nats.server.id | The server ID | keyword |
| nats.server.time | Server time of metric creation | date |
| nats.stats.cores | The number of logical cores the NATS process runs on | integer |
| nats.stats.cpu | The current cpu usage of NATs process | scaled_float |
| nats.stats.http.req_stats.uri.connz | The number of hits on connz monitoring uri | long |
| nats.stats.http.req_stats.uri.root | The number of hits on root monitoring uri | long |
| nats.stats.http.req_stats.uri.routez | The number of hits on routez monitoring uri | long |
| nats.stats.http.req_stats.uri.subsz | The number of hits on subsz monitoring uri | long |
| nats.stats.http.req_stats.uri.varz | The number of hits on varz monitoring uri | long |
| nats.stats.in.bytes | The amount of incoming bytes | long |
| nats.stats.in.messages | The amount of incoming messages | long |
| nats.stats.mem.bytes | The current memory usage of NATS process | long |
| nats.stats.out.bytes | The amount of outgoing bytes | long |
| nats.stats.out.messages | The amount of outgoing messages | long |
| nats.stats.remotes | The number of registered remotes | integer |
| nats.stats.slow_consumers | The number of slow consumers currently on NATS | long |
| nats.stats.total_connections | The number of totally created clients | long |
| nats.stats.uptime | The period the server is up (sec) | long |
| service.address | Service address | keyword |
| service.type | Service type | keyword |


### connections

This is the `connections` dataset of the Nats package, in charge of retrieving generic
metrics about connections from a Nats instance.

An example event for `connections` looks as following:

```json
{
    "@timestamp": "2020-11-25T11:55:32.849Z",
    "metricset": {
        "name": "connections",
        "period": 10000
    },
    "service": {
        "address": "http://nats:8222/connz",
        "type": "nats"
    },
    "data_stream": {
        "dataset": "nats.connections",
        "namespace": "default",
        "type": "metrics"
    },
    "ecs": {
        "version": "1.6.0"
    },
    "agent": {
        "hostname": "5706c620a165",
        "ephemeral_id": "faba036b-68bf-4ea8-a1f1-78c6e61dce6c",
        "id": "5f6fe0bb-58aa-43bb-99ef-385eb36c0e8a",
        "name": "5706c620a165",
        "type": "metricbeat",
        "version": "7.11.0"
    },
    "nats": {
        "server": {
            "id": "NAOMPZQ3UW6A57N3UKBKFVTZLNWZCCS6OUGV3XXEQPFZ5BE5M52CDGVL",
            "time": "2020-11-25T11:55:32.8490791Z"
        },
        "connections": {
            "total": 0
        }
    },
    "elastic_agent": {
        "id": "5a7b52c1-66ae-47ce-ad18-70dadf1bedfa",
        "snapshot": true,
        "version": "7.11.0"
    },
    "host": {
        "hostname": "5706c620a165",
        "architecture": "x86_64",
        "os": {
            "platform": "centos",
            "version": "7 (Core)",
            "family": "redhat",
            "name": "CentOS Linux",
            "kernel": "4.9.184-linuxkit",
            "codename": "Core"
        },
        "name": "5706c620a165",
        "id": "06c26569966fd125c15acac5d7feffb6",
        "containerized": true,
        "ip": [
            "192.168.192.8"
        ],
        "mac": [
            "02:42:c0:a8:c0:08"
        ]
    },
    "event": {
        "dataset": "nats.connections",
        "module": "nats",
        "duration": 2287200
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
| nats.connections.total | The number of currently active clients | integer |
| nats.server.id | The server ID | keyword |
| nats.server.time | Server time of metric creation | date |
| service.address | Service address | keyword |
| service.type | Service type | keyword |


### routes

This is the `routes` dataset of the Nats package, in charge of retrieving generic
metrics about routes from a Nats instance.

An example event for `routes` looks as following:

```json
{
    "@timestamp": "2020-11-25T11:54:52.887Z",
    "event": {
        "dataset": "nats.routes",
        "module": "nats",
        "duration": 2796500
    },
    "data_stream": {
        "type": "metrics",
        "dataset": "nats.routes",
        "namespace": "default"
    },
    "host": {
        "os": {
            "kernel": "4.9.184-linuxkit",
            "codename": "Core",
            "platform": "centos",
            "version": "7 (Core)",
            "family": "redhat",
            "name": "CentOS Linux"
        },
        "id": "06c26569966fd125c15acac5d7feffb6",
        "containerized": true,
        "ip": [
            "192.168.192.8"
        ],
        "mac": [
            "02:42:c0:a8:c0:08"
        ],
        "hostname": "5706c620a165",
        "architecture": "x86_64",
        "name": "5706c620a165"
    },
    "elastic_agent": {
        "version": "7.11.0",
        "id": "5a7b52c1-66ae-47ce-ad18-70dadf1bedfa",
        "snapshot": true
    },
    "agent": {
        "ephemeral_id": "faba036b-68bf-4ea8-a1f1-78c6e61dce6c",
        "id": "5f6fe0bb-58aa-43bb-99ef-385eb36c0e8a",
        "name": "5706c620a165",
        "type": "metricbeat",
        "version": "7.11.0",
        "hostname": "5706c620a165"
    },
    "ecs": {
        "version": "1.6.0"
    },
    "metricset": {
        "name": "routes",
        "period": 10000
    },
    "service": {
        "type": "nats",
        "address": "http://nats:8222/routez"
    },
    "nats": {
        "routes": {
            "total": 1
        },
        "server": {
            "time": "2020-11-25T11:54:52.8871762Z",
            "id": "NAOMPZQ3UW6A57N3UKBKFVTZLNWZCCS6OUGV3XXEQPFZ5BE5M52CDGVL"
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
| nats.routes.total | The number of registered routes | integer |
| nats.server.id | The server ID | keyword |
| nats.server.time | Server time of metric creation | date |
| service.address | Service address | keyword |
| service.type | Service type | keyword |


### subscriptions

This is the `subscriptions` dataset of the Nats package, in charge of retrieving
metrics about subscriptions from a Nats instance.

An example event for `subscriptions` looks as following:

```json
{
    "@timestamp": "2020-11-25T11:56:12.814Z",
    "service": {
        "address": "http://nats:8222/subsz",
        "type": "nats"
    },
    "metricset": {
        "name": "subscriptions",
        "period": 10000
    },
    "data_stream": {
        "dataset": "nats.subscriptions",
        "namespace": "default",
        "type": "metrics"
    },
    "event": {
        "dataset": "nats.subscriptions",
        "module": "nats",
        "duration": 2620000
    },
    "nats": {
        "subscriptions": {
            "removes": 0,
            "matches": 171,
            "total": 0,
            "cache": {
                "size": 4,
                "hit_rate": 0.9766081871345029,
                "fanout": {
                    "max": 0,
                    "avg": 0
                }
            },
            "inserts": 0
        }
    },
    "elastic_agent": {
        "version": "7.11.0",
        "id": "5a7b52c1-66ae-47ce-ad18-70dadf1bedfa",
        "snapshot": true
    },
    "host": {
        "name": "5706c620a165",
        "mac": [
            "02:42:c0:a8:c0:08"
        ],
        "hostname": "5706c620a165",
        "architecture": "x86_64",
        "os": {
            "name": "CentOS Linux",
            "kernel": "4.9.184-linuxkit",
            "codename": "Core",
            "platform": "centos",
            "version": "7 (Core)",
            "family": "redhat"
        },
        "id": "06c26569966fd125c15acac5d7feffb6",
        "containerized": true,
        "ip": [
            "192.168.192.8"
        ]
    },
    "agent": {
        "name": "5706c620a165",
        "type": "metricbeat",
        "version": "7.11.0",
        "hostname": "5706c620a165",
        "ephemeral_id": "faba036b-68bf-4ea8-a1f1-78c6e61dce6c",
        "id": "5f6fe0bb-58aa-43bb-99ef-385eb36c0e8a"
    },
    "ecs": {
        "version": "1.6.0"
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
| nats.server.id | The server ID | keyword |
| nats.server.time | Server time of metric creation | date |
| nats.subscriptions.cache.fanout.avg | The average fanout served by cache | double |
| nats.subscriptions.cache.fanout.max | The maximum fanout served by cache | integer |
| nats.subscriptions.cache.hit_rate | The rate matches are being retrieved from cache | scaled_float |
| nats.subscriptions.cache.size | The number of result sets in the cache | integer |
| nats.subscriptions.inserts | The number of insert operations in subscriptions list | long |
| nats.subscriptions.matches | The number of times a match is found for a subscription | long |
| nats.subscriptions.removes | The number of remove operations in subscriptions list | long |
| nats.subscriptions.total | The number of active subscriptions | integer |
| service.address | Service address | keyword |
| service.type | Service type | keyword |


### connection

This is the `connection` dataset of the Nats package, in charge of retrieving detailed
metrics per connection from a Nats instance.

An example event for `connection` looks as following:

```json
{
    "@timestamp": "2020-11-25T11:55:52.814Z",
    "service": {
        "address": "http://nats:8222/connz",
        "type": "nats"
    },
    "nats": {
        "server": {
            "id": "NAOMPZQ3UW6A57N3UKBKFVTZLNWZCCS6OUGV3XXEQPFZ5BE5M52CDGVL"
        },
        "connection": {
            "out": {
                "messages": 0,
                "bytes": 0
            },
            "pending_bytes": 0,
            "uptime": 12,
            "idle_time": 6,
            "name": "NATS Benchmark",
            "subscriptions": 0,
            "in": {
                "messages": 2167,
                "bytes": 34672
            }
        }
    },
    "elastic_agent": {
        "version": "7.11.0",
        "id": "5a7b52c1-66ae-47ce-ad18-70dadf1bedfa",
        "snapshot": true
    },
    "agent": {
        "id": "5f6fe0bb-58aa-43bb-99ef-385eb36c0e8a",
        "name": "5706c620a165",
        "type": "metricbeat",
        "version": "7.11.0",
        "hostname": "5706c620a165",
        "ephemeral_id": "faba036b-68bf-4ea8-a1f1-78c6e61dce6c"
    },
    "host": {
        "mac": [
            "02:42:c0:a8:c0:08"
        ],
        "hostname": "5706c620a165",
        "architecture": "x86_64",
        "os": {
            "platform": "centos",
            "version": "7 (Core)",
            "family": "redhat",
            "name": "CentOS Linux",
            "kernel": "4.9.184-linuxkit",
            "codename": "Core"
        },
        "id": "06c26569966fd125c15acac5d7feffb6",
        "containerized": true,
        "ip": [
            "192.168.192.8"
        ],
        "name": "5706c620a165"
    },
    "event": {
        "module": "nats",
        "duration": 8447800,
        "dataset": "nats.connection"
    },
    "metricset": {
        "name": "connection",
        "period": 10000
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "nats.connection"
    },
    "ecs": {
        "version": "1.6.0"
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
| nats.connection.idle_time | The period the connection is idle (sec) | long |
| nats.connection.in.bytes | The amount of incoming bytes | long |
| nats.connection.in.messages | The amount of incoming messages | long |
| nats.connection.name | The name of the connection | keyword |
| nats.connection.out.bytes | The amount of outgoing bytes | long |
| nats.connection.out.messages | The amount of outgoing messages | long |
| nats.connection.pending_bytes | The number of pending bytes of this connection | long |
| nats.connection.subscriptions | The number of subscriptions in this connection | integer |
| nats.connection.uptime | The period the connection is up (sec) | long |
| nats.server.id | The server ID | keyword |
| nats.server.time | Server time of metric creation | date |
| service.address | Service address | keyword |
| service.type | Service type | keyword |


### route

This is the `route` dataset of the Nats package, in charge of retrieving detailed
metric per route from a Nats instance.

An example event for `route` looks as following:

```json
{
    "@timestamp": "2020-11-25T11:54:22.920Z",
    "service": {
        "address": "http://nats:8222/routez",
        "type": "nats"
    },
    "event": {
        "duration": 2391000,
        "dataset": "nats.route",
        "module": "nats"
    },
    "data_stream": {
        "dataset": "nats.route",
        "namespace": "default",
        "type": "metrics"
    },
    "elastic_agent": {
        "id": "5a7b52c1-66ae-47ce-ad18-70dadf1bedfa",
        "snapshot": true,
        "version": "7.11.0"
    },
    "agent": {
        "ephemeral_id": "faba036b-68bf-4ea8-a1f1-78c6e61dce6c",
        "id": "5f6fe0bb-58aa-43bb-99ef-385eb36c0e8a",
        "name": "5706c620a165",
        "type": "metricbeat",
        "version": "7.11.0",
        "hostname": "5706c620a165"
    },
    "metricset": {
        "name": "route",
        "period": 10000
    },
    "nats": {
        "server": {
            "id": "NAOMPZQ3UW6A57N3UKBKFVTZLNWZCCS6OUGV3XXEQPFZ5BE5M52CDGVL"
        },
        "route": {
            "in": {
                "messages": 0,
                "bytes": 0
            },
            "out": {
                "messages": 0,
                "bytes": 0
            },
            "pending_size": 0,
            "port": 55276,
            "ip": "192.168.192.4",
            "remote_id": "NAEKG72UKB5SS3MH27LLWTVUXUWXIKRAX5ZCXVVBZT7SC6LKBBNSNDQY",
            "subscriptions": 0
        }
    },
    "ecs": {
        "version": "1.6.0"
    },
    "host": {
        "id": "06c26569966fd125c15acac5d7feffb6",
        "containerized": true,
        "name": "5706c620a165",
        "ip": [
            "192.168.192.8"
        ],
        "mac": [
            "02:42:c0:a8:c0:08"
        ],
        "hostname": "5706c620a165",
        "architecture": "x86_64",
        "os": {
            "version": "7 (Core)",
            "family": "redhat",
            "name": "CentOS Linux",
            "kernel": "4.9.184-linuxkit",
            "codename": "Core",
            "platform": "centos"
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
| nats.route.in.bytes | The amount of incoming bytes | long |
| nats.route.in.messages | The amount of incoming messages | long |
| nats.route.ip | The ip of the route | ip |
| nats.route.out.bytes | The amount of outgoing bytes | long |
| nats.route.out.messages | The amount of outgoing messages | long |
| nats.route.pending_size | The number of pending routes | long |
| nats.route.port | The port of the route | integer |
| nats.route.remote_id | The remote id on which the route is connected to | keyword |
| nats.route.subscriptions | The number of subscriptions in this connection | integer |
| nats.server.id | The server ID | keyword |
| nats.server.time | Server time of metric creation | date |
| service.address | Service address | keyword |
| service.type | Service type | keyword |

