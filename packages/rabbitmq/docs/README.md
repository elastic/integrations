# RabbitMQ Integration

This integration uses [HTTP API](http://www.rabbitmq.com/management.html) created by the management plugin to collect metrics.

The default data streams are `connection`, `node`, `queue`, `exchange` and standard logs.

If `management.path_prefix` is set in RabbitMQ configuration, management_path_prefix has to be set to the same value
in this integration configuration.

## Compatibility

The RabbitMQ integration is fully tested with RabbitMQ 3.7.4 and it should be compatible with any version supporting
the management plugin (which needs to be installed and enabled). Exchange dataset is also tested with 3.6.0, 3.6.5 and 3.7.14.

The application logs dataset parses single file format introduced in 3.7.0.

## Logs

### Application Logs

Application logs collects standard RabbitMQ logs.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
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
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| rabbitmq.log.pid | The Erlang process id | keyword |
| tags | List of keywords used to tag each event. | keyword |


## Metrics

### Connection Metrics

An example event for `connection` looks as following:

```json
{
    "@timestamp": "2020-06-25T10:16:10.138Z",
    "rabbitmq": {
        "vhost": "/",
        "connection": {
            "channel_max": 65535,
            "channels": 2,
            "client_provided": {
                "name": "Connection1"
            },
            "frame_max": 131072,
            "host": "::1",
            "name": "[::1]:31153 -\u003e [::1]:5672",
            "octet_count": {
                "received": 5834,
                "sent": 5834
            },
            "packet_count": {
                "pending": 0,
                "received": 442,
                "sent": 422
            },
            "peer": {
                "host": "::1",
                "port": 31153
            },
            "port": 5672,
            "state": "running",
            "type": "network"
        }
    },
    "event": {
        "duration": 374411,
        "dataset": "rabbitmq.connection",
        "module": "rabbitmq"
    },
    "metricset": {
        "name": "connection",
        "period": 10000
    },
    "service": {
        "address": "localhost:15672",
        "type": "rabbitmq"
    },
    "ecs": {
        "version": "1.5.0"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
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
| rabbitmq.connection.channel_max | The maximum number of channels allowed on the connection. | long |
| rabbitmq.connection.channels | The number of channels on the connection. | long |
| rabbitmq.connection.client_provided.name | User specified connection name. | keyword |
| rabbitmq.connection.frame_max | Maximum permissible size of a frame (in bytes) to negotiate with clients. | long |
| rabbitmq.connection.host | Server hostname obtained via reverse DNS, or its IP address if reverse DNS failed or was disabled. | keyword |
| rabbitmq.connection.name | The name of the connection with non-ASCII characters escaped as in C. | keyword |
| rabbitmq.connection.octet_count.received | Number of octets received on the connection. | long |
| rabbitmq.connection.octet_count.sent | Number of octets sent on the connection. | long |
| rabbitmq.connection.packet_count.pending | Number of packets pending on the connection. | long |
| rabbitmq.connection.packet_count.received | Number of packets received on the connection. | long |
| rabbitmq.connection.packet_count.sent | Number of packets sent on the connection. | long |
| rabbitmq.connection.peer.host | Peer hostname obtained via reverse DNS, or its IP address if reverse DNS failed or was not enabled. | keyword |
| rabbitmq.connection.peer.port | Peer port. | long |
| rabbitmq.connection.port | Server port. | long |
| rabbitmq.connection.state | Connection state. | keyword |
| rabbitmq.connection.type | Type of the connection. | keyword |
| rabbitmq.vhost | Virtual host name with non-ASCII characters escaped as in C. | keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| user | The user fields describe information about the user that is relevant to the event. Fields can have one entry or multiple entries. If a user has more than one id, provide an array that includes all of them. | group |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |


### Exchange Metrics

An example event for `exchange` looks as following:

```json
{
    "@timestamp": "2020-06-25T10:04:20.944Z",
    "rabbitmq": {
        "vhost": "/",
        "exchange": {
            "arguments": {},
            "durable": true,
            "auto_delete": false,
            "name": "",
            "internal": false
        }
    },
    "event": {
        "duration": 4078507,
        "dataset": "rabbitmq.exchange",
        "module": "rabbitmq"
    },
    "metricset": {
        "name": "exchange",
        "period": 10000
    },
    "user": {
        "name": "rmq-internal"
    },
    "service": {
        "address": "localhost:15672",
        "type": "rabbitmq"
    },
    "ecs": {
        "version": "1.5.0"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
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
| rabbitmq.exchange.auto_delete | Whether the queue will be deleted automatically when no longer used. | boolean |
| rabbitmq.exchange.durable | Whether or not the queue survives server restarts. | boolean |
| rabbitmq.exchange.internal | Whether the exchange is internal, i.e. cannot be directly published to by a client. | boolean |
| rabbitmq.exchange.messages.publish_in.count | Count of messages published "in" to an exchange, i.e. not taking account of routing. | long |
| rabbitmq.exchange.messages.publish_in.details.rate | How much the exchange publish-in count has changed per second in the most recent sampling interval. | float |
| rabbitmq.exchange.messages.publish_out.count | Count of messages published "out" of an exchange, i.e. taking account of routing. | long |
| rabbitmq.exchange.messages.publish_out.details.rate | How much the exchange publish-out count has changed per second in the most recent sampling interval. | float |
| rabbitmq.exchange.name | The name of the queue with non-ASCII characters escaped as in C. | keyword |
| rabbitmq.vhost | Virtual host name with non-ASCII characters escaped as in C. | keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| user | The user fields describe information about the user that is relevant to the event. Fields can have one entry or multiple entries. If a user has more than one id, provide an array that includes all of them. | group |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |


### Node Metrics

The "node" dataset collects metrics about RabbitMQ nodes.

It supports two modes to collect data which can be selected with the "Collection mode" setting:

* `node` - collects metrics only from the node the agent connects to.
* `cluster` - collects metrics from all the nodes in the cluster. This is recommended when collecting metrics of an only endpoint for the whole cluster.

An example event for `node` looks as following:

```json
{
    "@timestamp": "2020-06-25T10:04:20.944Z",
    "event": {
        "dataset": "rabbitmq.node",
        "duration": 115000,
        "module": "rabbitmq"
    },
    "rabbitmq": {
        "node": {
            "disk": {
                "free": {
                    "bytes": 485213712384,
                    "limit": {
                        "bytes": 50000000
                    }
                }
            },
            "fd": {
                "total": 1048576,
                "used": 54
            },
            "gc": {
                "num": {
                    "count": 5724
                },
                "reclaimed": {
                    "bytes": 294021640
                }
            },
            "io": {
                "file_handle": {
                    "open_attempt": {
                        "avg": {
                            "ms": 0
                        },
                        "count": 10
                    }
                },
                "read": {
                    "avg": {
                        "ms": 0
                    },
                    "bytes": 1,
                    "count": 1
                },
                "reopen": {
                    "count": 1
                },
                "seek": {
                    "avg": {
                        "ms": 0
                    },
                    "count": 0
                },
                "sync": {
                    "avg": {
                        "ms": 0
                    },
                    "count": 0
                },
                "write": {
                    "avg": {
                        "ms": 0
                    },
                    "bytes": 0,
                    "count": 0
                }
            },
            "mem": {
                "limit": {
                    "bytes": 13340778496
                },
                "used": {
                    "bytes": 71448312
                }
            },
            "mnesia": {
                "disk": {
                    "tx": {
                        "count": 0
                    }
                },
                "ram": {
                    "tx": {
                        "count": 43
                    }
                }
            },
            "msg": {
                "store_read": {
                    "count": 0
                },
                "store_write": {
                    "count": 0
                }
            },
            "name": "rabbit@my-rabbit",
            "proc": {
                "total": 1048576,
                "used": 234
            },
            "processors": 12,
            "queue": {
                "index": {
                    "journal_write": {
                        "count": 0
                    },
                    "read": {
                        "count": 0
                    },
                    "write": {
                        "count": 0
                    }
                }
            },
            "run": {
                "queue": 0
            },
            "socket": {
                "total": 943626,
                "used": 0
            },
            "type": "disc",
            "uptime": 155275
        }
    },
    "service": {
        "address": "localhost:15672",
        "type": "rabbitmq"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
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
| rabbitmq.node.disk.free.bytes | Disk free space in bytes. | long |
| rabbitmq.node.disk.free.limit.bytes | Point at which the disk alarm will go off. | long |
| rabbitmq.node.fd.total | File descriptors available. | long |
| rabbitmq.node.fd.used | Used file descriptors. | long |
| rabbitmq.node.gc.num.count | Number of GC operations. | long |
| rabbitmq.node.gc.reclaimed.bytes | GC bytes reclaimed. | long |
| rabbitmq.node.io.file_handle.open_attempt.avg.ms | File handle open avg time | long |
| rabbitmq.node.io.file_handle.open_attempt.count | File handle open attempts | long |
| rabbitmq.node.io.read.avg.ms | File handle read avg time | long |
| rabbitmq.node.io.read.bytes | Data read in bytes | long |
| rabbitmq.node.io.read.count | Data read operations | long |
| rabbitmq.node.io.reopen.count | Data reopen operations | long |
| rabbitmq.node.io.seek.avg.ms | Data seek avg time | long |
| rabbitmq.node.io.seek.count | Data seek operations | long |
| rabbitmq.node.io.sync.avg.ms | Data sync avg time | long |
| rabbitmq.node.io.sync.count | Data sync operations | long |
| rabbitmq.node.io.write.avg.ms | Data write avg time | long |
| rabbitmq.node.io.write.bytes | Data write in bytes | long |
| rabbitmq.node.io.write.count | Data write operations | long |
| rabbitmq.node.mem.limit.bytes | Point at which the memory alarm will go off. | long |
| rabbitmq.node.mem.used.bytes | Memory used in bytes. | long |
| rabbitmq.node.mnesia.disk.tx.count | Number of Mnesia transactions which have been performed that required writes to disk. | long |
| rabbitmq.node.mnesia.ram.tx.count | Number of Mnesia transactions which have been performed that did not require writes to disk. | long |
| rabbitmq.node.msg.store_read.count | Number of messages which have been read from the message store. | long |
| rabbitmq.node.msg.store_write.count | Number of messages which have been written to the message store. | long |
| rabbitmq.node.name | Node name | keyword |
| rabbitmq.node.proc.total | Maximum number of Erlang processes. | long |
| rabbitmq.node.proc.used | Number of Erlang processes in use. | long |
| rabbitmq.node.processors | Number of cores detected and usable by Erlang. | long |
| rabbitmq.node.queue.index.journal_write.count | Number of records written to the queue index journal. | long |
| rabbitmq.node.queue.index.read.count | Number of records read from the queue index. | long |
| rabbitmq.node.queue.index.write.count | Number of records written to the queue index. | long |
| rabbitmq.node.run.queue | Average number of Erlang processes waiting to run. | long |
| rabbitmq.node.socket.total | File descriptors available for use as sockets. | long |
| rabbitmq.node.socket.used | File descriptors used as sockets. | long |
| rabbitmq.node.type | Node type. | keyword |
| rabbitmq.node.uptime | Node uptime. | long |
| rabbitmq.vhost | Virtual host name with non-ASCII characters escaped as in C. | keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |


### Queue Metrics

An example event for `queue` looks as following:

```json
{
    "@timestamp": "2020-06-25T10:15:10.955Z",
    "rabbitmq": {
        "queue": {
            "auto_delete": false,
            "state": "running",
            "disk": {
                "reads": {},
                "writes": {}
            },
            "memory": {
                "bytes": 14000
            },
            "messages": {
                "persistent": {
                    "count": 0
                },
                "total": {
                    "details": {
                        "rate": 0
                    },
                    "count": 0
                },
                "ready": {
                    "details": {
                        "rate": 0
                    },
                    "count": 0
                },
                "unacknowledged": {
                    "count": 0,
                    "details": {
                        "rate": 0
                    }
                }
            },
            "durable": true,
            "arguments": {},
            "consumers": {
                "utilisation": {},
                "count": 0
            },
            "name": "NameofQueue1",
            "exclusive": false
        },
        "vhost": "/"
    },
    "event": {
        "dataset": "rabbitmq.queue",
        "module": "rabbitmq",
        "duration": 5860529
    },
    "metricset": {
        "name": "queue",
        "period": 10000
    },
    "service": {
        "type": "rabbitmq",
        "address": "localhost:15672"
    },
    "ecs": {
        "version": "1.5.0"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
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
| rabbitmq.queue.arguments.max_priority | Maximum number of priority levels for the queue to support. | long |
| rabbitmq.queue.auto_delete | Whether the queue will be deleted automatically when no longer used. | boolean |
| rabbitmq.queue.consumers.count | Number of consumers. | long |
| rabbitmq.queue.consumers.utilisation.pct | Fraction of the time (between 0.0 and 1.0) that the queue is able to immediately deliver messages to consumers. This can be less than 1.0 if consumers are limited by network congestion or prefetch count. | long |
| rabbitmq.queue.disk.reads.count | Total number of times messages have been read from disk by this queue since it started. | long |
| rabbitmq.queue.disk.writes.count | Total number of times messages have been written to disk by this queue since it started. | long |
| rabbitmq.queue.durable | Whether or not the queue survives server restarts. | boolean |
| rabbitmq.queue.exclusive | Whether the queue is exclusive (i.e. has owner_pid). | boolean |
| rabbitmq.queue.memory.bytes | Bytes of memory consumed by the Erlang process associated with the queue, including stack, heap and internal structures. | long |
| rabbitmq.queue.messages.persistent.count | Total number of persistent messages in the queue (will always be 0 for transient queues). | long |
| rabbitmq.queue.messages.ready.count | Number of messages ready to be delivered to clients. | long |
| rabbitmq.queue.messages.ready.details.rate | How much the count of messages ready has changed per second in the most recent sampling interval. | float |
| rabbitmq.queue.messages.total.count | Sum of ready and unacknowledged messages (queue depth). | long |
| rabbitmq.queue.messages.total.details.rate | How much the queue depth has changed per second in the most recent sampling interval. | float |
| rabbitmq.queue.messages.unacknowledged.count | Number of messages delivered to clients but not yet acknowledged. | long |
| rabbitmq.queue.messages.unacknowledged.details.rate | How much the count of unacknowledged messages has changed per second in the most recent sampling interval. | float |
| rabbitmq.queue.name | The name of the queue with non-ASCII characters escaped as in C. | keyword |
| rabbitmq.queue.state | The state of the queue. Normally 'running', but may be `"\{syncing, MsgCount\}"` if the queue is synchronising. Queues which are located on cluster nodes that are currently down will be shown with a status of 'down'. | keyword |
| rabbitmq.vhost | Virtual host name with non-ASCII characters escaped as in C. | keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
