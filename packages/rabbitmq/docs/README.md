# RabbitMQ Integration

This integration uses [http://www.rabbitmq.com/management.html](HTTP API) created by the management plugin to collect metrics.

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
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| rabbitmq.log.pid | The Erlang process id | keyword |


## Metrics

### Connection Metrics

An example event for `connection` looks as following:

```$json
{
  "@timestamp": "2020-06-25T10:16:10.138Z",
  "dataset": {
    "name": "rabbitmq.connection",
    "namespace": "default",
    "type": "metrics"
  },
  "ecs": {
    "version": "1.5.0"
  },
  "event": {
    "dataset": "rabbitmq.connection",
    "duration": 374411,
    "module": "rabbitmq"
  },
  "metricset": {
    "name": "connection",
    "period": 10000
  },
  "rabbitmq": {
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
    },
    "vhost": "/"
  },
  "service": {
    "address": "localhost:15672",
    "type": "rabbitmq"
  },
  "stream": {
    "dataset": "rabbitmq.connection",
    "namespace": "default",
    "type": "metrics"
  }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
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
| user.name | Short name or login of the user. | keyword |


### Exchange Metrics

An example event for `exchange` looks as following:

```$json
{
  "@timestamp": "2020-06-25T10:04:20.944Z",
  "dataset": {
    "name": "rabbitmq.exchange",
    "namespace": "default",
    "type": "metrics"
  },
  "ecs": {
    "version": "1.5.0"
  },
  "event": {
    "dataset": "rabbitmq.exchange",
    "duration": 4078507,
    "module": "rabbitmq"
  },
  "metricset": {
    "name": "exchange",
    "period": 10000
  },
  "rabbitmq": {
    "exchange": {
      "arguments": {},
      "auto_delete": false,
      "durable": true,
      "internal": false,
      "name": "",
      "type": "direct"
    },
    "vhost": "/"
  },
  "service": {
    "address": "localhost:15672",
    "type": "rabbitmq"
  },
  "stream": {
    "dataset": "rabbitmq.exchange",
    "namespace": "default",
    "type": "metrics"
  },
  "user": {
    "name": "rmq-internal"
  }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| rabbitmq.exchange.auto_delete | Whether the queue will be deleted automatically when no longer used. | boolean |
| rabbitmq.exchange.durable | Whether or not the queue survives server restarts. | boolean |
| rabbitmq.exchange.internal | Whether the exchange is internal, i.e. cannot be directly published to by a client. | boolean |
| rabbitmq.exchange.messages.publish_in.count | Count of messages published "in" to an exchange, i.e. not taking account of routing. | long |
| rabbitmq.exchange.messages.publish_in.details.rate | How much the exchange publish-in count has changed per second in the most recent sampling interval. | float |
| rabbitmq.exchange.messages.publish_out.count | Count of messages published "out" of an exchange, i.e. taking account of routing. | long |
| rabbitmq.exchange.messages.publish_out.details.rate | How much the exchange publish-out count has changed per second in the most recent sampling interval. | float |
| rabbitmq.exchange.name | The name of the queue with non-ASCII characters escaped as in C. | keyword |
| rabbitmq.vhost | Virtual host name with non-ASCII characters escaped as in C. | keyword |
| user.name | Short name or login of the user. | keyword |


### Node Metrics

The "node" dataset collects metrics about RabbitMQ nodes.

It supports two modes to collect data which can be selected with the "Collection mode" setting:

* `node` - collects metrics only from the node the agent connects to.
* `cluster` - collects metrics from all the nodes in the cluster. This is recommended when collecting metrics of an only endpoint for the whole cluster.

An example event for `node` looks as following:

```$json
{
  "@timestamp": "2020-06-25T10:04:20.944Z",
  "dataset": {
    "name": "rabbitmq.exchange",
    "namespace": "default",
    "type": "metrics"
  },
  "ecs": {
    "version": "1.5.0"
  },
  "event": {
    "dataset": "rabbitmq.exchange",
    "duration": 4104737,
    "module": "rabbitmq"
  },
  "metricset": {
    "name": "exchange",
    "period": 10000
  },
  "rabbitmq": {
    "exchange": {
      "arguments": {},
      "auto_delete": false,
      "durable": true,
      "internal": false,
      "name": "amq.fanout",
      "type": "fanout"
    },
    "vhost": "/"
  },
  "service": {
    "address": "localhost:15672",
    "type": "rabbitmq"
  },
  "stream": {
    "dataset": "rabbitmq.exchange",
    "namespace": "default",
    "type": "metrics"
  },
  "user": {
    "name": "rmq-internal"
  }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
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


### Queue Metrics

An example event for `queue` looks as following:

```$json
{
  "@timestamp": "2020-06-25T10:15:10.955Z",
  "dataset": {
    "name": "rabbitmq.queue",
    "namespace": "default",
    "type": "metrics"
  },
  "ecs": {
    "version": "1.5.0"
  },
  "event": {
    "dataset": "rabbitmq.queue",
    "duration": 5860529,
    "module": "rabbitmq"
  },
  "metricset": {
    "name": "queue",
    "period": 10000
  },
  "rabbitmq": {
    "node": {
      "name": "rabbit@047b9c4733f5"
    },
    "queue": {
      "arguments": {},
      "auto_delete": false,
      "consumers": {
        "count": 0,
        "utilisation": {}
      },
      "disk": {
        "reads": {},
        "writes": {}
      },
      "durable": true,
      "exclusive": false,
      "memory": {
        "bytes": 14000
      },
      "messages": {
        "persistent": {
          "count": 0
        },
        "ready": {
          "count": 0,
          "details": {
            "rate": 0
          }
        },
        "total": {
          "count": 0,
          "details": {
            "rate": 0
          }
        },
        "unacknowledged": {
          "count": 0,
          "details": {
            "rate": 0
          }
        }
      },
      "name": "NameofQueue1",
      "state": "running"
    },
    "vhost": "/"
  },
  "service": {
    "address": "localhost:15672",
    "type": "rabbitmq"
  },
  "stream": {
    "dataset": "rabbitmq.queue",
    "namespace": "default",
    "type": "metrics"
  }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
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
| rabbitmq.queue.state | The state of the queue. Normally 'running', but may be "{syncing, MsgCount}" if the queue is synchronising. Queues which are located on cluster nodes that are currently down will be shown with a status of 'down'. | keyword |
| rabbitmq.vhost | Virtual host name with non-ASCII characters escaped as in C. | keyword |
