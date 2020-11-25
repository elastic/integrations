# NATS integration

This integration is used to collect logs and metrics from [NATS servers](https://nats.io/).
The integration collects metrics from [NATS monitoring server APIs](https://nats.io/documentation/managing_the_server/monitoring/).


## Compatibility

The Nats package is tested with Nats 1.3.0, 2.0.4 and 2.1.4

## Logs

### log

The `log` dataset collects the NATS logs.

An example event for `stats` looks as following:

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
| error.message | Error message. | text |
| event.created | Time when the event was first read by an agent or by your pipeline. | date |
| event.kind | The kind of the event. The highest categorization field in the hierarchy. | keyword |
| event.type | Event type. The third categorization field in the hierarchy. | keyword |
| log.level | Log level of the log event. | keyword |
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
| related.ip | All of the IPs seen on your event. | ip |


## Metrics

The default datasets are `stats`, `connections`, `routes` and `subscriptions` while `connection` and `route`
datasets can be enabled to collect detailed metrics per connection/route.

### stats

This is the `stats` dataset of the Nats package, in charge of retrieving generic
metrics from a Nats instance.


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


### connections

This is the `connections` dataset of the Nats package, in charge of retrieving generic
metrics about connections from a Nats instance.

An example event for `connections` looks as following:

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
| nats.connections.total | The number of currently active clients | integer |
| nats.server.id | The server ID | keyword |
| nats.server.time | Server time of metric creation | date |


### routes

This is the `routes` dataset of the Nats package, in charge of retrieving generic
metrics about routes from a Nats instance.

An example event for `routes` looks as following:

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
| nats.routes.total | The number of registered routes | integer |
| nats.server.id | The server ID | keyword |
| nats.server.time | Server time of metric creation | date |


### subscriptions

This is the `subscriptions` dataset of the Nats package, in charge of retrieving
metrics about subscriptions from a Nats instance.

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


### connection

This is the `connection` dataset of the Nats package, in charge of retrieving detailed
metrics per connection from a Nats instance.

An example event for `connection` looks as following:

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


### route

This is the `route` dataset of the Nats package, in charge of retrieving detailed
metric per route from a Nats instance.

An example event for `route` looks as following:

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

