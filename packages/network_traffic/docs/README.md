# Network Packet Capture Integration

This integration sniffs network packets on a host and dissects
known protocols.

## Network Flows

Overall flow information about the network connections on a
host.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.bytes | Bytes sent from the client to the server. | long |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| client.port | Port of the client. | long |
| client.process.args | The command-line of the process that initiated the transaction. | keyword |
| client.process.executable | Absolute path to the client process executable. | keyword |
| client.process.name | The name of the process that initiated the transaction. | keyword |
| client.process.start | The time the client process started. | date |
| client.process.working_directory | The working directory of the client process. | keyword |
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
| destination.bytes | Bytes sent from the destination to the source. | long |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| flow.final | Indicates if event is last event in flow. If final is false, the event reports an intermediate flow state only. | boolean |
| flow.id | Internal flow ID based on connection meta data and address. | keyword |
| flow.vlan | VLAN identifier from the 802.1q frame. In case of a multi-tagged frame this field will be an array with the outer tag's VLAN identifier listed first. | long |
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
| method | The command/verb/method of the transaction. For HTTP, this is the method name (GET, POST, PUT, and so on), for SQL this is the verb (SELECT, UPDATE, DELETE, and so on). | keyword |
| network.bytes | Total bytes transferred in both directions. If `source.bytes` and `destination.bytes` are known, `network.bytes` is their sum. | long |
| network.community_id | A hash of source and destination IPs and ports, as well as the protocol used in a communication. This is a tool-agnostic standard to identify flows. Learn more at https://github.com/corelight/community-id-spec. | keyword |
| network.direction | Direction of the network traffic. Recommended values are:   \* ingress   \* egress   \* inbound   \* outbound   \* internal   \* external   \* unknown  When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.forwarded_ip | Host IP address when the source IP address is the proxy. | ip |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc The field value must be normalized to lowercase for querying. | keyword |
| params | The request parameters. For HTTP, these are the POST or GET parameters. For Thrift-RPC, these are the parameters from the request. | text |
| path | The path the transaction refers to. For HTTP, this is the URL. For SQL databases, this is the table name. For key-value stores, this is the key. | keyword |
| query | The query in a human readable format. For HTTP, it will typically be something like `GET /users/_search?name=test`. For MySQL, it is something like `SELECT id from users where name=test`. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| request | For text protocols, this is the request as seen on the wire (application layer only). For binary protocols this is our representation of the request. | text |
| resource | The logical resource that this transaction refers to. For HTTP, this is the URL path up to the last slash (/). For example, if the URL is `/users/1`, the resource is `/users`. For databases, the resource is typically the table name. The field is not filled for all transaction types. | keyword |
| response | For text protocols, this is the response as seen on the wire (application layer only). For binary protocols this is our representation of the request. | text |
| server.bytes | Bytes sent from the server to the client. | long |
| server.ip | IP address of the server (IPv4 or IPv6). | ip |
| server.port | Port of the server. | long |
| server.process.args | The command-line of the process that served the transaction. | keyword |
| server.process.executable | Absolute path to the server process executable. | keyword |
| server.process.name | The name of the process that served the transaction. | keyword |
| server.process.start | The time the server process started. | date |
| server.process.working_directory | The working directory of the server process. | keyword |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| status | The high level status of the transaction. The way to compute this value depends on the protocol, but the result has a meaning independent of the protocol. | keyword |
| type | The type of the transaction (for example, HTTP, MySQL, Redis, or RUM) or "flow" in case of flows. | keyword |


## Protocols

### AMQP

Fields published for AMQP packets.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| amqp.app-id | Creating application id. | keyword |
| amqp.arguments | Optional additional arguments passed to some methods. Can be of various types. | object |
| amqp.auto-delete | If set, auto-delete queue when unused. | boolean |
| amqp.class-id | Failing method class. | long |
| amqp.consumer-count | The number of consumers of a queue. | long |
| amqp.consumer-tag | Identifier for the consumer, valid within the current channel. | keyword |
| amqp.content-encoding | MIME content encoding. | keyword |
| amqp.content-type | MIME content type. | keyword |
| amqp.correlation-id | Application correlation identifier. | keyword |
| amqp.delivery-mode | Non-persistent (1) or persistent (2). | keyword |
| amqp.delivery-tag | The server-assigned and channel-specific delivery tag. | long |
| amqp.durable | If set, request a durable exchange/queue. | boolean |
| amqp.exchange | Name of the exchange. | keyword |
| amqp.exchange-type | Exchange type. | keyword |
| amqp.exclusive | If set, request an exclusive queue. | boolean |
| amqp.expiration | Message expiration specification. | keyword |
| amqp.headers | Message header field table. | object |
| amqp.if-empty | Delete only if empty. | boolean |
| amqp.if-unused | Delete only if unused. | boolean |
| amqp.immediate | Request immediate delivery. | boolean |
| amqp.mandatory | Indicates mandatory routing. | boolean |
| amqp.message-count | The number of messages in the queue, which will be zero for newly-declared queues. | long |
| amqp.message-id | Application message identifier. | keyword |
| amqp.method-id | Failing method ID. | long |
| amqp.multiple | Acknowledge multiple messages. | boolean |
| amqp.no-ack | If set, the server does not expect acknowledgements for messages. | boolean |
| amqp.no-local | If set, the server will not send messages to the connection that published them. | boolean |
| amqp.no-wait | If set, the server will not respond to the method. | boolean |
| amqp.passive | If set, do not create exchange/queue. | boolean |
| amqp.priority | Message priority, 0 to 9. | long |
| amqp.queue | The queue name identifies the queue within the vhost. | keyword |
| amqp.redelivered | Indicates that the message has been previously delivered to this or another client. | boolean |
| amqp.reply-code | AMQP reply code to an error, similar to http reply-code | long |
| amqp.reply-text | Text explaining the error. | keyword |
| amqp.reply-to | Address to reply to. | keyword |
| amqp.routing-key | Message routing key. | keyword |
| amqp.timestamp | Message timestamp. | keyword |
| amqp.type | Message type name. | keyword |
| amqp.user-id | Creating user id. | keyword |
| client.bytes | Bytes sent from the client to the server. | long |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| client.port | Port of the client. | long |
| client.process.args | The command-line of the process that initiated the transaction. | keyword |
| client.process.executable | Absolute path to the client process executable. | keyword |
| client.process.name | The name of the process that initiated the transaction. | keyword |
| client.process.start | The time the client process started. | date |
| client.process.working_directory | The working directory of the client process. | keyword |
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
| destination.bytes | Bytes sent from the destination to the source. | long |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| flow.final | Indicates if event is last event in flow. If final is false, the event reports an intermediate flow state only. | boolean |
| flow.id | Internal flow ID based on connection meta data and address. | keyword |
| flow.vlan | VLAN identifier from the 802.1q frame. In case of a multi-tagged frame this field will be an array with the outer tag's VLAN identifier listed first. | long |
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
| method | The command/verb/method of the transaction. For HTTP, this is the method name (GET, POST, PUT, and so on), for SQL this is the verb (SELECT, UPDATE, DELETE, and so on). | keyword |
| network.bytes | Total bytes transferred in both directions. If `source.bytes` and `destination.bytes` are known, `network.bytes` is their sum. | long |
| network.community_id | A hash of source and destination IPs and ports, as well as the protocol used in a communication. This is a tool-agnostic standard to identify flows. Learn more at https://github.com/corelight/community-id-spec. | keyword |
| network.direction | Direction of the network traffic. Recommended values are:   \* ingress   \* egress   \* inbound   \* outbound   \* internal   \* external   \* unknown  When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.forwarded_ip | Host IP address when the source IP address is the proxy. | ip |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc The field value must be normalized to lowercase for querying. | keyword |
| params | The request parameters. For HTTP, these are the POST or GET parameters. For Thrift-RPC, these are the parameters from the request. | text |
| path | The path the transaction refers to. For HTTP, this is the URL. For SQL databases, this is the table name. For key-value stores, this is the key. | keyword |
| query | The query in a human readable format. For HTTP, it will typically be something like `GET /users/_search?name=test`. For MySQL, it is something like `SELECT id from users where name=test`. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| request | For text protocols, this is the request as seen on the wire (application layer only). For binary protocols this is our representation of the request. | text |
| resource | The logical resource that this transaction refers to. For HTTP, this is the URL path up to the last slash (/). For example, if the URL is `/users/1`, the resource is `/users`. For databases, the resource is typically the table name. The field is not filled for all transaction types. | keyword |
| response | For text protocols, this is the response as seen on the wire (application layer only). For binary protocols this is our representation of the request. | text |
| server.bytes | Bytes sent from the server to the client. | long |
| server.ip | IP address of the server (IPv4 or IPv6). | ip |
| server.port | Port of the server. | long |
| server.process.args | The command-line of the process that served the transaction. | keyword |
| server.process.executable | Absolute path to the server process executable. | keyword |
| server.process.name | The name of the process that served the transaction. | keyword |
| server.process.start | The time the server process started. | date |
| server.process.working_directory | The working directory of the server process. | keyword |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| status | The high level status of the transaction. The way to compute this value depends on the protocol, but the result has a meaning independent of the protocol. | keyword |
| type | The type of the transaction (for example, HTTP, MySQL, Redis, or RUM) or "flow" in case of flows. | keyword |


An example event for `amqp` looks as following:

```json
{
    "@timestamp": "2022-03-09T07:37:02.033Z",
    "agent": {
        "ephemeral_id": "ff9ccf25-9d67-46a5-b661-aa01e3db9b84",
        "id": "f789afb0-558d-48bd-b448-0fc838efd730",
        "name": "docker-fleet-agent",
        "type": "packetbeat",
        "version": "8.0.0"
    },
    "amqp": {
        "auto-delete": false,
        "consumer-count": 0,
        "durable": false,
        "exclusive": false,
        "message-count": 0,
        "no-wait": false,
        "passive": false,
        "queue": "hello"
    },
    "client": {
        "bytes": 25,
        "ip": "127.0.0.1",
        "port": 34222
    },
    "data_stream": {
        "dataset": "network_traffic.amqp",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "bytes": 26,
        "ip": "127.0.0.1",
        "port": 5672
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "f789afb0-558d-48bd-b448-0fc838efd730",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "action": "amqp.queue.declare",
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "network_traffic.amqp",
        "duration": 1325900,
        "end": "2022-03-09T07:37:02.035Z",
        "ingested": "2022-03-09T07:37:03Z",
        "kind": "event",
        "start": "2022-03-09T07:37:02.033Z",
        "type": [
            "connection",
            "protocol"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "192.168.176.7"
        ],
        "mac": [
            "02-42-C0-A8-B0-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.47-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.3 LTS (Focal Fossa)"
        }
    },
    "method": "queue.declare",
    "network": {
        "bytes": 51,
        "community_id": "1:i6J4zz0FGnZMYLIy8kabND2W/XE=",
        "direction": "ingress",
        "protocol": "amqp",
        "transport": "tcp",
        "type": "ipv4"
    },
    "related": {
        "ip": [
            "127.0.0.1"
        ]
    },
    "server": {
        "bytes": 26,
        "ip": "127.0.0.1",
        "port": 5672
    },
    "source": {
        "bytes": 25,
        "ip": "127.0.0.1",
        "port": 34222
    },
    "status": "OK",
    "type": "amqp"
}
```

### Cassandra

Fields published for Apache Cassandra packets.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cassandra.no_request | Indicates that there is no request because this is a PUSH message. | boolean |
| cassandra.request.headers.flags | Flags applying to this frame. | keyword |
| cassandra.request.headers.length | A integer representing the length of the body of the frame (a frame is limited to 256MB in length). | long |
| cassandra.request.headers.op | An operation type that distinguishes the actual message. | keyword |
| cassandra.request.headers.stream | A frame has a stream id.  If a client sends a request message with the stream id X, it is guaranteed that the stream id of the response to that message will be X. | keyword |
| cassandra.request.headers.version | The version of the protocol. | keyword |
| cassandra.request.query | The CQL query which client send to cassandra. | keyword |
| cassandra.response.authentication.class | Indicates the full class name of the IAuthenticator in use | keyword |
| cassandra.response.error.code | The error code of the Cassandra response. | long |
| cassandra.response.error.details.alive | Representing the number of replicas that were known to be alive when the request had been processed (since an unavailable exception has been triggered). | long |
| cassandra.response.error.details.arg_types | One string for each argument type (as CQL type) of the failed function. | keyword |
| cassandra.response.error.details.blockfor | Representing the number of replicas whose acknowledgement is required to achieve consistency level. | long |
| cassandra.response.error.details.data_present | It means the replica that was asked for data had responded. | boolean |
| cassandra.response.error.details.function | The name of the failed function. | keyword |
| cassandra.response.error.details.keyspace | The keyspace of the failed function. | keyword |
| cassandra.response.error.details.num_failures | Representing the number of nodes that experience a failure while executing the request. | keyword |
| cassandra.response.error.details.read_consistency | Representing the consistency level of the query that triggered the exception. | keyword |
| cassandra.response.error.details.received | Representing the number of nodes having acknowledged the request. | long |
| cassandra.response.error.details.required | Representing the number of nodes that should be alive to respect consistency level. | long |
| cassandra.response.error.details.stmt_id | Representing the unknown ID. | keyword |
| cassandra.response.error.details.table | The keyspace of the failed function. | keyword |
| cassandra.response.error.details.write_type | Describe the type of the write that timed out. | keyword |
| cassandra.response.error.msg | The error message of the Cassandra response. | keyword |
| cassandra.response.error.type | The error type of the Cassandra response. | keyword |
| cassandra.response.event.change | The message corresponding respectively to the type of change followed by the address of the new/removed node. | keyword |
| cassandra.response.event.host | Representing the node ip. | keyword |
| cassandra.response.event.port | Representing the node port. | long |
| cassandra.response.event.schema_change.args | One string for each argument type (as CQL type). | keyword |
| cassandra.response.event.schema_change.change | Representing the type of changed involved. | keyword |
| cassandra.response.event.schema_change.keyspace | This describes which keyspace has changed. | keyword |
| cassandra.response.event.schema_change.name | The function/aggregate name. | keyword |
| cassandra.response.event.schema_change.object | This describes the name of said affected object (either the table, user type, function, or aggregate name). | keyword |
| cassandra.response.event.schema_change.table | This describes which table has changed. | keyword |
| cassandra.response.event.schema_change.target | Target could be "FUNCTION" or "AGGREGATE", multiple arguments. | keyword |
| cassandra.response.event.type | Representing the event type. | keyword |
| cassandra.response.headers.flags | Flags applying to this frame. | keyword |
| cassandra.response.headers.length | A integer representing the length of the body of the frame (a frame is limited to 256MB in length). | long |
| cassandra.response.headers.op | An operation type that distinguishes the actual message. | keyword |
| cassandra.response.headers.stream | A frame has a stream id.  If a client sends a request message with the stream id X, it is guaranteed that the stream id of the response to that message will be X. | keyword |
| cassandra.response.headers.version | The version of the protocol. | keyword |
| cassandra.response.result.keyspace | Indicating the name of the keyspace that has been set. | keyword |
| cassandra.response.result.prepared.prepared_id | Representing the prepared query ID. | keyword |
| cassandra.response.result.prepared.req_meta.col_count | Representing the number of columns selected by the query that produced this result. | long |
| cassandra.response.result.prepared.req_meta.flags | Provides information on the formatting of the remaining information. | keyword |
| cassandra.response.result.prepared.req_meta.keyspace | Only present after set Global_tables_spec, the keyspace name. | keyword |
| cassandra.response.result.prepared.req_meta.paging_state | The paging_state is a bytes value that should be used in QUERY/EXECUTE to continue paging and retrieve the remainder of the result for this query. | keyword |
| cassandra.response.result.prepared.req_meta.pkey_columns | Representing the PK columns index and counts. | long |
| cassandra.response.result.prepared.req_meta.table | Only present after set Global_tables_spec, the table name. | keyword |
| cassandra.response.result.prepared.resp_meta.col_count | Representing the number of columns selected by the query that produced this result. | long |
| cassandra.response.result.prepared.resp_meta.flags | Provides information on the formatting of the remaining information. | keyword |
| cassandra.response.result.prepared.resp_meta.keyspace | Only present after set Global_tables_spec, the keyspace name. | keyword |
| cassandra.response.result.prepared.resp_meta.paging_state | The paging_state is a bytes value that should be used in QUERY/EXECUTE to continue paging and retrieve the remainder of the result for this query. | keyword |
| cassandra.response.result.prepared.resp_meta.pkey_columns | Representing the PK columns index and counts. | long |
| cassandra.response.result.prepared.resp_meta.table | Only present after set Global_tables_spec, the table name. | keyword |
| cassandra.response.result.rows.meta.col_count | Representing the number of columns selected by the query that produced this result. | long |
| cassandra.response.result.rows.meta.flags | Provides information on the formatting of the remaining information. | keyword |
| cassandra.response.result.rows.meta.keyspace | Only present after set Global_tables_spec, the keyspace name. | keyword |
| cassandra.response.result.rows.meta.paging_state | The paging_state is a bytes value that should be used in QUERY/EXECUTE to continue paging and retrieve the remainder of the result for this query. | keyword |
| cassandra.response.result.rows.meta.pkey_columns | Representing the PK columns index and counts. | long |
| cassandra.response.result.rows.meta.table | Only present after set Global_tables_spec, the table name. | keyword |
| cassandra.response.result.rows.num_rows | Representing the number of rows present in this result. | long |
| cassandra.response.result.schema_change.args | One string for each argument type (as CQL type). | keyword |
| cassandra.response.result.schema_change.change | Representing the type of changed involved. | keyword |
| cassandra.response.result.schema_change.keyspace | This describes which keyspace has changed. | keyword |
| cassandra.response.result.schema_change.name | The function/aggregate name. | keyword |
| cassandra.response.result.schema_change.object | This describes the name of said affected object (either the table, user type, function, or aggregate name). | keyword |
| cassandra.response.result.schema_change.table | This describes which table has changed. | keyword |
| cassandra.response.result.schema_change.target | Target could be "FUNCTION" or "AGGREGATE", multiple arguments. | keyword |
| cassandra.response.result.type | Cassandra result type. | keyword |
| cassandra.response.supported | Indicates which startup options are supported by the server. This message comes as a response to an OPTIONS message. | flattened |
| cassandra.response.warnings | The text of the warnings, only occur when Warning flag was set. | keyword |
| client.bytes | Bytes sent from the client to the server. | long |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| client.port | Port of the client. | long |
| client.process.args | The command-line of the process that initiated the transaction. | keyword |
| client.process.executable | Absolute path to the client process executable. | keyword |
| client.process.name | The name of the process that initiated the transaction. | keyword |
| client.process.start | The time the client process started. | date |
| client.process.working_directory | The working directory of the client process. | keyword |
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
| destination.bytes | Bytes sent from the destination to the source. | long |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| flow.final | Indicates if event is last event in flow. If final is false, the event reports an intermediate flow state only. | boolean |
| flow.id | Internal flow ID based on connection meta data and address. | keyword |
| flow.vlan | VLAN identifier from the 802.1q frame. In case of a multi-tagged frame this field will be an array with the outer tag's VLAN identifier listed first. | long |
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
| method | The command/verb/method of the transaction. For HTTP, this is the method name (GET, POST, PUT, and so on), for SQL this is the verb (SELECT, UPDATE, DELETE, and so on). | keyword |
| network.bytes | Total bytes transferred in both directions. If `source.bytes` and `destination.bytes` are known, `network.bytes` is their sum. | long |
| network.community_id | A hash of source and destination IPs and ports, as well as the protocol used in a communication. This is a tool-agnostic standard to identify flows. Learn more at https://github.com/corelight/community-id-spec. | keyword |
| network.direction | Direction of the network traffic. Recommended values are:   \* ingress   \* egress   \* inbound   \* outbound   \* internal   \* external   \* unknown  When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.forwarded_ip | Host IP address when the source IP address is the proxy. | ip |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc The field value must be normalized to lowercase for querying. | keyword |
| params | The request parameters. For HTTP, these are the POST or GET parameters. For Thrift-RPC, these are the parameters from the request. | text |
| path | The path the transaction refers to. For HTTP, this is the URL. For SQL databases, this is the table name. For key-value stores, this is the key. | keyword |
| query | The query in a human readable format. For HTTP, it will typically be something like `GET /users/_search?name=test`. For MySQL, it is something like `SELECT id from users where name=test`. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| request | For text protocols, this is the request as seen on the wire (application layer only). For binary protocols this is our representation of the request. | text |
| resource | The logical resource that this transaction refers to. For HTTP, this is the URL path up to the last slash (/). For example, if the URL is `/users/1`, the resource is `/users`. For databases, the resource is typically the table name. The field is not filled for all transaction types. | keyword |
| response | For text protocols, this is the response as seen on the wire (application layer only). For binary protocols this is our representation of the request. | text |
| server.bytes | Bytes sent from the server to the client. | long |
| server.ip | IP address of the server (IPv4 or IPv6). | ip |
| server.port | Port of the server. | long |
| server.process.args | The command-line of the process that served the transaction. | keyword |
| server.process.executable | Absolute path to the server process executable. | keyword |
| server.process.name | The name of the process that served the transaction. | keyword |
| server.process.start | The time the server process started. | date |
| server.process.working_directory | The working directory of the server process. | keyword |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| status | The high level status of the transaction. The way to compute this value depends on the protocol, but the result has a meaning independent of the protocol. | keyword |
| type | The type of the transaction (for example, HTTP, MySQL, Redis, or RUM) or "flow" in case of flows. | keyword |


An example event for `cassandra` looks as following:

```json
{
    "@timestamp": "2022-03-09T07:43:05.888Z",
    "agent": {
        "ephemeral_id": "20d6eb94-1319-473d-9e2f-05621a4d2494",
        "id": "f789afb0-558d-48bd-b448-0fc838efd730",
        "name": "docker-fleet-agent",
        "type": "packetbeat",
        "version": "8.0.0"
    },
    "cassandra": {
        "request": {
            "headers": {
                "flags": "Default",
                "length": 98,
                "op": "QUERY",
                "stream": 49,
                "version": "4"
            },
            "query": "CREATE TABLE users (\n  user_id int PRIMARY KEY,\n  fname text,\n  lname text\n);"
        },
        "response": {
            "headers": {
                "flags": "Default",
                "length": 39,
                "op": "RESULT",
                "stream": 49,
                "version": "4"
            },
            "result": {
                "schema_change": {
                    "change": "CREATED",
                    "keyspace": "mykeyspace",
                    "object": "users",
                    "target": "TABLE"
                },
                "type": "schemaChanged"
            }
        }
    },
    "client": {
        "bytes": 107,
        "ip": "127.0.0.1",
        "port": 52749
    },
    "data_stream": {
        "dataset": "network_traffic.cassandra",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "bytes": 48,
        "ip": "127.0.0.1",
        "port": 9042
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "f789afb0-558d-48bd-b448-0fc838efd730",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "network_traffic.cassandra",
        "duration": 131589500,
        "end": "2022-03-09T07:43:06.019Z",
        "ingested": "2022-03-09T07:43:09Z",
        "kind": "event",
        "start": "2022-03-09T07:43:05.888Z",
        "type": [
            "connection",
            "protocol"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "192.168.176.7"
        ],
        "mac": [
            "02-42-C0-A8-B0-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.47-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.3 LTS (Focal Fossa)"
        }
    },
    "network": {
        "bytes": 155,
        "community_id": "1:bCORHZnGIk6GWYaE3Kn0DOpQCKE=",
        "direction": "ingress",
        "protocol": "cassandra",
        "transport": "tcp",
        "type": "ipv4"
    },
    "related": {
        "ip": [
            "127.0.0.1"
        ]
    },
    "server": {
        "bytes": 48,
        "ip": "127.0.0.1",
        "port": 9042
    },
    "source": {
        "bytes": 107,
        "ip": "127.0.0.1",
        "port": 52749
    },
    "status": "OK",
    "type": "cassandra"
}
```

### DHCP

Fields published for DHCPv4 packets.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.bytes | Bytes sent from the client to the server. | long |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| client.port | Port of the client. | long |
| client.process.args | The command-line of the process that initiated the transaction. | keyword |
| client.process.executable | Absolute path to the client process executable. | keyword |
| client.process.name | The name of the process that initiated the transaction. | keyword |
| client.process.start | The time the client process started. | date |
| client.process.working_directory | The working directory of the client process. | keyword |
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
| destination.bytes | Bytes sent from the destination to the source. | long |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| dhcpv4.assigned_ip | The IP address that the DHCP server is assigning to the client. This field is also known as "your" IP address. | ip |
| dhcpv4.client_ip | The current IP address of the client. | ip |
| dhcpv4.client_mac | The client's MAC address (layer two). | keyword |
| dhcpv4.flags | Flags are set by the client to indicate how the DHCP server should its reply -- either unicast or broadcast. | keyword |
| dhcpv4.hardware_type | The type of hardware used for the local network (Ethernet, LocalTalk, etc). | keyword |
| dhcpv4.hops | The number of hops the DHCP message went through. | long |
| dhcpv4.op_code | The message op code (bootrequest or bootreply). | keyword |
| dhcpv4.option.boot_file_name | This option is used to identify a bootfile when the 'file' field in the DHCP header has been used for DHCP options. | keyword |
| dhcpv4.option.broadcast_address | This option specifies the broadcast address in use on the client's subnet. | ip |
| dhcpv4.option.class_identifier | This option is used by DHCP clients to optionally identify the vendor type and configuration of a DHCP client. Vendors may choose to define specific vendor class identifiers to convey particular configuration or other identification information about a client.  For example, the identifier may encode the client's hardware configuration. | keyword |
| dhcpv4.option.dns_servers | The domain name server option specifies a list of Domain Name System servers available to the client. | ip |
| dhcpv4.option.domain_name | This option specifies the domain name that client should use when resolving hostnames via the Domain Name System. | keyword |
| dhcpv4.option.hostname | This option specifies the name of the client. | keyword |
| dhcpv4.option.ip_address_lease_time_sec | This option is used in a client request (DHCPDISCOVER or DHCPREQUEST) to allow the client to request a lease time for the IP address.  In a server reply (DHCPOFFER), a DHCP server uses this option to specify the lease time it is willing to offer. | long |
| dhcpv4.option.max_dhcp_message_size | This option specifies the maximum length DHCP message that the client is willing to accept. | long |
| dhcpv4.option.message | This option is used by a DHCP server to provide an error message to a DHCP client in a DHCPNAK message in the event of a failure. A client may use this option in a DHCPDECLINE message to indicate the why the client declined the offered parameters. | text |
| dhcpv4.option.message_type | The specific type of DHCP message being sent (e.g. discover, offer, request, decline, ack, nak, release, inform). | keyword |
| dhcpv4.option.ntp_servers | This option specifies a list of IP addresses indicating NTP servers available to the client. | ip |
| dhcpv4.option.parameter_request_list | This option is used by a DHCP client to request values for specified configuration parameters. | keyword |
| dhcpv4.option.rebinding_time_sec | This option specifies the time interval from address assignment until the client transitions to the REBINDING state. | long |
| dhcpv4.option.renewal_time_sec | This option specifies the time interval from address assignment until the client transitions to the RENEWING state. | long |
| dhcpv4.option.requested_ip_address | This option is used in a client request (DHCPDISCOVER) to allow the client to request that a particular IP address be assigned. | ip |
| dhcpv4.option.router | The router option specifies a list of IP addresses for routers on the client's subnet. | ip |
| dhcpv4.option.server_identifier | IP address of the individual DHCP server which handled this message. | ip |
| dhcpv4.option.subnet_mask | The subnet mask that the client should use on the currnet network. | ip |
| dhcpv4.option.time_servers | The time server option specifies a list of RFC 868 time servers available to the client. | ip |
| dhcpv4.option.utc_time_offset_sec | The time offset field specifies the offset of the client's subnet in seconds from Coordinated Universal Time (UTC). | long |
| dhcpv4.option.vendor_identifying_options | A DHCP client may use this option to unambiguously identify the vendor that manufactured the hardware on which the client is running, the software in use, or an industry consortium to which the vendor belongs. This field is described in RFC 3925. | object |
| dhcpv4.relay_ip | The relay IP address used by the client to contact the server (i.e. a DHCP relay server). | ip |
| dhcpv4.seconds | Number of seconds elapsed since client began address acquisition or renewal process. | long |
| dhcpv4.server_ip | The IP address of the DHCP server that the client should use for the next step in the bootstrap process. | ip |
| dhcpv4.server_name | The name of the server sending the message. Optional. Used in DHCPOFFER or DHCPACK messages. | keyword |
| dhcpv4.transaction_id | Transaction ID, a random number chosen by the client, used by the client and server to associate messages and responses between a client and a server. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| flow.final | Indicates if event is last event in flow. If final is false, the event reports an intermediate flow state only. | boolean |
| flow.id | Internal flow ID based on connection meta data and address. | keyword |
| flow.vlan | VLAN identifier from the 802.1q frame. In case of a multi-tagged frame this field will be an array with the outer tag's VLAN identifier listed first. | long |
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
| method | The command/verb/method of the transaction. For HTTP, this is the method name (GET, POST, PUT, and so on), for SQL this is the verb (SELECT, UPDATE, DELETE, and so on). | keyword |
| network.bytes | Total bytes transferred in both directions. If `source.bytes` and `destination.bytes` are known, `network.bytes` is their sum. | long |
| network.community_id | A hash of source and destination IPs and ports, as well as the protocol used in a communication. This is a tool-agnostic standard to identify flows. Learn more at https://github.com/corelight/community-id-spec. | keyword |
| network.direction | Direction of the network traffic. Recommended values are:   \* ingress   \* egress   \* inbound   \* outbound   \* internal   \* external   \* unknown  When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.forwarded_ip | Host IP address when the source IP address is the proxy. | ip |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc The field value must be normalized to lowercase for querying. | keyword |
| params | The request parameters. For HTTP, these are the POST or GET parameters. For Thrift-RPC, these are the parameters from the request. | text |
| path | The path the transaction refers to. For HTTP, this is the URL. For SQL databases, this is the table name. For key-value stores, this is the key. | keyword |
| query | The query in a human readable format. For HTTP, it will typically be something like `GET /users/_search?name=test`. For MySQL, it is something like `SELECT id from users where name=test`. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| request | For text protocols, this is the request as seen on the wire (application layer only). For binary protocols this is our representation of the request. | text |
| resource | The logical resource that this transaction refers to. For HTTP, this is the URL path up to the last slash (/). For example, if the URL is `/users/1`, the resource is `/users`. For databases, the resource is typically the table name. The field is not filled for all transaction types. | keyword |
| response | For text protocols, this is the response as seen on the wire (application layer only). For binary protocols this is our representation of the request. | text |
| server.bytes | Bytes sent from the server to the client. | long |
| server.ip | IP address of the server (IPv4 or IPv6). | ip |
| server.port | Port of the server. | long |
| server.process.args | The command-line of the process that served the transaction. | keyword |
| server.process.executable | Absolute path to the server process executable. | keyword |
| server.process.name | The name of the process that served the transaction. | keyword |
| server.process.start | The time the server process started. | date |
| server.process.working_directory | The working directory of the server process. | keyword |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| status | The high level status of the transaction. The way to compute this value depends on the protocol, but the result has a meaning independent of the protocol. | keyword |
| type | The type of the transaction (for example, HTTP, MySQL, Redis, or RUM) or "flow" in case of flows. | keyword |


An example event for `dhcpv4` looks as following:

```json
{
    "@timestamp": "2022-03-09T07:43:52.712Z",
    "agent": {
        "ephemeral_id": "b98a43ba-d050-42e6-ab2f-2eba352e9cb0",
        "id": "f789afb0-558d-48bd-b448-0fc838efd730",
        "name": "docker-fleet-agent",
        "type": "packetbeat",
        "version": "8.0.0"
    },
    "client": {
        "bytes": 272,
        "ip": "0.0.0.0",
        "port": 68
    },
    "data_stream": {
        "dataset": "network_traffic.dhcpv4",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "ip": "255.255.255.255",
        "port": 67
    },
    "dhcpv4": {
        "client_mac": "00-0B-82-01-FC-42",
        "flags": "unicast",
        "hardware_type": "Ethernet",
        "hops": 0,
        "op_code": "bootrequest",
        "option": {
            "message_type": "discover",
            "parameter_request_list": [
                "Subnet Mask",
                "Router",
                "Domain Name Server",
                "NTP Servers"
            ],
            "requested_ip_address": "0.0.0.0"
        },
        "seconds": 0,
        "transaction_id": "0x00003d1d"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "f789afb0-558d-48bd-b448-0fc838efd730",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "network_traffic.dhcpv4",
        "ingested": "2022-03-09T07:43:53Z",
        "kind": "event",
        "start": "2022-03-09T07:43:52.712Z",
        "type": [
            "connection",
            "protocol"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "192.168.176.7"
        ],
        "mac": [
            "02-42-C0-A8-B0-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.47-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.3 LTS (Focal Fossa)"
        }
    },
    "network": {
        "bytes": 272,
        "community_id": "1:t9O1j0qj71O4wJM7gnaHtgmfev8=",
        "direction": "unknown",
        "protocol": "dhcpv4",
        "transport": "udp",
        "type": "ipv4"
    },
    "related": {
        "ip": [
            "0.0.0.0",
            "255.255.255.255"
        ]
    },
    "server": {
        "ip": "255.255.255.255",
        "port": 67
    },
    "source": {
        "bytes": 272,
        "ip": "0.0.0.0",
        "port": 68
    },
    "status": "OK",
    "type": "dhcpv4"
}
```

### DNS

Fields published for DNS packets.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.bytes | Bytes sent from the client to the server. | long |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| client.port | Port of the client. | long |
| client.process.args | The command-line of the process that initiated the transaction. | keyword |
| client.process.executable | Absolute path to the client process executable. | keyword |
| client.process.name | The name of the process that initiated the transaction. | keyword |
| client.process.start | The time the client process started. | date |
| client.process.working_directory | The working directory of the client process. | keyword |
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
| destination.bytes | Bytes sent from the destination to the source. | long |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| dns.additionals | An array containing a dictionary for each additional section from the answer. | object |
| dns.additionals.class | The class of DNS data contained in this resource record. | keyword |
| dns.additionals.data | The data describing the resource. The meaning of this data depends on the type and class of the resource record. | keyword |
| dns.additionals.name | The domain name to which this resource record pertains. | keyword |
| dns.additionals.ttl | The time interval in seconds that this resource record may be cached before it should be discarded. Zero values mean that the data should not be cached. | long |
| dns.additionals.type | The type of data contained in this resource record. | keyword |
| dns.additionals_count | The number of resource records contained in the `dns.additionals` field. The `dns.additionals` field may or may not be included depending on the configuration of Packetbeat. | long |
| dns.answers | An array containing an object for each answer section returned by the server. The main keys that should be present in these objects are defined by ECS. Records that have more information may contain more keys than what ECS defines. Not all DNS data sources give all details about DNS answers. At minimum, answer objects must contain the `data` key. If more information is available, map as much of it to ECS as possible, and add any additional fields to the answer objects as custom fields. | object |
| dns.answers_count | The number of resource records contained in the `dns.answers` field. | long |
| dns.authorities | An array containing a dictionary for each authority section from the answer. | object |
| dns.authorities.class | The class of DNS data contained in this resource record. | keyword |
| dns.authorities.name | The domain name to which this resource record pertains. | keyword |
| dns.authorities.type | The type of data contained in this resource record. | keyword |
| dns.authorities_count | The number of resource records contained in the `dns.authorities` field. The `dns.authorities` field may or may not be included depending on the configuration of Packetbeat. | long |
| dns.flags.authentic_data | A DNS flag specifying that the recursive server considers the response authentic. | boolean |
| dns.flags.authoritative | A DNS flag specifying that the responding server is an authority for the domain name used in the question. | boolean |
| dns.flags.checking_disabled | A DNS flag specifying that the client disables the server signature validation of the query. | boolean |
| dns.flags.recursion_available | A DNS flag specifying whether recursive query support is available in the name server. | boolean |
| dns.flags.recursion_desired | A DNS flag specifying that the client directs the server to pursue a query recursively. Recursive query support is optional. | boolean |
| dns.flags.truncated_response | A DNS flag specifying that only the first 512 bytes of the reply were returned. | boolean |
| dns.header_flags | Array of 2 letter DNS header flags. Expected values are: AA, TC, RD, RA, AD, CD, DO. | keyword |
| dns.id | The DNS packet identifier assigned by the program that generated the query. The identifier is copied to the response. | keyword |
| dns.op_code | The DNS operation code that specifies the kind of query in the message. This value is set by the originator of a query and copied into the response. | keyword |
| dns.opt.do | If set, the transaction uses DNSSEC. | boolean |
| dns.opt.ext_rcode | Extended response code field. | keyword |
| dns.opt.udp_size | Requestor's UDP payload size (in bytes). | long |
| dns.opt.version | The EDNS version. | keyword |
| dns.question.class | The class of records being queried. | keyword |
| dns.question.etld_plus_one | The effective top-level domain (eTLD) plus one more label. For example, the eTLD+1 for "foo.bar.golang.org." is "golang.org.". The data for determining the eTLD comes from an embedded copy of the data from http://publicsuffix.org. | keyword |
| dns.question.name | The name being queried. If the name field contains non-printable characters (below 32 or above 126), those characters should be represented as escaped base 10 integers (\DDD). Back slashes and quotes should be escaped. Tabs, carriage returns, and line feeds should be converted to \t, \r, and \n respectively. | keyword |
| dns.question.registered_domain | The highest registered domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| dns.question.subdomain | The subdomain is all of the labels under the registered_domain. If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| dns.question.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| dns.question.type | The type of record being queried. | keyword |
| dns.resolved_ip | Array containing all IPs seen in `answers.data`. The `answers` array can be difficult to use, because of the variety of data formats it can contain. Extracting all IP addresses seen in there to `dns.resolved_ip` makes it possible to index them as IP addresses, and makes them easier to visualize and query for. | ip |
| dns.response_code | The DNS response code. | keyword |
| dns.type | The type of DNS event captured, query or answer. If your source of DNS events only gives you DNS queries, you should only create dns events of type `dns.type:query`. If your source of DNS events gives you answers as well, you should create one event per query (optionally as soon as the query is seen). And a second event containing all query details as well as an array of answers. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| flow.final | Indicates if event is last event in flow. If final is false, the event reports an intermediate flow state only. | boolean |
| flow.id | Internal flow ID based on connection meta data and address. | keyword |
| flow.vlan | VLAN identifier from the 802.1q frame. In case of a multi-tagged frame this field will be an array with the outer tag's VLAN identifier listed first. | long |
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
| method | The command/verb/method of the transaction. For HTTP, this is the method name (GET, POST, PUT, and so on), for SQL this is the verb (SELECT, UPDATE, DELETE, and so on). | keyword |
| network.bytes | Total bytes transferred in both directions. If `source.bytes` and `destination.bytes` are known, `network.bytes` is their sum. | long |
| network.community_id | A hash of source and destination IPs and ports, as well as the protocol used in a communication. This is a tool-agnostic standard to identify flows. Learn more at https://github.com/corelight/community-id-spec. | keyword |
| network.direction | Direction of the network traffic. Recommended values are:   \* ingress   \* egress   \* inbound   \* outbound   \* internal   \* external   \* unknown  When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.forwarded_ip | Host IP address when the source IP address is the proxy. | ip |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc The field value must be normalized to lowercase for querying. | keyword |
| params | The request parameters. For HTTP, these are the POST or GET parameters. For Thrift-RPC, these are the parameters from the request. | text |
| path | The path the transaction refers to. For HTTP, this is the URL. For SQL databases, this is the table name. For key-value stores, this is the key. | keyword |
| query | The query in a human readable format. For HTTP, it will typically be something like `GET /users/_search?name=test`. For MySQL, it is something like `SELECT id from users where name=test`. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| request | For text protocols, this is the request as seen on the wire (application layer only). For binary protocols this is our representation of the request. | text |
| resource | The logical resource that this transaction refers to. For HTTP, this is the URL path up to the last slash (/). For example, if the URL is `/users/1`, the resource is `/users`. For databases, the resource is typically the table name. The field is not filled for all transaction types. | keyword |
| response | For text protocols, this is the response as seen on the wire (application layer only). For binary protocols this is our representation of the request. | text |
| server.bytes | Bytes sent from the server to the client. | long |
| server.ip | IP address of the server (IPv4 or IPv6). | ip |
| server.port | Port of the server. | long |
| server.process.args | The command-line of the process that served the transaction. | keyword |
| server.process.executable | Absolute path to the server process executable. | keyword |
| server.process.name | The name of the process that served the transaction. | keyword |
| server.process.start | The time the server process started. | date |
| server.process.working_directory | The working directory of the server process. | keyword |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| status | The high level status of the transaction. The way to compute this value depends on the protocol, but the result has a meaning independent of the protocol. | keyword |
| type | The type of the transaction (for example, HTTP, MySQL, Redis, or RUM) or "flow" in case of flows. | keyword |


An example event for `dns` looks as following:

```json
{
    "@timestamp": "2022-03-09T07:48:42.751Z",
    "agent": {
        "ephemeral_id": "1d099984-2551-49e1-9e6a-c1dff964be0f",
        "id": "f789afb0-558d-48bd-b448-0fc838efd730",
        "name": "docker-fleet-agent",
        "type": "packetbeat",
        "version": "8.0.0"
    },
    "client": {
        "bytes": 28,
        "ip": "192.168.238.68",
        "port": 53765
    },
    "data_stream": {
        "dataset": "network_traffic.dns",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "bytes": 167,
        "ip": "8.8.8.8",
        "port": 53
    },
    "dns": {
        "additionals_count": 0,
        "answers": [
            {
                "class": "IN",
                "data": "ns-1183.awsdns-19.org",
                "name": "elastic.co",
                "ttl": "21599",
                "type": "NS"
            },
            {
                "class": "IN",
                "data": "ns-2007.awsdns-58.co.uk",
                "name": "elastic.co",
                "ttl": "21599",
                "type": "NS"
            },
            {
                "class": "IN",
                "data": "ns-66.awsdns-08.com",
                "name": "elastic.co",
                "ttl": "21599",
                "type": "NS"
            },
            {
                "class": "IN",
                "data": "ns-835.awsdns-40.net",
                "name": "elastic.co",
                "ttl": "21599",
                "type": "NS"
            }
        ],
        "answers_count": 4,
        "authorities_count": 0,
        "flags": {
            "authentic_data": false,
            "authoritative": false,
            "checking_disabled": false,
            "recursion_available": true,
            "recursion_desired": true,
            "truncated_response": false
        },
        "header_flags": [
            "RD",
            "RA"
        ],
        "id": 26187,
        "op_code": "QUERY",
        "question": {
            "class": "IN",
            "etld_plus_one": "elastic.co",
            "name": "elastic.co",
            "registered_domain": "elastic.co",
            "top_level_domain": "co",
            "type": "NS"
        },
        "response_code": "NOERROR",
        "type": "answer"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "f789afb0-558d-48bd-b448-0fc838efd730",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "network_traffic.dns",
        "duration": 68515700,
        "end": "2022-03-09T07:48:42.819Z",
        "ingested": "2022-03-09T07:48:43Z",
        "kind": "event",
        "start": "2022-03-09T07:48:42.751Z",
        "type": [
            "connection",
            "protocol"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "192.168.176.7"
        ],
        "mac": [
            "02-42-C0-A8-B0-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.47-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.3 LTS (Focal Fossa)"
        }
    },
    "method": "QUERY",
    "network": {
        "bytes": 195,
        "community_id": "1:3P4ruI0bVlqxiTAs0WyBhnF74ek=",
        "direction": "unknown",
        "protocol": "dns",
        "transport": "udp",
        "type": "ipv4"
    },
    "query": "class IN, type NS, elastic.co",
    "related": {
        "ip": [
            "192.168.238.68",
            "8.8.8.8"
        ]
    },
    "resource": "elastic.co",
    "server": {
        "bytes": 167,
        "ip": "8.8.8.8",
        "port": 53
    },
    "source": {
        "bytes": 28,
        "ip": "192.168.238.68",
        "port": 53765
    },
    "status": "OK",
    "type": "dns"
}
```

### HTTP

Fields published for HTTP packets.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.bytes | Bytes sent from the client to the server. | long |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| client.port | Port of the client. | long |
| client.process.args | The command-line of the process that initiated the transaction. | keyword |
| client.process.executable | Absolute path to the client process executable. | keyword |
| client.process.name | The name of the process that initiated the transaction. | keyword |
| client.process.start | The time the client process started. | date |
| client.process.working_directory | The working directory of the client process. | keyword |
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
| destination.bytes | Bytes sent from the destination to the source. | long |
| destination.domain | The domain name of the destination system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| flow.final | Indicates if event is last event in flow. If final is false, the event reports an intermediate flow state only. | boolean |
| flow.id | Internal flow ID based on connection meta data and address. | keyword |
| flow.vlan | VLAN identifier from the 802.1q frame. In case of a multi-tagged frame this field will be an array with the outer tag's VLAN identifier listed first. | long |
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
| http.request.body.bytes | Size in bytes of the request body. | long |
| http.request.bytes | Total size in bytes of the request (body and headers). | long |
| http.request.headers | A map containing the captured header fields from the request. Which headers to capture is configurable. If headers with the same header name are present in the message, they will be separated by commas. | flattened |
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| http.response.body.bytes | Size in bytes of the response body. | long |
| http.response.bytes | Total size in bytes of the response (body and headers). | long |
| http.response.headers | A map containing the captured header fields from the response. Which headers to capture is configurable. If headers with the same header name are present in the message, they will be separated by commas. | flattened |
| http.response.status_code | HTTP response status code. | long |
| http.response.status_phrase | The HTTP status phrase. | keyword |
| http.version | HTTP version. | keyword |
| method | The command/verb/method of the transaction. For HTTP, this is the method name (GET, POST, PUT, and so on), for SQL this is the verb (SELECT, UPDATE, DELETE, and so on). | keyword |
| network.bytes | Total bytes transferred in both directions. If `source.bytes` and `destination.bytes` are known, `network.bytes` is their sum. | long |
| network.community_id | A hash of source and destination IPs and ports, as well as the protocol used in a communication. This is a tool-agnostic standard to identify flows. Learn more at https://github.com/corelight/community-id-spec. | keyword |
| network.direction | Direction of the network traffic. Recommended values are:   \* ingress   \* egress   \* inbound   \* outbound   \* internal   \* external   \* unknown  When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.forwarded_ip | Host IP address when the source IP address is the proxy. | ip |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc The field value must be normalized to lowercase for querying. | keyword |
| params | The request parameters. For HTTP, these are the POST or GET parameters. For Thrift-RPC, these are the parameters from the request. | text |
| path | The path the transaction refers to. For HTTP, this is the URL. For SQL databases, this is the table name. For key-value stores, this is the key. | keyword |
| query | The query in a human readable format. For HTTP, it will typically be something like `GET /users/_search?name=test`. For MySQL, it is something like `SELECT id from users where name=test`. | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| request | For text protocols, this is the request as seen on the wire (application layer only). For binary protocols this is our representation of the request. | text |
| resource | The logical resource that this transaction refers to. For HTTP, this is the URL path up to the last slash (/). For example, if the URL is `/users/1`, the resource is `/users`. For databases, the resource is typically the table name. The field is not filled for all transaction types. | keyword |
| response | For text protocols, this is the response as seen on the wire (application layer only). For binary protocols this is our representation of the request. | text |
| server.bytes | Bytes sent from the server to the client. | long |
| server.domain | The domain name of the server system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| server.ip | IP address of the server (IPv4 or IPv6). | ip |
| server.port | Port of the server. | long |
| server.process.args | The command-line of the process that served the transaction. | keyword |
| server.process.executable | Absolute path to the server process executable. | keyword |
| server.process.name | The name of the process that served the transaction. | keyword |
| server.process.start | The time the server process started. | date |
| server.process.working_directory | The working directory of the server process. | keyword |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| status | The high level status of the transaction. The way to compute this value depends on the protocol, but the result has a meaning independent of the protocol. | keyword |
| type | The type of the transaction (for example, HTTP, MySQL, Redis, or RUM) or "flow" in case of flows. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| url.full | If full URLs are important to your use case, they should be stored in `url.full`, whether this field is reconstructed or present in the event source. | wildcard |
| url.path | Path of the request, such as "/search". | wildcard |
| url.port | Port of the request, such as 443. | long |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |


An example event for `http` looks as following:

```json
{
    "@timestamp": "2022-03-09T07:54:42.031Z",
    "agent": {
        "ephemeral_id": "822947c0-15fd-4278-ba0d-2cc64d687bb2",
        "id": "f789afb0-558d-48bd-b448-0fc838efd730",
        "name": "docker-fleet-agent",
        "type": "packetbeat",
        "version": "8.0.0"
    },
    "client": {
        "bytes": 211,
        "ip": "192.168.238.50",
        "port": 64770
    },
    "data_stream": {
        "dataset": "network_traffic.http",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "bytes": 9108,
        "domain": "packetbeat.com",
        "ip": "107.170.1.22",
        "port": 80
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "f789afb0-558d-48bd-b448-0fc838efd730",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "network_traffic.http",
        "duration": 141490400,
        "end": "2022-03-09T07:54:42.172Z",
        "ingested": "2022-03-09T07:54:43Z",
        "kind": "event",
        "start": "2022-03-09T07:54:42.031Z",
        "type": [
            "connection",
            "protocol"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "192.168.176.7"
        ],
        "mac": [
            "02-42-C0-A8-B0-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.47-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.3 LTS (Focal Fossa)"
        }
    },
    "http": {
        "request": {
            "body": {
                "bytes": 55
            },
            "bytes": 211,
            "headers": {
                "content-length": 55,
                "content-type": "application/x-www-form-urlencoded"
            },
            "method": "POST"
        },
        "response": {
            "body": {
                "bytes": 8936
            },
            "bytes": 9108,
            "headers": {
                "content-length": 8936,
                "content-type": "text/html; charset=utf-8"
            },
            "status_code": 404,
            "status_phrase": "not found"
        },
        "version": "1.1"
    },
    "method": "POST",
    "network": {
        "bytes": 9319,
        "community_id": "1:LREAuuDqOAxXEbzF064U0QX5FBs=",
        "direction": "unknown",
        "protocol": "http",
        "transport": "tcp",
        "type": "ipv4"
    },
    "query": "POST /register",
    "related": {
        "hosts": [
            "packetbeat.com"
        ],
        "ip": [
            "192.168.238.50",
            "107.170.1.22"
        ]
    },
    "server": {
        "bytes": 9108,
        "domain": "packetbeat.com",
        "ip": "107.170.1.22",
        "port": 80
    },
    "source": {
        "bytes": 211,
        "ip": "192.168.238.50",
        "port": 64770
    },
    "status": "Error",
    "type": "http",
    "url": {
        "domain": "packetbeat.com",
        "full": "http://packetbeat.com/register?address=anklamerstr.14b\u0026telephon=8932784368\u0026user=monica",
        "path": "/register",
        "query": "address=anklamerstr.14b\u0026telephon=8932784368\u0026user=monica",
        "scheme": "http"
    },
    "user_agent": {
        "original": "curl/7.37.1"
    }
}
```

### ICMP

Fields published for ICMP packets.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.bytes | Bytes sent from the client to the server. | long |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| client.port | Port of the client. | long |
| client.process.args | The command-line of the process that initiated the transaction. | keyword |
| client.process.executable | Absolute path to the client process executable. | keyword |
| client.process.name | The name of the process that initiated the transaction. | keyword |
| client.process.start | The time the client process started. | date |
| client.process.working_directory | The working directory of the client process. | keyword |
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
| destination.bytes | Bytes sent from the destination to the source. | long |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| flow.final | Indicates if event is last event in flow. If final is false, the event reports an intermediate flow state only. | boolean |
| flow.id | Internal flow ID based on connection meta data and address. | keyword |
| flow.vlan | VLAN identifier from the 802.1q frame. In case of a multi-tagged frame this field will be an array with the outer tag's VLAN identifier listed first. | long |
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
| icmp.request.code | The request code. | long |
| icmp.request.message | A human readable form of the request. | keyword |
| icmp.request.type | The request type. | long |
| icmp.response.code | The response code. | long |
| icmp.response.message | A human readable form of the response. | keyword |
| icmp.response.type | The response type. | long |
| icmp.version | The version of the ICMP protocol. | long |
| method | The command/verb/method of the transaction. For HTTP, this is the method name (GET, POST, PUT, and so on), for SQL this is the verb (SELECT, UPDATE, DELETE, and so on). | keyword |
| network.bytes | Total bytes transferred in both directions. If `source.bytes` and `destination.bytes` are known, `network.bytes` is their sum. | long |
| network.community_id | A hash of source and destination IPs and ports, as well as the protocol used in a communication. This is a tool-agnostic standard to identify flows. Learn more at https://github.com/corelight/community-id-spec. | keyword |
| network.direction | Direction of the network traffic. Recommended values are:   \* ingress   \* egress   \* inbound   \* outbound   \* internal   \* external   \* unknown  When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.forwarded_ip | Host IP address when the source IP address is the proxy. | ip |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc The field value must be normalized to lowercase for querying. | keyword |
| params | The request parameters. For HTTP, these are the POST or GET parameters. For Thrift-RPC, these are the parameters from the request. | text |
| path | The path the transaction refers to. For HTTP, this is the URL. For SQL databases, this is the table name. For key-value stores, this is the key. | keyword |
| query | The query in a human readable format. For HTTP, it will typically be something like `GET /users/_search?name=test`. For MySQL, it is something like `SELECT id from users where name=test`. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| request | For text protocols, this is the request as seen on the wire (application layer only). For binary protocols this is our representation of the request. | text |
| resource | The logical resource that this transaction refers to. For HTTP, this is the URL path up to the last slash (/). For example, if the URL is `/users/1`, the resource is `/users`. For databases, the resource is typically the table name. The field is not filled for all transaction types. | keyword |
| response | For text protocols, this is the response as seen on the wire (application layer only). For binary protocols this is our representation of the request. | text |
| server.bytes | Bytes sent from the server to the client. | long |
| server.ip | IP address of the server (IPv4 or IPv6). | ip |
| server.port | Port of the server. | long |
| server.process.args | The command-line of the process that served the transaction. | keyword |
| server.process.executable | Absolute path to the server process executable. | keyword |
| server.process.name | The name of the process that served the transaction. | keyword |
| server.process.start | The time the server process started. | date |
| server.process.working_directory | The working directory of the server process. | keyword |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| status | The high level status of the transaction. The way to compute this value depends on the protocol, but the result has a meaning independent of the protocol. | keyword |
| type | The type of the transaction (for example, HTTP, MySQL, Redis, or RUM) or "flow" in case of flows. | keyword |


An example event for `icmp` looks as following:

```json
{
    "@timestamp": "2022-03-09T07:57:32.766Z",
    "agent": {
        "ephemeral_id": "34e079a4-8dee-40db-a820-2296c225fbbe",
        "id": "f789afb0-558d-48bd-b448-0fc838efd730",
        "name": "docker-fleet-agent",
        "type": "packetbeat",
        "version": "8.0.0"
    },
    "client": {
        "bytes": 4,
        "ip": "::1"
    },
    "data_stream": {
        "dataset": "network_traffic.icmp",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "bytes": 4,
        "ip": "::2"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "f789afb0-558d-48bd-b448-0fc838efd730",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "network_traffic.icmp",
        "duration": 13336600,
        "end": "2022-03-09T07:57:32.779Z",
        "ingested": "2022-03-09T07:57:36Z",
        "kind": "event",
        "start": "2022-03-09T07:57:32.766Z",
        "type": [
            "connection"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "192.168.176.7"
        ],
        "mac": [
            "02-42-C0-A8-B0-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.47-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.3 LTS (Focal Fossa)"
        }
    },
    "icmp": {
        "request": {
            "code": 0,
            "message": "EchoRequest",
            "type": 128
        },
        "response": {
            "code": 0,
            "message": "EchoReply",
            "type": 129
        },
        "version": 6
    },
    "network": {
        "bytes": 8,
        "community_id": "1:9UpHcZHFAOl8WqZVOs5YRQ5wDGE=",
        "direction": "egress",
        "transport": "ipv6-icmp",
        "type": "ipv6"
    },
    "path": "::2",
    "related": {
        "ip": [
            "::1",
            "::2"
        ]
    },
    "server": {
        "bytes": 4,
        "ip": "::2"
    },
    "source": {
        "bytes": 4,
        "ip": "::1"
    },
    "status": "OK",
    "type": "icmp"
}
```

### Memcached

Fields published for Memcached packets.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.bytes | Bytes sent from the client to the server. | long |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| client.port | Port of the client. | long |
| client.process.args | The command-line of the process that initiated the transaction. | keyword |
| client.process.executable | Absolute path to the client process executable. | keyword |
| client.process.name | The name of the process that initiated the transaction. | keyword |
| client.process.start | The time the client process started. | date |
| client.process.working_directory | The working directory of the client process. | keyword |
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
| destination.bytes | Bytes sent from the destination to the source. | long |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| flow.final | Indicates if event is last event in flow. If final is false, the event reports an intermediate flow state only. | boolean |
| flow.id | Internal flow ID based on connection meta data and address. | keyword |
| flow.vlan | VLAN identifier from the 802.1q frame. In case of a multi-tagged frame this field will be an array with the outer tag's VLAN identifier listed first. | long |
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
| memcache.protocol_type | The memcache protocol implementation. The value can be "binary" for binary-based, "text" for text-based, or "unknown" for an unknown memcache protocol type. | keyword |
| memcache.request.automove | The automove mode in the 'slab automove' command expressed as a string. This value can be "standby"(=0), "slow"(=1), "aggressive"(=2), or the raw value if the value is unknown. | keyword |
| memcache.request.bytes | The byte count of the values being transferred. | long |
| memcache.request.cas_unique | The CAS (compare-and-swap) identifier if present. | long |
| memcache.request.command | The memcache command being requested in the memcache text protocol. For example "set" or "get". The binary protocol opcodes are translated into memcache text protocol commands. | keyword |
| memcache.request.count_values | The number of values found in the memcache request message. If the command does not send any data, this field is missing. | long |
| memcache.request.delta | The counter increment/decrement delta value. | long |
| memcache.request.dest_class | The destination class id in 'slab reassign' command. | long |
| memcache.request.exptime | The data expiry time in seconds sent with the memcache command (if present). If the value is `\< 30` days, the expiry time is relative to "now", or else it is an absolute Unix time in seconds (32-bit). | long |
| memcache.request.flags | The memcache command flags sent in the request (if present). | long |
| memcache.request.initial | The counter increment/decrement initial value parameter (binary protocol only). | long |
| memcache.request.keys | The list of keys sent in the store or load commands. | array |
| memcache.request.line | The raw command line for unknown commands ONLY. | keyword |
| memcache.request.noreply | Set to true if noreply was set in the request. The `memcache.response` field will be missing. | boolean |
| memcache.request.opaque | The binary protocol opaque header value used for correlating request with response messages. | long |
| memcache.request.opcode | The binary protocol message opcode name. | keyword |
| memcache.request.opcode_value | The binary protocol message opcode value. | long |
| memcache.request.quiet | Set to true if the binary protocol message is to be treated as a quiet message. | boolean |
| memcache.request.raw_args | The text protocol raw arguments for the "stats ..." and "lru crawl ..." commands. | keyword |
| memcache.request.sleep_us | The sleep setting in microseconds for the 'lru_crawler sleep' command. | long |
| memcache.request.source_class | The source class id in 'slab reassign' command. | long |
| memcache.request.type | The memcache command classification. This value can be "UNKNOWN", "Load", "Store", "Delete", "Counter", "Info", "SlabCtrl", "LRUCrawler", "Stats", "Success", "Fail", or "Auth". | keyword |
| memcache.request.values | The list of base64 encoded values sent with the request (if present). | array |
| memcache.request.vbucket | The vbucket index sent in the binary message. | long |
| memcache.request.verbosity | The value of the memcache "verbosity" command. | long |
| memcache.response.bytes | The byte count of the values being transferred. | long |
| memcache.response.cas_unique | The CAS (compare-and-swap) identifier to be used with CAS-based updates (if present). | long |
| memcache.response.command | Either the text based protocol response message type or the name of the originating request if binary protocol is used. | keyword |
| memcache.response.count_values | The number of values found in the memcache response message. If the command does not send any data, this field is missing. | long |
| memcache.response.error_msg | The optional error message in the memcache response (text based protocol only). | keyword |
| memcache.response.flags | The memcache message flags sent in the response (if present). | long |
| memcache.response.keys | The list of keys returned for the load command (if present). | array |
| memcache.response.opaque | The binary protocol opaque header value used for correlating request with response messages. | long |
| memcache.response.opcode | The binary protocol message opcode name. | keyword |
| memcache.response.opcode_value | The binary protocol message opcode value. | long |
| memcache.response.stats | The list of statistic values returned. Each entry is a dictionary with the fields "name" and "value". | array |
| memcache.response.status | The textual representation of the response error code (binary protocol only). | keyword |
| memcache.response.status_code | The status code value returned in the response (binary protocol only). | long |
| memcache.response.type | The memcache command classification. This value can be "UNKNOWN", "Load", "Store", "Delete", "Counter", "Info", "SlabCtrl", "LRUCrawler", "Stats", "Success", "Fail", or "Auth". The text based protocol will employ any of these, whereas the binary based protocol will mirror the request commands only (see `memcache.response.status` for binary protocol). | keyword |
| memcache.response.value | The counter value returned by a counter operation. | long |
| memcache.response.values | The list of base64 encoded values sent with the response (if present). | array |
| memcache.response.version | The returned memcache version string. | keyword |
| method | The command/verb/method of the transaction. For HTTP, this is the method name (GET, POST, PUT, and so on), for SQL this is the verb (SELECT, UPDATE, DELETE, and so on). | keyword |
| network.bytes | Total bytes transferred in both directions. If `source.bytes` and `destination.bytes` are known, `network.bytes` is their sum. | long |
| network.community_id | A hash of source and destination IPs and ports, as well as the protocol used in a communication. This is a tool-agnostic standard to identify flows. Learn more at https://github.com/corelight/community-id-spec. | keyword |
| network.direction | Direction of the network traffic. Recommended values are:   \* ingress   \* egress   \* inbound   \* outbound   \* internal   \* external   \* unknown  When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.forwarded_ip | Host IP address when the source IP address is the proxy. | ip |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc The field value must be normalized to lowercase for querying. | keyword |
| params | The request parameters. For HTTP, these are the POST or GET parameters. For Thrift-RPC, these are the parameters from the request. | text |
| path | The path the transaction refers to. For HTTP, this is the URL. For SQL databases, this is the table name. For key-value stores, this is the key. | keyword |
| query | The query in a human readable format. For HTTP, it will typically be something like `GET /users/_search?name=test`. For MySQL, it is something like `SELECT id from users where name=test`. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| request | For text protocols, this is the request as seen on the wire (application layer only). For binary protocols this is our representation of the request. | text |
| resource | The logical resource that this transaction refers to. For HTTP, this is the URL path up to the last slash (/). For example, if the URL is `/users/1`, the resource is `/users`. For databases, the resource is typically the table name. The field is not filled for all transaction types. | keyword |
| response | For text protocols, this is the response as seen on the wire (application layer only). For binary protocols this is our representation of the request. | text |
| server.bytes | Bytes sent from the server to the client. | long |
| server.ip | IP address of the server (IPv4 or IPv6). | ip |
| server.port | Port of the server. | long |
| server.process.args | The command-line of the process that served the transaction. | keyword |
| server.process.executable | Absolute path to the server process executable. | keyword |
| server.process.name | The name of the process that served the transaction. | keyword |
| server.process.start | The time the server process started. | date |
| server.process.working_directory | The working directory of the server process. | keyword |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| status | The high level status of the transaction. The way to compute this value depends on the protocol, but the result has a meaning independent of the protocol. | keyword |
| type | The type of the transaction (for example, HTTP, MySQL, Redis, or RUM) or "flow" in case of flows. | keyword |


An example event for `memcached` looks as following:

```json
{
    "@timestamp": "2022-03-09T08:09:26.564Z",
    "agent": {
        "ephemeral_id": "53c3aab1-4c1d-4f33-87a9-1d1d4ce75205",
        "id": "f789afb0-558d-48bd-b448-0fc838efd730",
        "name": "docker-fleet-agent",
        "type": "packetbeat",
        "version": "8.0.0"
    },
    "client": {
        "ip": "192.168.188.37",
        "port": 65195
    },
    "data_stream": {
        "dataset": "network_traffic.memcached",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "bytes": 1064,
        "ip": "192.168.188.38",
        "port": 11211
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "f789afb0-558d-48bd-b448-0fc838efd730",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "network_traffic.memcached",
        "ingested": "2022-03-09T08:09:37Z",
        "kind": "event",
        "start": "2022-03-09T08:09:26.564Z",
        "type": [
            "connection",
            "protocol"
        ]
    },
    "event.action": "memcache.store",
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "192.168.176.7"
        ],
        "mac": [
            "02-42-C0-A8-B0-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.47-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.3 LTS (Focal Fossa)"
        }
    },
    "memcache": {
        "protocol_type": "binary",
        "request": {
            "bytes": 1024,
            "command": "set",
            "count_values": 1,
            "exptime": 0,
            "flags": 0,
            "keys": [
                "test_key"
            ],
            "opaque": 65536,
            "opcode": "SetQ",
            "opcode_value": 17,
            "quiet": true,
            "type": "Store",
            "vbucket": 0
        }
    },
    "network": {
        "bytes": 1064,
        "community_id": "1:QMbWqXK5vGDDbp48SEFuFe8Z1lQ=",
        "direction": "unknown",
        "protocol": "memcache",
        "transport": "udp",
        "type": "ipv4"
    },
    "related": {
        "ip": [
            "192.168.188.37",
            "192.168.188.38"
        ]
    },
    "server": {
        "bytes": 1064,
        "ip": "192.168.188.38",
        "port": 11211
    },
    "source": {
        "ip": "192.168.188.37",
        "port": 65195
    },
    "status": "OK",
    "type": "memcache"
}
```

### MongoDB

Fields published for MongoDB packets.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.bytes | Bytes sent from the client to the server. | long |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| client.port | Port of the client. | long |
| client.process.args | The command-line of the process that initiated the transaction. | keyword |
| client.process.executable | Absolute path to the client process executable. | keyword |
| client.process.name | The name of the process that initiated the transaction. | keyword |
| client.process.start | The time the client process started. | date |
| client.process.working_directory | The working directory of the client process. | keyword |
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
| destination.bytes | Bytes sent from the destination to the source. | long |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| flow.final | Indicates if event is last event in flow. If final is false, the event reports an intermediate flow state only. | boolean |
| flow.id | Internal flow ID based on connection meta data and address. | keyword |
| flow.vlan | VLAN identifier from the 802.1q frame. In case of a multi-tagged frame this field will be an array with the outer tag's VLAN identifier listed first. | long |
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
| method | The command/verb/method of the transaction. For HTTP, this is the method name (GET, POST, PUT, and so on), for SQL this is the verb (SELECT, UPDATE, DELETE, and so on). | keyword |
| mongodb.cursorId | The cursor identifier returned in the OP_REPLY. This must be the value that was returned from the database. | keyword |
| mongodb.error | If the MongoDB request has resulted in an error, this field contains the error message returned by the server. | keyword |
| mongodb.fullCollectionName | The full collection name. The full collection name is the concatenation of the database name with the collection name, using a dot (.) for the concatenation. For example, for the database foo and the collection bar, the full collection name is foo.bar. | keyword |
| mongodb.numberReturned | The number of documents in the reply. | long |
| mongodb.numberToReturn | The requested maximum number of documents to be returned. | long |
| mongodb.numberToSkip | Sets the number of documents to omit - starting from the first document in the resulting dataset - when returning the result of the query. | long |
| mongodb.query | A JSON document that represents the query. The query will contain one or more elements, all of which must match for a document to be included in the result set. Possible elements include $query, $orderby, $hint, $explain, and $snapshot. | keyword |
| mongodb.returnFieldsSelector | A JSON document that limits the fields in the returned documents. The returnFieldsSelector contains one or more elements, each of which is the name of a field that should be returned, and the integer value 1. | keyword |
| mongodb.selector | A BSON document that specifies the query for selecting the document to update or delete. | keyword |
| mongodb.startingFrom | Where in the cursor this reply is starting. | keyword |
| mongodb.update | A BSON document that specifies the update to be performed. For information on specifying updates, see the Update Operations documentation from the MongoDB Manual. | keyword |
| network.bytes | Total bytes transferred in both directions. If `source.bytes` and `destination.bytes` are known, `network.bytes` is their sum. | long |
| network.community_id | A hash of source and destination IPs and ports, as well as the protocol used in a communication. This is a tool-agnostic standard to identify flows. Learn more at https://github.com/corelight/community-id-spec. | keyword |
| network.direction | Direction of the network traffic. Recommended values are:   \* ingress   \* egress   \* inbound   \* outbound   \* internal   \* external   \* unknown  When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.forwarded_ip | Host IP address when the source IP address is the proxy. | ip |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc The field value must be normalized to lowercase for querying. | keyword |
| params | The request parameters. For HTTP, these are the POST or GET parameters. For Thrift-RPC, these are the parameters from the request. | text |
| path | The path the transaction refers to. For HTTP, this is the URL. For SQL databases, this is the table name. For key-value stores, this is the key. | keyword |
| query | The query in a human readable format. For HTTP, it will typically be something like `GET /users/_search?name=test`. For MySQL, it is something like `SELECT id from users where name=test`. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| request | For text protocols, this is the request as seen on the wire (application layer only). For binary protocols this is our representation of the request. | text |
| resource | The logical resource that this transaction refers to. For HTTP, this is the URL path up to the last slash (/). For example, if the URL is `/users/1`, the resource is `/users`. For databases, the resource is typically the table name. The field is not filled for all transaction types. | keyword |
| response | For text protocols, this is the response as seen on the wire (application layer only). For binary protocols this is our representation of the request. | text |
| server.bytes | Bytes sent from the server to the client. | long |
| server.ip | IP address of the server (IPv4 or IPv6). | ip |
| server.port | Port of the server. | long |
| server.process.args | The command-line of the process that served the transaction. | keyword |
| server.process.executable | Absolute path to the server process executable. | keyword |
| server.process.name | The name of the process that served the transaction. | keyword |
| server.process.start | The time the server process started. | date |
| server.process.working_directory | The working directory of the server process. | keyword |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| status | The high level status of the transaction. The way to compute this value depends on the protocol, but the result has a meaning independent of the protocol. | keyword |
| type | The type of the transaction (for example, HTTP, MySQL, Redis, or RUM) or "flow" in case of flows. | keyword |


An example event for `mongodb` looks as following:

```json
{
    "@timestamp": "2022-03-09T08:15:48.570Z",
    "agent": {
        "ephemeral_id": "fafaeb02-c623-46a0-a3e0-72e035bd12ba",
        "id": "f789afb0-558d-48bd-b448-0fc838efd730",
        "name": "docker-fleet-agent",
        "type": "packetbeat",
        "version": "8.0.0"
    },
    "client": {
        "bytes": 50,
        "ip": "127.0.0.1",
        "port": 57203
    },
    "data_stream": {
        "dataset": "network_traffic.mongodb",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "bytes": 514,
        "ip": "127.0.0.1",
        "port": 27017
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "f789afb0-558d-48bd-b448-0fc838efd730",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "network_traffic.mongodb",
        "duration": 1365900,
        "end": "2022-03-09T08:15:48.571Z",
        "ingested": "2022-03-09T08:15:49Z",
        "kind": "event",
        "start": "2022-03-09T08:15:48.570Z",
        "type": [
            "connection",
            "protocol"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "192.168.176.7"
        ],
        "mac": [
            "02-42-C0-A8-B0-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.47-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.3 LTS (Focal Fossa)"
        }
    },
    "method": "find",
    "mongodb": {
        "cursorId": 0,
        "fullCollectionName": "test.restaurants",
        "numberReturned": 1,
        "numberToReturn": 1,
        "numberToSkip": 0,
        "startingFrom": 0
    },
    "network": {
        "bytes": 564,
        "community_id": "1:mYSTZ4QZBfvJO05Em9TnPwrae6g=",
        "direction": "ingress",
        "protocol": "mongodb",
        "transport": "tcp",
        "type": "ipv4"
    },
    "query": "test.restaurants.find().limit(1)",
    "related": {
        "ip": [
            "127.0.0.1"
        ]
    },
    "resource": "test.restaurants",
    "server": {
        "bytes": 514,
        "ip": "127.0.0.1",
        "port": 27017
    },
    "source": {
        "bytes": 50,
        "ip": "127.0.0.1",
        "port": 57203
    },
    "status": "OK",
    "type": "mongodb"
}
```

### MySQL

Fields published for MySQL packets.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.bytes | Bytes sent from the client to the server. | long |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| client.port | Port of the client. | long |
| client.process.args | The command-line of the process that initiated the transaction. | keyword |
| client.process.executable | Absolute path to the client process executable. | keyword |
| client.process.name | The name of the process that initiated the transaction. | keyword |
| client.process.start | The time the client process started. | date |
| client.process.working_directory | The working directory of the client process. | keyword |
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
| destination.bytes | Bytes sent from the destination to the source. | long |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| flow.final | Indicates if event is last event in flow. If final is false, the event reports an intermediate flow state only. | boolean |
| flow.id | Internal flow ID based on connection meta data and address. | keyword |
| flow.vlan | VLAN identifier from the 802.1q frame. In case of a multi-tagged frame this field will be an array with the outer tag's VLAN identifier listed first. | long |
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
| method | The command/verb/method of the transaction. For HTTP, this is the method name (GET, POST, PUT, and so on), for SQL this is the verb (SELECT, UPDATE, DELETE, and so on). | keyword |
| mysql.affected_rows | If the MySQL command is successful, this field contains the affected number of rows of the last statement. | long |
| mysql.error_code | The error code returned by MySQL. | long |
| mysql.error_message | The error info message returned by MySQL. | keyword |
| mysql.insert_id | If the INSERT query is successful, this field contains the id of the newly inserted row. | keyword |
| mysql.num_fields | If the SELECT query is successful, this field is set to the number of fields returned. | long |
| mysql.num_rows | If the SELECT query is successful, this field is set to the number of rows returned. | long |
| mysql.query | The row mysql query as read from the transaction's request. | keyword |
| network.bytes | Total bytes transferred in both directions. If `source.bytes` and `destination.bytes` are known, `network.bytes` is their sum. | long |
| network.community_id | A hash of source and destination IPs and ports, as well as the protocol used in a communication. This is a tool-agnostic standard to identify flows. Learn more at https://github.com/corelight/community-id-spec. | keyword |
| network.direction | Direction of the network traffic. Recommended values are:   \* ingress   \* egress   \* inbound   \* outbound   \* internal   \* external   \* unknown  When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.forwarded_ip | Host IP address when the source IP address is the proxy. | ip |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc The field value must be normalized to lowercase for querying. | keyword |
| params | The request parameters. For HTTP, these are the POST or GET parameters. For Thrift-RPC, these are the parameters from the request. | text |
| path | The path the transaction refers to. For HTTP, this is the URL. For SQL databases, this is the table name. For key-value stores, this is the key. | keyword |
| query | The query in a human readable format. For HTTP, it will typically be something like `GET /users/_search?name=test`. For MySQL, it is something like `SELECT id from users where name=test`. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| request | For text protocols, this is the request as seen on the wire (application layer only). For binary protocols this is our representation of the request. | text |
| resource | The logical resource that this transaction refers to. For HTTP, this is the URL path up to the last slash (/). For example, if the URL is `/users/1`, the resource is `/users`. For databases, the resource is typically the table name. The field is not filled for all transaction types. | keyword |
| response | For text protocols, this is the response as seen on the wire (application layer only). For binary protocols this is our representation of the request. | text |
| server.bytes | Bytes sent from the server to the client. | long |
| server.ip | IP address of the server (IPv4 or IPv6). | ip |
| server.port | Port of the server. | long |
| server.process.args | The command-line of the process that served the transaction. | keyword |
| server.process.executable | Absolute path to the server process executable. | keyword |
| server.process.name | The name of the process that served the transaction. | keyword |
| server.process.start | The time the server process started. | date |
| server.process.working_directory | The working directory of the server process. | keyword |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| status | The high level status of the transaction. The way to compute this value depends on the protocol, but the result has a meaning independent of the protocol. | keyword |
| type | The type of the transaction (for example, HTTP, MySQL, Redis, or RUM) or "flow" in case of flows. | keyword |


An example event for `mysql` looks as following:

```json
{
    "@timestamp": "2022-03-09T08:20:44.667Z",
    "agent": {
        "ephemeral_id": "43167926-7ebd-4acd-8216-daf3664fe286",
        "id": "f789afb0-558d-48bd-b448-0fc838efd730",
        "name": "docker-fleet-agent",
        "type": "packetbeat",
        "version": "8.0.0"
    },
    "client": {
        "bytes": 23,
        "ip": "127.0.0.1",
        "port": 41517
    },
    "data_stream": {
        "dataset": "network_traffic.mysql",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "bytes": 3629,
        "ip": "127.0.0.1",
        "port": 3306
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "f789afb0-558d-48bd-b448-0fc838efd730",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "network_traffic.mysql",
        "duration": 5532500,
        "end": "2022-03-09T08:20:44.673Z",
        "ingested": "2022-03-09T08:20:45Z",
        "kind": "event",
        "start": "2022-03-09T08:20:44.667Z",
        "type": [
            "connection",
            "protocol"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "192.168.176.7"
        ],
        "mac": [
            "02-42-C0-A8-B0-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.47-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.3 LTS (Focal Fossa)"
        }
    },
    "method": "SELECT",
    "mysql": {
        "affected_rows": 0,
        "insert_id": 0,
        "num_fields": 3,
        "num_rows": 15
    },
    "network": {
        "bytes": 3652,
        "community_id": "1:goIcZn7CMIJ6W7Yf8JRV618zzxA=",
        "direction": "ingress",
        "protocol": "mysql",
        "transport": "tcp",
        "type": "ipv4"
    },
    "path": "test.test",
    "query": "select * from test",
    "related": {
        "ip": [
            "127.0.0.1"
        ]
    },
    "server": {
        "bytes": 3629,
        "ip": "127.0.0.1",
        "port": 3306
    },
    "source": {
        "bytes": 23,
        "ip": "127.0.0.1",
        "port": 41517
    },
    "status": "OK",
    "type": "mysql"
}
```

### NFS

Fields published for NFS packets.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.bytes | Bytes sent from the client to the server. | long |
| client.domain | The domain name of the client system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| client.port | Port of the client. | long |
| client.process.args | The command-line of the process that initiated the transaction. | keyword |
| client.process.executable | Absolute path to the client process executable. | keyword |
| client.process.name | The name of the process that initiated the transaction. | keyword |
| client.process.start | The time the client process started. | date |
| client.process.working_directory | The working directory of the client process. | keyword |
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
| destination.bytes | Bytes sent from the destination to the source. | long |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| flow.final | Indicates if event is last event in flow. If final is false, the event reports an intermediate flow state only. | boolean |
| flow.id | Internal flow ID based on connection meta data and address. | keyword |
| flow.vlan | VLAN identifier from the 802.1q frame. In case of a multi-tagged frame this field will be an array with the outer tag's VLAN identifier listed first. | long |
| group.id | Unique identifier for the group on the system/platform. | keyword |
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
| method | The command/verb/method of the transaction. For HTTP, this is the method name (GET, POST, PUT, and so on), for SQL this is the verb (SELECT, UPDATE, DELETE, and so on). | keyword |
| network.bytes | Total bytes transferred in both directions. If `source.bytes` and `destination.bytes` are known, `network.bytes` is their sum. | long |
| network.community_id | A hash of source and destination IPs and ports, as well as the protocol used in a communication. This is a tool-agnostic standard to identify flows. Learn more at https://github.com/corelight/community-id-spec. | keyword |
| network.direction | Direction of the network traffic. Recommended values are:   \* ingress   \* egress   \* inbound   \* outbound   \* internal   \* external   \* unknown  When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.forwarded_ip | Host IP address when the source IP address is the proxy. | ip |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc The field value must be normalized to lowercase for querying. | keyword |
| nfs.minor_version | NFS protocol minor version number. | long |
| nfs.opcode | NFS operation name, or main operation name, in case of COMPOUND calls. | keyword |
| nfs.status | NFS operation reply status. | keyword |
| nfs.tag | NFS v4 COMPOUND operation tag. | keyword |
| nfs.version | NFS protocol version number. | long |
| params | The request parameters. For HTTP, these are the POST or GET parameters. For Thrift-RPC, these are the parameters from the request. | text |
| path | The path the transaction refers to. For HTTP, this is the URL. For SQL databases, this is the table name. For key-value stores, this is the key. | keyword |
| query | The query in a human readable format. For HTTP, it will typically be something like `GET /users/_search?name=test`. For MySQL, it is something like `SELECT id from users where name=test`. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| request | For text protocols, this is the request as seen on the wire (application layer only). For binary protocols this is our representation of the request. | text |
| resource | The logical resource that this transaction refers to. For HTTP, this is the URL path up to the last slash (/). For example, if the URL is `/users/1`, the resource is `/users`. For databases, the resource is typically the table name. The field is not filled for all transaction types. | keyword |
| response | For text protocols, this is the response as seen on the wire (application layer only). For binary protocols this is our representation of the request. | text |
| rpc.auth_flavor | RPC authentication flavor. | keyword |
| rpc.cred.gid | RPC caller's group id, in case of auth-unix. | long |
| rpc.cred.gids | RPC caller's secondary group ids, in case of auth-unix. | long |
| rpc.cred.machinename | The name of the caller's machine. | keyword |
| rpc.cred.stamp | Arbitrary ID which the caller machine may generate. | long |
| rpc.cred.uid | RPC caller's user id, in case of auth-unix. | long |
| rpc.status | RPC message reply status. | keyword |
| rpc.xid | RPC message transaction identifier. | keyword |
| server.bytes | Bytes sent from the server to the client. | long |
| server.ip | IP address of the server (IPv4 or IPv6). | ip |
| server.port | Port of the server. | long |
| server.process.args | The command-line of the process that served the transaction. | keyword |
| server.process.executable | Absolute path to the server process executable. | keyword |
| server.process.name | The name of the process that served the transaction. | keyword |
| server.process.start | The time the server process started. | date |
| server.process.working_directory | The working directory of the server process. | keyword |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.domain | The domain name of the source system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| status | The high level status of the transaction. The way to compute this value depends on the protocol, but the result has a meaning independent of the protocol. | keyword |
| type | The type of the transaction (for example, HTTP, MySQL, Redis, or RUM) or "flow" in case of flows. | keyword |
| user.id | Unique identifier of the user. | keyword |


An example event for `nfs` looks as following:

```json
{
    "@timestamp": "2022-03-09T08:24:00.569Z",
    "agent": {
        "ephemeral_id": "62904593-11a1-4706-8487-78b14fb72c08",
        "id": "f789afb0-558d-48bd-b448-0fc838efd730",
        "name": "docker-fleet-agent",
        "type": "packetbeat",
        "version": "8.0.0"
    },
    "client": {
        "bytes": 208,
        "domain": "desycloud03.desy.de",
        "ip": "131.169.5.156",
        "port": 907
    },
    "data_stream": {
        "dataset": "network_traffic.nfs",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "bytes": 176,
        "ip": "131.169.192.35",
        "port": 2049
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "f789afb0-558d-48bd-b448-0fc838efd730",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "action": "nfs.CLOSE",
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "network_traffic.nfs",
        "duration": 6573500,
        "end": "2022-03-09T08:24:00.575Z",
        "ingested": "2022-03-09T08:24:01Z",
        "kind": "event",
        "start": "2022-03-09T08:24:00.569Z",
        "type": [
            "connection",
            "protocol"
        ]
    },
    "group.id": 48,
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "192.168.176.7"
        ],
        "mac": [
            "02-42-C0-A8-B0-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.47-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.3 LTS (Focal Fossa)"
        }
    },
    "host.hostname": "desycloud03.desy.de",
    "network": {
        "bytes": 384,
        "community_id": "1:cd5eLXemAsSPMdXwCbdDUWWud4M=",
        "direction": "unknown",
        "protocol": "nfsv4",
        "transport": "tcp",
        "type": "ipv4"
    },
    "nfs": {
        "minor_version": 1,
        "opcode": "CLOSE",
        "status": "NFS_OK",
        "tag": "",
        "version": 4
    },
    "related": {
        "ip": [
            "131.169.5.156",
            "131.169.192.35"
        ]
    },
    "rpc": {
        "auth_flavor": "unix",
        "cred": {
            "gid": 48,
            "gids": [
                48
            ],
            "machinename": "desycloud03.desy.de",
            "stamp": 4308441,
            "uid": 48
        },
        "status": "success",
        "xid": "c3103fc1"
    },
    "server": {
        "bytes": 176,
        "ip": "131.169.192.35",
        "port": 2049
    },
    "source": {
        "bytes": 208,
        "domain": "desycloud03.desy.de",
        "ip": "131.169.5.156",
        "port": 907
    },
    "status": "OK",
    "type": "nfs",
    "user.id": 48
}
```

### PostgreSQL

Fields published for PostgreSQL packets.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.bytes | Bytes sent from the client to the server. | long |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| client.port | Port of the client. | long |
| client.process.args | The command-line of the process that initiated the transaction. | keyword |
| client.process.executable | Absolute path to the client process executable. | keyword |
| client.process.name | The name of the process that initiated the transaction. | keyword |
| client.process.start | The time the client process started. | date |
| client.process.working_directory | The working directory of the client process. | keyword |
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
| destination.bytes | Bytes sent from the destination to the source. | long |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| flow.final | Indicates if event is last event in flow. If final is false, the event reports an intermediate flow state only. | boolean |
| flow.id | Internal flow ID based on connection meta data and address. | keyword |
| flow.vlan | VLAN identifier from the 802.1q frame. In case of a multi-tagged frame this field will be an array with the outer tag's VLAN identifier listed first. | long |
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
| method | The command/verb/method of the transaction. For HTTP, this is the method name (GET, POST, PUT, and so on), for SQL this is the verb (SELECT, UPDATE, DELETE, and so on). | keyword |
| network.bytes | Total bytes transferred in both directions. If `source.bytes` and `destination.bytes` are known, `network.bytes` is their sum. | long |
| network.community_id | A hash of source and destination IPs and ports, as well as the protocol used in a communication. This is a tool-agnostic standard to identify flows. Learn more at https://github.com/corelight/community-id-spec. | keyword |
| network.direction | Direction of the network traffic. Recommended values are:   \* ingress   \* egress   \* inbound   \* outbound   \* internal   \* external   \* unknown  When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.forwarded_ip | Host IP address when the source IP address is the proxy. | ip |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc The field value must be normalized to lowercase for querying. | keyword |
| params | The request parameters. For HTTP, these are the POST or GET parameters. For Thrift-RPC, these are the parameters from the request. | text |
| path | The path the transaction refers to. For HTTP, this is the URL. For SQL databases, this is the table name. For key-value stores, this is the key. | keyword |
| pgsql.error_code | The PostgreSQL error code. | keyword |
| pgsql.error_message | The PostgreSQL error message. | keyword |
| pgsql.error_severity | The PostgreSQL error severity. | keyword |
| pgsql.num_fields | If the SELECT query if successful, this field is set to the number of fields returned. | long |
| pgsql.num_rows | If the SELECT query if successful, this field is set to the number of rows returned. | long |
| query | The query in a human readable format. For HTTP, it will typically be something like `GET /users/_search?name=test`. For MySQL, it is something like `SELECT id from users where name=test`. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| request | For text protocols, this is the request as seen on the wire (application layer only). For binary protocols this is our representation of the request. | text |
| resource | The logical resource that this transaction refers to. For HTTP, this is the URL path up to the last slash (/). For example, if the URL is `/users/1`, the resource is `/users`. For databases, the resource is typically the table name. The field is not filled for all transaction types. | keyword |
| response | For text protocols, this is the response as seen on the wire (application layer only). For binary protocols this is our representation of the request. | text |
| server.bytes | Bytes sent from the server to the client. | long |
| server.ip | IP address of the server (IPv4 or IPv6). | ip |
| server.port | Port of the server. | long |
| server.process.args | The command-line of the process that served the transaction. | keyword |
| server.process.executable | Absolute path to the server process executable. | keyword |
| server.process.name | The name of the process that served the transaction. | keyword |
| server.process.start | The time the server process started. | date |
| server.process.working_directory | The working directory of the server process. | keyword |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| status | The high level status of the transaction. The way to compute this value depends on the protocol, but the result has a meaning independent of the protocol. | keyword |
| type | The type of the transaction (for example, HTTP, MySQL, Redis, or RUM) or "flow" in case of flows. | keyword |


An example event for `pgsql` looks as following:

```json
{
    "@timestamp": "2022-03-09T08:29:39.675Z",
    "agent": {
        "ephemeral_id": "1e05998c-1d97-426b-8d9e-f5f92c446612",
        "id": "f789afb0-558d-48bd-b448-0fc838efd730",
        "name": "docker-fleet-agent",
        "type": "packetbeat",
        "version": "8.0.0"
    },
    "client": {
        "bytes": 34,
        "ip": "127.0.0.1",
        "port": 34936
    },
    "data_stream": {
        "dataset": "network_traffic.pgsql",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "bytes": 3186,
        "ip": "127.0.0.1",
        "port": 5432
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "f789afb0-558d-48bd-b448-0fc838efd730",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "network_traffic.pgsql",
        "duration": 2568100,
        "end": "2022-03-09T08:29:39.678Z",
        "ingested": "2022-03-09T08:29:40Z",
        "kind": "event",
        "start": "2022-03-09T08:29:39.675Z",
        "type": [
            "connection",
            "protocol"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "192.168.176.7"
        ],
        "mac": [
            "02-42-C0-A8-B0-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.47-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.3 LTS (Focal Fossa)"
        }
    },
    "method": "SELECT",
    "network": {
        "bytes": 3220,
        "community_id": "1:WUuTzESSpZnUwZ2tuZKZtNOdHSU=",
        "direction": "ingress",
        "protocol": "pgsql",
        "transport": "tcp",
        "type": "ipv4"
    },
    "pgsql": {
        "num_fields": 3,
        "num_rows": 15
    },
    "query": "select * from long_response",
    "related": {
        "ip": [
            "127.0.0.1"
        ]
    },
    "server": {
        "bytes": 3186,
        "ip": "127.0.0.1",
        "port": 5432
    },
    "source": {
        "bytes": 34,
        "ip": "127.0.0.1",
        "port": 34936
    },
    "status": "OK",
    "type": "pgsql"
}
```

### Redis

Fields published for Redis packets.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.bytes | Bytes sent from the client to the server. | long |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| client.port | Port of the client. | long |
| client.process.args | The command-line of the process that initiated the transaction. | keyword |
| client.process.executable | Absolute path to the client process executable. | keyword |
| client.process.name | The name of the process that initiated the transaction. | keyword |
| client.process.start | The time the client process started. | date |
| client.process.working_directory | The working directory of the client process. | keyword |
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
| destination.bytes | Bytes sent from the destination to the source. | long |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| flow.final | Indicates if event is last event in flow. If final is false, the event reports an intermediate flow state only. | boolean |
| flow.id | Internal flow ID based on connection meta data and address. | keyword |
| flow.vlan | VLAN identifier from the 802.1q frame. In case of a multi-tagged frame this field will be an array with the outer tag's VLAN identifier listed first. | long |
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
| method | The command/verb/method of the transaction. For HTTP, this is the method name (GET, POST, PUT, and so on), for SQL this is the verb (SELECT, UPDATE, DELETE, and so on). | keyword |
| network.bytes | Total bytes transferred in both directions. If `source.bytes` and `destination.bytes` are known, `network.bytes` is their sum. | long |
| network.community_id | A hash of source and destination IPs and ports, as well as the protocol used in a communication. This is a tool-agnostic standard to identify flows. Learn more at https://github.com/corelight/community-id-spec. | keyword |
| network.direction | Direction of the network traffic. Recommended values are:   \* ingress   \* egress   \* inbound   \* outbound   \* internal   \* external   \* unknown  When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.forwarded_ip | Host IP address when the source IP address is the proxy. | ip |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc The field value must be normalized to lowercase for querying. | keyword |
| params | The request parameters. For HTTP, these are the POST or GET parameters. For Thrift-RPC, these are the parameters from the request. | text |
| path | The path the transaction refers to. For HTTP, this is the URL. For SQL databases, this is the table name. For key-value stores, this is the key. | keyword |
| query | The query in a human readable format. For HTTP, it will typically be something like `GET /users/_search?name=test`. For MySQL, it is something like `SELECT id from users where name=test`. | keyword |
| redis.error | If the Redis command has resulted in an error, this field contains the error message returned by the Redis server. | keyword |
| redis.return_value | The return value of the Redis command in a human readable format. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| request | For text protocols, this is the request as seen on the wire (application layer only). For binary protocols this is our representation of the request. | text |
| resource | The logical resource that this transaction refers to. For HTTP, this is the URL path up to the last slash (/). For example, if the URL is `/users/1`, the resource is `/users`. For databases, the resource is typically the table name. The field is not filled for all transaction types. | keyword |
| response | For text protocols, this is the response as seen on the wire (application layer only). For binary protocols this is our representation of the request. | text |
| server.bytes | Bytes sent from the server to the client. | long |
| server.ip | IP address of the server (IPv4 or IPv6). | ip |
| server.port | Port of the server. | long |
| server.process.args | The command-line of the process that served the transaction. | keyword |
| server.process.executable | Absolute path to the server process executable. | keyword |
| server.process.name | The name of the process that served the transaction. | keyword |
| server.process.start | The time the server process started. | date |
| server.process.working_directory | The working directory of the server process. | keyword |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| status | The high level status of the transaction. The way to compute this value depends on the protocol, but the result has a meaning independent of the protocol. | keyword |
| type | The type of the transaction (for example, HTTP, MySQL, Redis, or RUM) or "flow" in case of flows. | keyword |


An example event for `redis` looks as following:

```json
{
    "@timestamp": "2022-03-09T08:30:57.254Z",
    "agent": {
        "ephemeral_id": "b68277a8-8012-4ada-bbdd-6ce88a51c5ce",
        "id": "f789afb0-558d-48bd-b448-0fc838efd730",
        "name": "docker-fleet-agent",
        "type": "packetbeat",
        "version": "8.0.0"
    },
    "client": {
        "bytes": 31,
        "ip": "127.0.0.1",
        "port": 32810
    },
    "data_stream": {
        "dataset": "network_traffic.redis",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "bytes": 5,
        "ip": "127.0.0.1",
        "port": 6380
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "f789afb0-558d-48bd-b448-0fc838efd730",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "action": "redis.set",
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "network_traffic.redis",
        "duration": 1421600,
        "end": "2022-03-09T08:30:57.256Z",
        "ingested": "2022-03-09T08:30:58Z",
        "kind": "event",
        "start": "2022-03-09T08:30:57.254Z",
        "type": [
            "connection",
            "protocol"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "192.168.176.7"
        ],
        "mac": [
            "02-42-C0-A8-B0-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.47-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.3 LTS (Focal Fossa)"
        }
    },
    "method": "SET",
    "network": {
        "bytes": 36,
        "community_id": "1:GuHlyWpX6bKkMXy19YkvZSNPTS4=",
        "direction": "ingress",
        "protocol": "redis",
        "transport": "tcp",
        "type": "ipv4"
    },
    "query": "set key3 me",
    "redis": {
        "return_value": "OK"
    },
    "related": {
        "ip": [
            "127.0.0.1"
        ]
    },
    "resource": "key3",
    "server": {
        "bytes": 5,
        "ip": "127.0.0.1",
        "port": 6380
    },
    "source": {
        "bytes": 31,
        "ip": "127.0.0.1",
        "port": 32810
    },
    "status": "OK",
    "type": "redis"
}
```

### SIP

Fields published for SIP packets.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.bytes | Bytes sent from the client to the server. | long |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| client.port | Port of the client. | long |
| client.process.args | The command-line of the process that initiated the transaction. | keyword |
| client.process.executable | Absolute path to the client process executable. | keyword |
| client.process.name | The name of the process that initiated the transaction. | keyword |
| client.process.start | The time the client process started. | date |
| client.process.working_directory | The working directory of the client process. | keyword |
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
| destination.bytes | Bytes sent from the destination to the source. | long |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| flow.final | Indicates if event is last event in flow. If final is false, the event reports an intermediate flow state only. | boolean |
| flow.id | Internal flow ID based on connection meta data and address. | keyword |
| flow.vlan | VLAN identifier from the 802.1q frame. In case of a multi-tagged frame this field will be an array with the outer tag's VLAN identifier listed first. | long |
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
| method | The command/verb/method of the transaction. For HTTP, this is the method name (GET, POST, PUT, and so on), for SQL this is the verb (SELECT, UPDATE, DELETE, and so on). | keyword |
| network.application | When a specific application or service is identified from network connection details (source/dest IPs, ports, certificates, or wire format), this field captures the application's or service's name. For example, the original event identifies the network connection being from a specific web service in a `https` network connection, like `facebook` or `twitter`. The field value must be normalized to lowercase for querying. | keyword |
| network.bytes | Total bytes transferred in both directions. If `source.bytes` and `destination.bytes` are known, `network.bytes` is their sum. | long |
| network.community_id | A hash of source and destination IPs and ports, as well as the protocol used in a communication. This is a tool-agnostic standard to identify flows. Learn more at https://github.com/corelight/community-id-spec. | keyword |
| network.direction | Direction of the network traffic. Recommended values are:   \* ingress   \* egress   \* inbound   \* outbound   \* internal   \* external   \* unknown  When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.forwarded_ip | Host IP address when the source IP address is the proxy. | ip |
| network.iana_number | IANA Protocol Number (https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml). Standardized list of protocols. This aligns well with NetFlow and sFlow related logs which use the IANA Protocol Number. | keyword |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc The field value must be normalized to lowercase for querying. | keyword |
| params | The request parameters. For HTTP, these are the POST or GET parameters. For Thrift-RPC, these are the parameters from the request. | text |
| path | The path the transaction refers to. For HTTP, this is the URL. For SQL databases, this is the table name. For key-value stores, this is the key. | keyword |
| query | The query in a human readable format. For HTTP, it will typically be something like `GET /users/_search?name=test`. For MySQL, it is something like `SELECT id from users where name=test`. | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| request | For text protocols, this is the request as seen on the wire (application layer only). For binary protocols this is our representation of the request. | text |
| resource | The logical resource that this transaction refers to. For HTTP, this is the URL path up to the last slash (/). For example, if the URL is `/users/1`, the resource is `/users`. For databases, the resource is typically the table name. The field is not filled for all transaction types. | keyword |
| response | For text protocols, this is the response as seen on the wire (application layer only). For binary protocols this is our representation of the request. | text |
| server.bytes | Bytes sent from the server to the client. | long |
| server.ip | IP address of the server (IPv4 or IPv6). | ip |
| server.port | Port of the server. | long |
| server.process.args | The command-line of the process that served the transaction. | keyword |
| server.process.executable | Absolute path to the server process executable. | keyword |
| server.process.name | The name of the process that served the transaction. | keyword |
| server.process.start | The time the server process started. | date |
| server.process.working_directory | The working directory of the server process. | keyword |
| sip.accept | Accept header value. | keyword |
| sip.allow | Allowed methods. | keyword |
| sip.auth.realm | Auth realm | keyword |
| sip.auth.scheme | Auth scheme | keyword |
| sip.auth.uri.host | Auth URI host | keyword |
| sip.auth.uri.original | Auth original URI | keyword |
| sip.auth.uri.port | Auth URI port | long |
| sip.auth.uri.scheme | Auth URI scheme | keyword |
| sip.call_id | Call ID. | keyword |
| sip.code | Response status code. | long |
| sip.contact.display_info | Contact display info | keyword |
| sip.contact.expires | Contact expires | keyword |
| sip.contact.line | Contact line | keyword |
| sip.contact.q | Contact Q | keyword |
| sip.contact.transport | Contact transport | keyword |
| sip.contact.uri.host | Contact URI host | keyword |
| sip.contact.uri.original | Contact original URI | keyword |
| sip.contact.uri.port | Contact URI port | long |
| sip.contact.uri.scheme | Contat URI scheme | keyword |
| sip.contact.uri.username | Contact URI user name | keyword |
| sip.content_length |  | long |
| sip.content_type |  | keyword |
| sip.cseq.code | Sequence code. | long |
| sip.cseq.method | Sequence method. | keyword |
| sip.from.display_info | From display info | keyword |
| sip.from.tag | From tag | keyword |
| sip.from.uri.host | From URI host | keyword |
| sip.from.uri.original | From original URI | keyword |
| sip.from.uri.port | From URI port | long |
| sip.from.uri.scheme | From URI scheme | keyword |
| sip.from.uri.username | From URI user name | keyword |
| sip.max_forwards |  | long |
| sip.method | Request method. | keyword |
| sip.private.uri.host | Private URI host. | keyword |
| sip.private.uri.original | Private original URI. | keyword |
| sip.private.uri.port | Private URI port. | long |
| sip.private.uri.scheme | Private URI scheme. | keyword |
| sip.private.uri.username | Private URI user name. | keyword |
| sip.sdp.body.original | SDP original body | keyword |
| sip.sdp.connection.address | SDP connection address | keyword |
| sip.sdp.connection.info | SDP connection info | keyword |
| sip.sdp.owner.ip | SDP owner IP | ip |
| sip.sdp.owner.session_id | SDP owner session ID | keyword |
| sip.sdp.owner.username | SDP owner user name | keyword |
| sip.sdp.owner.version | SDP owner version | keyword |
| sip.sdp.session.name | SDP session name | keyword |
| sip.sdp.version | SDP version | keyword |
| sip.status | Response status phrase. | keyword |
| sip.supported | Supported methods. | keyword |
| sip.to.display_info | To display info | keyword |
| sip.to.tag | To tag | keyword |
| sip.to.uri.host | To URI host | keyword |
| sip.to.uri.original | To original URI | keyword |
| sip.to.uri.port | To URI port | long |
| sip.to.uri.scheme | To URI scheme | keyword |
| sip.to.uri.username | To URI user name | keyword |
| sip.type | Either request or response. | keyword |
| sip.uri.host | The URI host. | keyword |
| sip.uri.original | The original URI. | keyword |
| sip.uri.port | The URI port. | long |
| sip.uri.scheme | The URI scheme. | keyword |
| sip.uri.username | The URI user name. | keyword |
| sip.user_agent.original |  | keyword |
| sip.version | SIP protocol version. | keyword |
| sip.via.original | The original Via value. | keyword |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| status | The high level status of the transaction. The way to compute this value depends on the protocol, but the result has a meaning independent of the protocol. | keyword |
| type | The type of the transaction (for example, HTTP, MySQL, Redis, or RUM) or "flow" in case of flows. | keyword |
| user.name | Short name or login of the user. | keyword |


An example event for `sip` looks as following:

```json
{
    "@timestamp": "2022-03-09T08:32:14.536Z",
    "agent": {
        "ephemeral_id": "ee3aeba6-2bd9-4a89-840a-32af72217a7a",
        "id": "f789afb0-558d-48bd-b448-0fc838efd730",
        "name": "docker-fleet-agent",
        "type": "packetbeat",
        "version": "8.0.0"
    },
    "client": {
        "ip": "10.0.2.20",
        "port": 5060
    },
    "data_stream": {
        "dataset": "network_traffic.sip",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "ip": "10.0.2.15",
        "port": 5060
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "f789afb0-558d-48bd-b448-0fc838efd730",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "action": "sip-invite",
        "agent_id_status": "verified",
        "category": [
            "network",
            "protocol"
        ],
        "dataset": "network_traffic.sip",
        "duration": 0,
        "end": "2022-03-09T08:32:14.536Z",
        "ingested": "2022-03-09T08:32:15Z",
        "kind": "event",
        "original": "INVITE sip:test@10.0.2.15:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.2.20:5060;branch=z9hG4bK-2187-1-0\r\nFrom: \"DVI4/8000\" \u003csip:sipp@10.0.2.20:5060\u003e;tag=1\r\nTo: test \u003csip:test@10.0.2.15:5060\u003e\r\nCall-ID: 1-2187@10.0.2.20\r\nCSeq: 1 INVITE\r\nContact: sip:sipp@10.0.2.20:5060\r\nMax-Forwards: 70\r\nContent-Type: application/sdp\r\nContent-Length:   123\r\n\r\nv=0\r\no=- 42 42 IN IP4 10.0.2.20\r\ns=-\r\nc=IN IP4 10.0.2.20\r\nt=0 0\r\nm=audio 6000 RTP/AVP 5\r\na=rtpmap:5 DVI4/8000\r\na=recvonly\r\n",
        "sequence": 1,
        "start": "2022-03-09T08:32:14.536Z",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "192.168.176.7"
        ],
        "mac": [
            "02-42-C0-A8-B0-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.47-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.3 LTS (Focal Fossa)"
        }
    },
    "network": {
        "application": "sip",
        "community_id": "1:xDRQZvk3ErEhBDslXv1c6EKI804=",
        "direction": "unknown",
        "iana_number": "17",
        "protocol": "sip",
        "transport": "udp",
        "type": "ipv4"
    },
    "related": {
        "hosts": [
            "10.0.2.15",
            "10.0.2.20"
        ],
        "ip": [
            "10.0.2.20",
            "10.0.2.15"
        ],
        "user": [
            "test",
            "sipp"
        ]
    },
    "server": {
        "ip": "10.0.2.15",
        "port": 5060
    },
    "sip": {
        "call_id": "1-2187@10.0.2.20",
        "contact": {
            "display_info": "test",
            "uri": {
                "host": "10.0.2.15",
                "original": "sip:test@10.0.2.15:5060",
                "port": 5060,
                "scheme": "sip",
                "username": "test"
            }
        },
        "content_length": 123,
        "content_type": "application/sdp",
        "cseq": {
            "code": 1,
            "method": "INVITE"
        },
        "from": {
            "display_info": "DVI4/8000",
            "tag": "1",
            "uri": {
                "host": "10.0.2.20",
                "original": "sip:sipp@10.0.2.20:5060",
                "port": 5060,
                "scheme": "sip",
                "username": "sipp"
            }
        },
        "max_forwards": 70,
        "method": "INVITE",
        "sdp": {
            "body": {
                "original": "v=0\r\no=- 42 42 IN IP4 10.0.2.20\r\ns=-\r\nc=IN IP4 10.0.2.20\r\nt=0 0\r\nm=audio 6000 RTP/AVP 5\r\na=rtpmap:5 DVI4/8000\r\na=recvonly\r\n"
            },
            "connection": {
                "address": "10.0.2.20",
                "info": "IN IP4 10.0.2.20"
            },
            "owner": {
                "ip": "10.0.2.20",
                "session_id": "42",
                "version": "42"
            },
            "version": "0"
        },
        "to": {
            "display_info": "test",
            "uri": {
                "host": "10.0.2.15",
                "original": "sip:test@10.0.2.15:5060",
                "port": 5060,
                "scheme": "sip",
                "username": "test"
            }
        },
        "type": "request",
        "uri": {
            "host": "10.0.2.15",
            "original": "sip:test@10.0.2.15:5060",
            "port": 5060,
            "scheme": "sip",
            "username": "test"
        },
        "version": "2.0",
        "via": {
            "original": [
                "SIP/2.0/UDP 10.0.2.20:5060;branch=z9hG4bK-2187-1-0"
            ]
        }
    },
    "source": {
        "ip": "10.0.2.20",
        "port": 5060
    },
    "status": "OK",
    "type": "sip"
}
```

### Thrift

Fields published for Thrift packets.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.bytes | Bytes sent from the client to the server. | long |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| client.port | Port of the client. | long |
| client.process.args | The command-line of the process that initiated the transaction. | keyword |
| client.process.executable | Absolute path to the client process executable. | keyword |
| client.process.name | The name of the process that initiated the transaction. | keyword |
| client.process.start | The time the client process started. | date |
| client.process.working_directory | The working directory of the client process. | keyword |
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
| destination.bytes | Bytes sent from the destination to the source. | long |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| flow.final | Indicates if event is last event in flow. If final is false, the event reports an intermediate flow state only. | boolean |
| flow.id | Internal flow ID based on connection meta data and address. | keyword |
| flow.vlan | VLAN identifier from the 802.1q frame. In case of a multi-tagged frame this field will be an array with the outer tag's VLAN identifier listed first. | long |
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
| method | The command/verb/method of the transaction. For HTTP, this is the method name (GET, POST, PUT, and so on), for SQL this is the verb (SELECT, UPDATE, DELETE, and so on). | keyword |
| network.bytes | Total bytes transferred in both directions. If `source.bytes` and `destination.bytes` are known, `network.bytes` is their sum. | long |
| network.community_id | A hash of source and destination IPs and ports, as well as the protocol used in a communication. This is a tool-agnostic standard to identify flows. Learn more at https://github.com/corelight/community-id-spec. | keyword |
| network.direction | Direction of the network traffic. Recommended values are:   \* ingress   \* egress   \* inbound   \* outbound   \* internal   \* external   \* unknown  When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.forwarded_ip | Host IP address when the source IP address is the proxy. | ip |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc The field value must be normalized to lowercase for querying. | keyword |
| params | The request parameters. For HTTP, these are the POST or GET parameters. For Thrift-RPC, these are the parameters from the request. | text |
| path | The path the transaction refers to. For HTTP, this is the URL. For SQL databases, this is the table name. For key-value stores, this is the key. | keyword |
| query | The query in a human readable format. For HTTP, it will typically be something like `GET /users/_search?name=test`. For MySQL, it is something like `SELECT id from users where name=test`. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| request | For text protocols, this is the request as seen on the wire (application layer only). For binary protocols this is our representation of the request. | text |
| resource | The logical resource that this transaction refers to. For HTTP, this is the URL path up to the last slash (/). For example, if the URL is `/users/1`, the resource is `/users`. For databases, the resource is typically the table name. The field is not filled for all transaction types. | keyword |
| response | For text protocols, this is the response as seen on the wire (application layer only). For binary protocols this is our representation of the request. | text |
| server.bytes | Bytes sent from the server to the client. | long |
| server.ip | IP address of the server (IPv4 or IPv6). | ip |
| server.port | Port of the server. | long |
| server.process.args | The command-line of the process that served the transaction. | keyword |
| server.process.executable | Absolute path to the server process executable. | keyword |
| server.process.name | The name of the process that served the transaction. | keyword |
| server.process.start | The time the server process started. | date |
| server.process.working_directory | The working directory of the server process. | keyword |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| status | The high level status of the transaction. The way to compute this value depends on the protocol, but the result has a meaning independent of the protocol. | keyword |
| thrift.exceptions | If the call resulted in exceptions, this field contains the exceptions in a human readable format. | keyword |
| thrift.params | The RPC method call parameters in a human readable format. If the IDL files are available, the parameters use names whenever possible. Otherwise, the IDs from the message are used. | keyword |
| thrift.return_value | The value returned by the Thrift-RPC call. This is encoded in a human readable format. | keyword |
| thrift.service | The name of the Thrift-RPC service as defined in the IDL files. | keyword |
| type | The type of the transaction (for example, HTTP, MySQL, Redis, or RUM) or "flow" in case of flows. | keyword |


An example event for `thrift` looks as following:

```json
{
    "@timestamp": "2022-03-09T08:33:31.022Z",
    "agent": {
        "ephemeral_id": "de52c04f-60dd-4ed1-a501-b297caa5c67c",
        "id": "f789afb0-558d-48bd-b448-0fc838efd730",
        "name": "docker-fleet-agent",
        "type": "packetbeat",
        "version": "8.0.0"
    },
    "client": {
        "bytes": 25,
        "ip": "127.0.0.1",
        "port": 50919
    },
    "data_stream": {
        "dataset": "network_traffic.thrift",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "bytes": 25,
        "ip": "127.0.0.1",
        "port": 9090
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "f789afb0-558d-48bd-b448-0fc838efd730",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "network_traffic.thrift",
        "duration": 1394000,
        "end": "2022-03-09T08:33:31.023Z",
        "ingested": "2022-03-09T08:33:32Z",
        "kind": "event",
        "start": "2022-03-09T08:33:31.022Z",
        "type": [
            "connection",
            "protocol"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "192.168.176.7"
        ],
        "mac": [
            "02-42-C0-A8-B0-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.47-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.3 LTS (Focal Fossa)"
        }
    },
    "method": "testByte",
    "network": {
        "bytes": 50,
        "community_id": "1:fs+HuhTN3hqKiWHtoK/DsQ0ni5Y=",
        "direction": "ingress",
        "protocol": "thrift",
        "transport": "tcp",
        "type": "ipv4"
    },
    "path": "",
    "query": "testByte(1: 63)",
    "related": {
        "ip": [
            "127.0.0.1"
        ]
    },
    "server": {
        "bytes": 25,
        "ip": "127.0.0.1",
        "port": 9090
    },
    "source": {
        "bytes": 25,
        "ip": "127.0.0.1",
        "port": 50919
    },
    "status": "OK",
    "thrift": {
        "params": "(1: 63)",
        "return_value": "63"
    },
    "type": "thrift"
}
```

### TLS

Fields published for TLS packets.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.bytes | Bytes sent from the client to the server. | long |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| client.port | Port of the client. | long |
| client.process.args | The command-line of the process that initiated the transaction. | keyword |
| client.process.executable | Absolute path to the client process executable. | keyword |
| client.process.name | The name of the process that initiated the transaction. | keyword |
| client.process.start | The time the client process started. | date |
| client.process.working_directory | The working directory of the client process. | keyword |
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
| destination.bytes | Bytes sent from the destination to the source. | long |
| destination.domain | The domain name of the destination system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| flow.final | Indicates if event is last event in flow. If final is false, the event reports an intermediate flow state only. | boolean |
| flow.id | Internal flow ID based on connection meta data and address. | keyword |
| flow.vlan | VLAN identifier from the 802.1q frame. In case of a multi-tagged frame this field will be an array with the outer tag's VLAN identifier listed first. | long |
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
| method | The command/verb/method of the transaction. For HTTP, this is the method name (GET, POST, PUT, and so on), for SQL this is the verb (SELECT, UPDATE, DELETE, and so on). | keyword |
| network.bytes | Total bytes transferred in both directions. If `source.bytes` and `destination.bytes` are known, `network.bytes` is their sum. | long |
| network.community_id | A hash of source and destination IPs and ports, as well as the protocol used in a communication. This is a tool-agnostic standard to identify flows. Learn more at https://github.com/corelight/community-id-spec. | keyword |
| network.direction | Direction of the network traffic. Recommended values are:   \* ingress   \* egress   \* inbound   \* outbound   \* internal   \* external   \* unknown  When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.forwarded_ip | Host IP address when the source IP address is the proxy. | ip |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc The field value must be normalized to lowercase for querying. | keyword |
| params | The request parameters. For HTTP, these are the POST or GET parameters. For Thrift-RPC, these are the parameters from the request. | text |
| path | The path the transaction refers to. For HTTP, this is the URL. For SQL databases, this is the table name. For key-value stores, this is the key. | keyword |
| query | The query in a human readable format. For HTTP, it will typically be something like `GET /users/_search?name=test`. For MySQL, it is something like `SELECT id from users where name=test`. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| request | For text protocols, this is the request as seen on the wire (application layer only). For binary protocols this is our representation of the request. | text |
| resource | The logical resource that this transaction refers to. For HTTP, this is the URL path up to the last slash (/). For example, if the URL is `/users/1`, the resource is `/users`. For databases, the resource is typically the table name. The field is not filled for all transaction types. | keyword |
| response | For text protocols, this is the response as seen on the wire (application layer only). For binary protocols this is our representation of the request. | text |
| server.bytes | Bytes sent from the server to the client. | long |
| server.domain | The domain name of the server system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| server.ip | IP address of the server (IPv4 or IPv6). | ip |
| server.port | Port of the server. | long |
| server.process.args | The command-line of the process that served the transaction. | keyword |
| server.process.executable | Absolute path to the server process executable. | keyword |
| server.process.name | The name of the process that served the transaction. | keyword |
| server.process.start | The time the server process started. | date |
| server.process.working_directory | The working directory of the server process. | keyword |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| status | The high level status of the transaction. The way to compute this value depends on the protocol, but the result has a meaning independent of the protocol. | keyword |
| tls.cipher | String indicating the cipher used during the current connection. | keyword |
| tls.client.ja3 | A hash that identifies clients based on how they perform an SSL/TLS handshake. | keyword |
| tls.client.server_name | Also called an SNI, this tells the server which hostname to which the client is attempting to connect to. When this value is available, it should get copied to `destination.domain`. | keyword |
| tls.client.supported_ciphers | Array of ciphers offered by the client during the client hello. | keyword |
| tls.client.x509.issuer.province | Province or region within country. | keyword |
| tls.client.x509.subject.province | Province or region within country. | keyword |
| tls.client.x509.version | Version of x509 format. | keyword |
| tls.detailed.alert_types | An array containing the TLS alert type for every alert received. | keyword |
| tls.detailed.client_certificate.alternative_names | Subject Alternative Names for this certificate. | keyword |
| tls.detailed.client_certificate.issuer.common_name | Name or host name identified by the certificate. | keyword |
| tls.detailed.client_certificate.issuer.country | Country code. | keyword |
| tls.detailed.client_certificate.issuer.distinguished_name | Distinguished name (DN) of the certificate issuer entity. | keyword |
| tls.detailed.client_certificate.issuer.locality | Locality. | keyword |
| tls.detailed.client_certificate.issuer.organization | Organization name. | keyword |
| tls.detailed.client_certificate.issuer.organizational_unit | Unit within organization. | keyword |
| tls.detailed.client_certificate.issuer.province | Province or region within country. | keyword |
| tls.detailed.client_certificate.not_after | Date after which the certificate expires. | date |
| tls.detailed.client_certificate.not_before | Date before which the certificate is not valid. | date |
| tls.detailed.client_certificate.public_key_algorithm | The algorithm used for this certificate's public key. One of RSA, DSA or ECDSA. | keyword |
| tls.detailed.client_certificate.public_key_size | Size of the public key. | long |
| tls.detailed.client_certificate.serial_number | The certificate's serial number. | keyword |
| tls.detailed.client_certificate.signature_algorithm | The algorithm used for the certificate's signature. | keyword |
| tls.detailed.client_certificate.subject.common_name | Name or host name identified by the certificate. | keyword |
| tls.detailed.client_certificate.subject.country | Country code. | keyword |
| tls.detailed.client_certificate.subject.distinguished_name | Distinguished name (DN) of the certificate subject entity. | keyword |
| tls.detailed.client_certificate.subject.locality | Locality. | keyword |
| tls.detailed.client_certificate.subject.organization | Organization name. | keyword |
| tls.detailed.client_certificate.subject.organizational_unit | Unit within organization. | keyword |
| tls.detailed.client_certificate.subject.province | Province or region within country. | keyword |
| tls.detailed.client_certificate.version | X509 format version. | long |
| tls.detailed.client_certificate.version_number | Version of x509 format. | keyword |
| tls.detailed.client_certificate_chain | Chain of trust for the client certificate. | array |
| tls.detailed.client_certificate_requested | Whether the server has requested the client to authenticate itself using a client certificate. | boolean |
| tls.detailed.client_hello.extensions._unparsed_ | List of extensions that were left unparsed by Packetbeat. | keyword |
| tls.detailed.client_hello.extensions.application_layer_protocol_negotiation | List of application-layer protocols the client is willing to use. | keyword |
| tls.detailed.client_hello.extensions.ec_points_formats | List of Elliptic Curve (EC) point formats. Indicates the set of point formats that the client can parse. | keyword |
| tls.detailed.client_hello.extensions.server_name_indication | List of hostnames | keyword |
| tls.detailed.client_hello.extensions.session_ticket | Length of the session ticket, if provided, or an empty string to advertise support for tickets. | keyword |
| tls.detailed.client_hello.extensions.signature_algorithms | List of signature algorithms that may be use in digital signatures. | keyword |
| tls.detailed.client_hello.extensions.status_request.request_extensions | The number of certificate extensions for the request. | short |
| tls.detailed.client_hello.extensions.status_request.responder_id_list_length | The length of the list of trusted responders. | short |
| tls.detailed.client_hello.extensions.status_request.type | The type of the status request. Always "ocsp" if present. | keyword |
| tls.detailed.client_hello.extensions.supported_groups | List of Elliptic Curve Cryptography (ECC) curve groups supported by the client. | keyword |
| tls.detailed.client_hello.extensions.supported_versions | List of TLS versions that the client is willing to use. | keyword |
| tls.detailed.client_hello.random | Random data used by the TLS protocol to generate the encryption key. | keyword |
| tls.detailed.client_hello.session_id | Unique number to identify the session for the corresponding connection with the client. | keyword |
| tls.detailed.client_hello.supported_compression_methods | The list of compression methods the client supports. See https://www.iana.org/assignments/comp-meth-ids/comp-meth-ids.xhtml | keyword |
| tls.detailed.client_hello.version | The version of the TLS protocol by which the client wishes to communicate during this session. | keyword |
| tls.detailed.ocsp_response | The result of an OCSP request. | keyword |
| tls.detailed.resumption_method | If the session has been resumed, the underlying method used. One of "id" for TLS session ID or "ticket" for TLS ticket extension. | keyword |
| tls.detailed.server_certificate.alternative_names | Subject Alternative Names for this certificate. | keyword |
| tls.detailed.server_certificate.issuer.common_name | Name or host name identified by the certificate. | keyword |
| tls.detailed.server_certificate.issuer.country | Country code. | keyword |
| tls.detailed.server_certificate.issuer.distinguished_name | Distinguished name (DN) of the certificate issuer entity. | keyword |
| tls.detailed.server_certificate.issuer.locality | Locality. | keyword |
| tls.detailed.server_certificate.issuer.organization | Organization name. | keyword |
| tls.detailed.server_certificate.issuer.organizational_unit | Unit within organization. | keyword |
| tls.detailed.server_certificate.issuer.province | Province or region within country. | keyword |
| tls.detailed.server_certificate.issuer.state_or_province | Province or region within country. | keyword |
| tls.detailed.server_certificate.not_after | Date after which the certificate expires. | date |
| tls.detailed.server_certificate.not_before | Date before which the certificate is not valid. | date |
| tls.detailed.server_certificate.public_key_algorithm | The algorithm used for this certificate's public key. One of RSA, DSA or ECDSA. | keyword |
| tls.detailed.server_certificate.public_key_size | Size of the public key. | long |
| tls.detailed.server_certificate.serial_number | The certificate's serial number. | keyword |
| tls.detailed.server_certificate.signature_algorithm | The algorithm used for the certificate's signature. | keyword |
| tls.detailed.server_certificate.subject.common_name | Name or host name identified by the certificate. | keyword |
| tls.detailed.server_certificate.subject.country | Country code. | keyword |
| tls.detailed.server_certificate.subject.distinguished_name | Distinguished name (DN) of the certificate subject entity. | keyword |
| tls.detailed.server_certificate.subject.locality | Locality. | keyword |
| tls.detailed.server_certificate.subject.organization | Organization name. | keyword |
| tls.detailed.server_certificate.subject.organizational_unit | Unit within organization. | keyword |
| tls.detailed.server_certificate.subject.province | Province or region within country. | keyword |
| tls.detailed.server_certificate.subject.state_or_province | Province or region within country. | keyword |
| tls.detailed.server_certificate.version | X509 format version. | long |
| tls.detailed.server_certificate.version_number | Version of x509 format. | keyword |
| tls.detailed.server_certificate_chain | Chain of trust for the server certificate. | array |
| tls.detailed.server_hello.extensions._unparsed_ | List of extensions that were left unparsed by Packetbeat. | keyword |
| tls.detailed.server_hello.extensions.application_layer_protocol_negotiation | Negotiated application layer protocol | keyword |
| tls.detailed.server_hello.extensions.ec_points_formats | List of Elliptic Curve (EC) point formats. Indicates the set of point formats that the server can parse. | keyword |
| tls.detailed.server_hello.extensions.session_ticket | Used to announce that a session ticket will be provided by the server. Always an empty string. | keyword |
| tls.detailed.server_hello.extensions.status_request.response | Whether a certificate status request response was made. | boolean |
| tls.detailed.server_hello.extensions.supported_versions | Negotiated TLS version to be used. | keyword |
| tls.detailed.server_hello.random | Random data used by the TLS protocol to generate the encryption key. | keyword |
| tls.detailed.server_hello.selected_compression_method | The compression method selected by the server from the list provided in the client hello. | keyword |
| tls.detailed.server_hello.session_id | Unique number to identify the session for the corresponding connection with the client. | keyword |
| tls.detailed.server_hello.version | The version of the TLS protocol that is used for this session. It is the highest version supported by the server not exceeding the version requested in the client hello. | keyword |
| tls.detailed.version | The version of the TLS protocol used. | keyword |
| tls.established | Boolean flag indicating if the TLS negotiation was successful and transitioned to an encrypted tunnel. | boolean |
| tls.resumed | Boolean flag indicating if this TLS connection was resumed from an existing TLS negotiation. | boolean |
| tls.server.x509.issuer.province | Province or region within country. | keyword |
| tls.server.x509.subject.province | Province or region within country. | keyword |
| tls.server.x509.version | Version of x509 format. | keyword |
| tls.version | Numeric part of the version parsed from the original string. | keyword |
| tls.version_protocol | Normalized lowercase protocol name parsed from original string. | keyword |
| type | The type of the transaction (for example, HTTP, MySQL, Redis, or RUM) or "flow" in case of flows. | keyword |


An example event for `tls` looks as following:

```json
{
    "@timestamp": "2022-03-09T08:34:08.391Z",
    "agent": {
        "ephemeral_id": "5f0bae3e-11e9-4578-9a69-fa5e61bd6b09",
        "id": "f789afb0-558d-48bd-b448-0fc838efd730",
        "name": "docker-fleet-agent",
        "type": "packetbeat",
        "version": "8.0.0"
    },
    "client": {
        "ip": "192.168.1.36",
        "port": 60946
    },
    "data_stream": {
        "dataset": "network_traffic.tls",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "domain": "play.google.com",
        "ip": "216.58.201.174",
        "port": 443
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "f789afb0-558d-48bd-b448-0fc838efd730",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "network_traffic.tls",
        "duration": 14861200,
        "end": "2022-03-09T08:34:08.406Z",
        "ingested": "2022-03-09T08:34:09Z",
        "kind": "event",
        "start": "2022-03-09T08:34:08.391Z",
        "type": [
            "connection",
            "protocol"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "192.168.176.7"
        ],
        "mac": [
            "02-42-C0-A8-B0-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.47-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.3 LTS (Focal Fossa)"
        }
    },
    "network": {
        "community_id": "1:hfsK5r0tJm7av4j7BtSxA6oH9xA=",
        "direction": "unknown",
        "protocol": "tls",
        "transport": "tcp",
        "type": "ipv4"
    },
    "related": {
        "ip": [
            "192.168.1.36",
            "216.58.201.174"
        ]
    },
    "server": {
        "domain": "play.google.com",
        "ip": "216.58.201.174",
        "port": 443
    },
    "source": {
        "ip": "192.168.1.36",
        "port": 60946
    },
    "status": "OK",
    "tls": {
        "cipher": "TLS_AES_128_GCM_SHA256",
        "client": {
            "ja3": "d470a3fa301d80227bc5650c75567d25",
            "server_name": "play.google.com",
            "supported_ciphers": [
                "TLS_AES_128_GCM_SHA256",
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
                "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
                "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
                "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
                "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
                "TLS_RSA_WITH_AES_128_CBC_SHA",
                "TLS_RSA_WITH_AES_256_CBC_SHA",
                "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
            ]
        },
        "detailed": {
            "client_certificate_requested": false,
            "client_hello": {
                "extensions": {
                    "_unparsed_": [
                        "23",
                        "renegotiation_info",
                        "status_request",
                        "51",
                        "45",
                        "28",
                        "41"
                    ],
                    "application_layer_protocol_negotiation": [
                        "h2",
                        "http/1.1"
                    ],
                    "ec_points_formats": [
                        "uncompressed"
                    ],
                    "server_name_indication": [
                        "play.google.com"
                    ],
                    "signature_algorithms": [
                        "ecdsa_secp256r1_sha256",
                        "ecdsa_secp384r1_sha384",
                        "ecdsa_secp521r1_sha512",
                        "rsa_pss_sha256",
                        "rsa_pss_sha384",
                        "rsa_pss_sha512",
                        "rsa_pkcs1_sha256",
                        "rsa_pkcs1_sha384",
                        "rsa_pkcs1_sha512",
                        "ecdsa_sha1",
                        "rsa_pkcs1_sha1"
                    ],
                    "supported_groups": [
                        "x25519",
                        "secp256r1",
                        "secp384r1",
                        "secp521r1",
                        "ffdhe2048",
                        "ffdhe3072"
                    ],
                    "supported_versions": [
                        "TLS 1.3",
                        "TLS 1.2",
                        "TLS 1.1",
                        "TLS 1.0"
                    ]
                },
                "session_id": "5d2b9f80d34143b5764ba6b23e1d4f9d1f172148b6fd83c81f42663459eaf6f6",
                "supported_compression_methods": [
                    "NULL"
                ],
                "version": "3.3"
            },
            "resumption_method": "id",
            "server_hello": {
                "extensions": {
                    "_unparsed_": [
                        "41",
                        "51"
                    ],
                    "supported_versions": "TLS 1.3"
                },
                "selected_compression_method": "NULL",
                "session_id": "5d2b9f80d34143b5764ba6b23e1d4f9d1f172148b6fd83c81f42663459eaf6f6",
                "version": "3.3"
            },
            "version": "TLS 1.3"
        },
        "established": true,
        "resumed": true,
        "version": "1.3",
        "version_protocol": "tls"
    },
    "type": "tls"
}
```

## Licensing for Windows Systems

The Network Packet Capture Integration incorporates a bundled Npcap installation on Windows hosts. The installation is provided under an [OEM license](https://npcap.com/oem/redist.html) from Insecure.Com LLC ("The Nmap Project").