# Cassandra Integration

This integration periodically fetches metrics from [Cassandra](https://cassandra.apache.org/) servers. It can parse System.

## Logs

Cassandra system logs from cassandra.log files.

An example event for `log` looks as following:

```json
{
    "@timestamp": "2021-07-21T12:23:32.856Z",
    "agent": {
        "ephemeral_id": "f7d5b705-376f-4a6d-ba25-ea0d2623fb14",
        "hostname": "docker-fleet-agent",
        "id": "cbbdce91-5354-4639-a8c0-b77bb78ba162",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.15.0"
    },
    "cassandra": {
        "log": {
            "meta": "\njava.io.IOException: An existing connection was forcibly closed by the remote host\n\tat sun.nio.ch.SocketDispatcher.read0(Native Method) ~[na:1.8.0_291]\n\tat sun.nio.ch.SocketDispatcher.read(SocketDispatcher.java:43) ~[na:1.8.0_291]\n\tat sun.nio.ch.IOUtil.readIntoNativeBuffer(IOUtil.java:223) ~[na:1.8.0_291]\n\tat sun.nio.ch.IOUtil.read(IOUtil.java:192) ~[na:1.8.0_291]\n\tat sun.nio.ch.SocketChannelImpl.read(SocketChannelImpl.java:378) ~[na:1.8.0_291]\n\tat io.netty.buffer.PooledUnsafeDirectByteBuf.setBytes(PooledUnsafeDirectByteBuf.java:221) ~[netty-all-4.0.44.Final.jar:4.0.44.Final]\n\tat io.netty.buffer.AbstractByteBuf.writeBytes(AbstractByteBuf.java:899) ~[netty-all-4.0.44.Final.jar:4.0.44.Final]\n\tat io.netty.channel.socket.nio.NioSocketChannel.doReadBytes(NioSocketChannel.java:276) ~[netty-all-4.0.44.Final.jar:4.0.44.Final]\n\tat io.netty.channel.nio.AbstractNioByteChannel$NioByteUnsafe.read(AbstractNioByteChannel.java:119) ~[netty-all-4.0.44.Final.jar:4.0.44.Final]\n\tat io.netty.channel.nio.NioEventLoop.processSelectedKey(NioEventLoop.java:643) [netty-all-4.0.44.Final.jar:4.0.44.Final]\n\tat io.netty.channel.nio.NioEventLoop.processSelectedKeysOptimized(NioEventLoop.java:566) [netty-all-4.0.44.Final.jar:4.0.44.Final]\n\tat io.netty.channel.nio.NioEventLoop.processSelectedKeys(NioEventLoop.java:480) [netty-all-4.0.44.Final.jar:4.0.44.Final]\n\tat io.netty.channel.nio.NioEventLoop.run(NioEventLoop.java:442) [netty-all-4.0.44.Final.jar:4.0.44.Final]\n\tat io.netty.util.concurrent.SingleThreadEventExecutor$2.run(SingleThreadEventExecutor.java:131) [netty-all-4.0.44.Final.jar:4.0.44.Final]\n\tat io.netty.util.concurrent.DefaultThreadFactory$DefaultRunnableDecorator.run(DefaultThreadFactory.java:144) [netty-all-4.0.44.Final.jar:4.0.44.Final]\n\tat java.lang.Thread.run(Thread.java:748) [na:1.8.0_291]"
        }
    },
    "data_stream": {
        "dataset": "cassandra.log",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "1.12.0"
    },
    "elastic_agent": {
        "id": "cbbdce91-5354-4639-a8c0-b77bb78ba162",
        "snapshot": true,
        "version": "7.15.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "database"
        ],
        "dataset": "cassandra.log",
        "ingested": "2021-09-21T09:57:25Z",
        "kind": "event",
        "original": "INFO  [nioEventLoopGroup-2-1] 2021-07-21 12:23:32,856 Message.java:826 - Unexpected exception during request; channel = [id: 0xa6112238, L:/127.0.0.1:9042 - R:/127.0.0.1:60106]\njava.io.IOException: An existing connection was forcibly closed by the remote host\n\tat sun.nio.ch.SocketDispatcher.read0(Native Method) ~[na:1.8.0_291]\n\tat sun.nio.ch.SocketDispatcher.read(SocketDispatcher.java:43) ~[na:1.8.0_291]\n\tat sun.nio.ch.IOUtil.readIntoNativeBuffer(IOUtil.java:223) ~[na:1.8.0_291]\n\tat sun.nio.ch.IOUtil.read(IOUtil.java:192) ~[na:1.8.0_291]\n\tat sun.nio.ch.SocketChannelImpl.read(SocketChannelImpl.java:378) ~[na:1.8.0_291]\n\tat io.netty.buffer.PooledUnsafeDirectByteBuf.setBytes(PooledUnsafeDirectByteBuf.java:221) ~[netty-all-4.0.44.Final.jar:4.0.44.Final]\n\tat io.netty.buffer.AbstractByteBuf.writeBytes(AbstractByteBuf.java:899) ~[netty-all-4.0.44.Final.jar:4.0.44.Final]\n\tat io.netty.channel.socket.nio.NioSocketChannel.doReadBytes(NioSocketChannel.java:276) ~[netty-all-4.0.44.Final.jar:4.0.44.Final]\n\tat io.netty.channel.nio.AbstractNioByteChannel$NioByteUnsafe.read(AbstractNioByteChannel.java:119) ~[netty-all-4.0.44.Final.jar:4.0.44.Final]\n\tat io.netty.channel.nio.NioEventLoop.processSelectedKey(NioEventLoop.java:643) [netty-all-4.0.44.Final.jar:4.0.44.Final]\n\tat io.netty.channel.nio.NioEventLoop.processSelectedKeysOptimized(NioEventLoop.java:566) [netty-all-4.0.44.Final.jar:4.0.44.Final]\n\tat io.netty.channel.nio.NioEventLoop.processSelectedKeys(NioEventLoop.java:480) [netty-all-4.0.44.Final.jar:4.0.44.Final]\n\tat io.netty.channel.nio.NioEventLoop.run(NioEventLoop.java:442) [netty-all-4.0.44.Final.jar:4.0.44.Final]\n\tat io.netty.util.concurrent.SingleThreadEventExecutor$2.run(SingleThreadEventExecutor.java:131) [netty-all-4.0.44.Final.jar:4.0.44.Final]\n\tat io.netty.util.concurrent.DefaultThreadFactory$DefaultRunnableDecorator.run(DefaultThreadFactory.java:144) [netty-all-4.0.44.Final.jar:4.0.44.Final]\n\tat java.lang.Thread.run(Thread.java:748) [na:1.8.0_291]",
        "type": "info"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "51d851402fe32de9c3ea31615e23a379",
        "ip": [
            "192.168.16.6"
        ],
        "mac": [
            "02:42:c0:a8:10:06"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "Core",
            "family": "redhat",
            "kernel": "3.10.0-1062.el7.x86_64",
            "name": "CentOS Linux",
            "platform": "centos",
            "type": "linux",
            "version": "7 (Core)"
        }
    },
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/system.log"
        },
        "flags": [
            "multiline"
        ],
        "level": "INFO",
        "offset": 0,
        "origin": {
            "file": {
                "line": "826",
                "name": "Message.java"
            }
        }
    },
    "message": "Unexpected exception during request; channel = [id: 0xa6112238, L:/127.0.0.1:9042 - R:/127.0.0.1:60106]",
    "process": {
        "thread": {
            "name": "nioEventLoopGroup-2-1"
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cassandra.log.meta | Log meta infos like java stack_trace | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| input.type | Input type | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.flags | Log flags | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.offset | Log offset | long |
| log.origin.file.line | The line number of the file containing the source code which originated the log event. | integer |
| log.origin.file.name | The name of the file containing the source code which originated the log event. Note that this field is not meant to capture the log file. The correct field to capture the log file is `log.file.path`. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | text |
| process.thread.name | Thread name. | keyword |
| tags | List of keywords used to tag each event. | keyword |

