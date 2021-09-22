# Cassandra Integration

This integration periodically fetches metrics from [Cassandra](https://cassandra.apache.org/) using jolokia agent. It can parse System logs.

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


## Metrics

Cassandra metrics using jolokia agent installed on cassandra.

An example event for `metrics` looks as following:

```json
{
    "@timestamp": "2021-09-22T04:12:17.759Z",
    "agent": {
        "ephemeral_id": "95d302dd-3e13-4127-8392-659fec794f8a",
        "hostname": "docker-fleet-agent",
        "id": "657e1b7f-adc2-4c7b-88e3-f63540ba62b8",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "7.15.0"
    },
    "cassandra": {
        "metrics": {
            "cache": {
                "keyCache": {
                    "OneMinuteHitRate": 0.8042840513090559,
                    "capacity": 99614720,
                    "requests": {
                        "OneMinuteRate": 17.3002094219168
                    }
                },
                "mbean": "org.apache.cassandra.metrics:type=Cache,scope=*,name=*",
                "rowCache": {
                    "capacity": 0,
                    "requests": {
                        "OneMinuteRate": 0
                    }
                }
            },
            "client_request": {
                "CASRead": {
                    "OneMinuteRate": 0
                },
                "CASWrite": {
                    "OneMinuteRate": 0
                },
                "mbean": "org.apache.cassandra.metrics:type=ClientRequest,scope=*,name=*",
                "rangeSlice": {
                    "OneMinuteRate": 0.015991117074135343
                },
                "read": {
                    "75thPercentile": 30130.992000000002,
                    "95thPercentile": 30130.992000000002,
                    "99thPercentile": 30130.992000000002,
                    "OneMinuteRate": 0.031982234148270686,
                    "timeouts": 0,
                    "unavailables": 0
                },
                "write": {
                    "75thPercentile": 7007.506,
                    "95thPercentile": 7007.506,
                    "99thPercentile": 7007.506,
                    "OneMinuteRate": 0.015991117074135343,
                    "timeouts": 0,
                    "unavailables": 0
                }
            },
            "columnFamily": {
                "mbean": "org.apache.cassandra.metrics:type=ColumnFamily,name=TotalDiskSpaceUsed",
                "totalDiskSpaceUsed": 72579
            },
            "compaction": {
                "completedTasks": 43,
                "mbean": "org.apache.cassandra.metrics:type=Compaction,name=*",
                "pendingTasks": 0
            },
            "gc": {
                "ConcurrentMarkSweep": {
                    "CollectionCount": 1,
                    "CollectionTime": 197
                },
                "ParNew": {
                    "CollectionCount": 2,
                    "CollectionTime": 251
                },
                "mbean": "java.lang:type=GarbageCollector,name=*"
            },
            "memory": {
                "heap": {
                    "usage": {
                        "committed": 2009071616,
                        "init": 2051014656,
                        "max": 2009071616,
                        "used": 219898896
                    }
                },
                "mbean": "java.lang:type=Memory",
                "other": {
                    "usage": {
                        "committed": 62054400,
                        "init": 2555904,
                        "max": -1,
                        "used": 60138680
                    }
                }
            },
            "storage": {
                "Exceptions": 0,
                "Load": 72579,
                "TotalHints": 0,
                "TotalHintsInProgress": 0,
                "mbean": "org.apache.cassandra.metrics:type=Storage,name=*"
            },
            "table": {
                "LiveSSTableCount": 11,
                "mbean": "org.apache.cassandra.metrics:type=Table,name=*"
            },
            "task": {
                "complete": 54,
                "mbean": "org.apache.cassandra.metrics:type=CommitLog,name=*",
                "pending": 0,
                "total": {
                    "commitlogSize": 67108864
                }
            },
            "threadPools": {
                "CounterMutationStage": {
                    "request": {
                        "ActiveTasks": 0,
                        "PendingTasks": 0
                    }
                },
                "MutationStage": {
                    "request": {
                        "ActiveTasks": 0,
                        "PendingTasks": 0
                    }
                },
                "ReadRepairStage": {
                    "request": {
                        "ActiveTasks": 0,
                        "PendingTasks": 0
                    }
                },
                "ReadStage": {
                    "request": {
                        "ActiveTasks": 0,
                        "PendingTasks": 0
                    }
                },
                "RequestResponseStage": {
                    "request": {
                        "ActiveTasks": 0,
                        "PendingTasks": 0
                    }
                },
                "mbean": "org.apache.cassandra.metrics:type=ThreadPools,scope=*,path=*,name=*"
            }
        }
    },
    "data_stream": {
        "dataset": "cassandra.metrics",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "1.11.0"
    },
    "elastic_agent": {
        "id": "657e1b7f-adc2-4c7b-88e3-f63540ba62b8",
        "snapshot": true,
        "version": "7.15.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "cassandra.metrics",
        "duration": 24612551,
        "ingested": "2021-09-22T04:12:21Z",
        "module": "jolokia"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "51d851402fe32de9c3ea31615e23a379",
        "ip": [
            "192.168.64.4"
        ],
        "mac": [
            "02:42:c0:a8:40:04"
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
    "metricset": {
        "name": "jmx",
        "period": 10000
    },
    "service": {
        "address": "http://elastic-package-service_cassandra_1:8778/jolokia/%3FignoreErrors=true\u0026canonicalNaming=false",
        "type": "jolokia"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cassandra.metrics.cache.keyCache.OneMinuteHitRate |  | long |
| cassandra.metrics.cache.keyCache.capacity |  | long |
| cassandra.metrics.cache.keyCache.requests.OneMinuteRate |  | long |
| cassandra.metrics.cache.mbean | Mbean that this event is related to | keyword |
| cassandra.metrics.cache.rowCache.OneMinuteHitRate |  | long |
| cassandra.metrics.cache.rowCache.capacity |  | long |
| cassandra.metrics.cache.rowCache.requests.OneMinuteRate |  | long |
| cassandra.metrics.client_request.CASRead.OneMinuteRate |  | long |
| cassandra.metrics.client_request.CASWrite.OneMinuteRate |  | long |
| cassandra.metrics.client_request.mbean | Mbean that this event is related to | keyword |
| cassandra.metrics.client_request.rangeSlice.OneMinuteRate |  | long |
| cassandra.metrics.client_request.read.75thPercentile |  | long |
| cassandra.metrics.client_request.read.95thPercentile |  | long |
| cassandra.metrics.client_request.read.99thPercentile |  | long |
| cassandra.metrics.client_request.read.OneMinuteRate |  | long |
| cassandra.metrics.client_request.read.timeouts |  | long |
| cassandra.metrics.client_request.read.unavailables |  | long |
| cassandra.metrics.client_request.write.75thPercentile |  | long |
| cassandra.metrics.client_request.write.95thPercentile |  | long |
| cassandra.metrics.client_request.write.99thPercentile |  | long |
| cassandra.metrics.client_request.write.OneMinuteRate |  | long |
| cassandra.metrics.client_request.write.timeouts | Number of read timeouts encountered | long |
| cassandra.metrics.client_request.write.unavailables | Number of read unavailables encountered | long |
| cassandra.metrics.columnFamily.mbean | Mbean that this event is related to | keyword |
| cassandra.metrics.columnFamily.totalDiskSpaceUsed |  | long |
| cassandra.metrics.compaction.completedTasks | compaction completed tasks | long |
| cassandra.metrics.compaction.mbean | Mbean that this event is related to | keyword |
| cassandra.metrics.compaction.pendingTasks | compaction pending tasks | long |
| cassandra.metrics.gc.ConcurrentMarkSweep.CollectionCount | Total number of CMS collections that have occurred. | long |
| cassandra.metrics.gc.ConcurrentMarkSweep.CollectionTime | Approximate accumulated CMS collection elapsed time in milliseconds. | long |
| cassandra.metrics.gc.ParNew.CollectionCount | Total number of ParNew collections that have occurred. | long |
| cassandra.metrics.gc.ParNew.CollectionTime | Approximate accumulated ParNew collection elapsed time in milliseconds. | long |
| cassandra.metrics.gc.mbean | Mbean that this event is related to | keyword |
| cassandra.metrics.memory.heap.usage.committed | Committed heap memory usage | long |
| cassandra.metrics.memory.heap.usage.init | Initial heap memory usage | long |
| cassandra.metrics.memory.heap.usage.max | Max heap memory usage | long |
| cassandra.metrics.memory.heap.usage.used | Used heap memory usage | long |
| cassandra.metrics.memory.mbean | Mbean that this event is related to | keyword |
| cassandra.metrics.memory.other.usage.committed | Committed non-heap memory usage | long |
| cassandra.metrics.memory.other.usage.init | Initial non-heap memory usage | long |
| cassandra.metrics.memory.other.usage.max | Max non-heap memory usage | long |
| cassandra.metrics.memory.other.usage.used | Used non-heap memory usage | long |
| cassandra.metrics.storage.Exceptions | The number of the total exceptions | long |
| cassandra.metrics.storage.Load | The Load in storage | long |
| cassandra.metrics.storage.TotalHints | The number of the total hits | long |
| cassandra.metrics.storage.TotalHintsInProgress | The number of the total hits in progress | long |
| cassandra.metrics.storage.mbean | Mbean that this event is related to | keyword |
| cassandra.metrics.table.LiveSSTableCount |  | long |
| cassandra.metrics.table.mbean | Mbean that this event is related to | keyword |
| cassandra.metrics.task.complete | completed tasks | long |
| cassandra.metrics.task.mbean | Mbean that this event is related to | keyword |
| cassandra.metrics.task.pending | pending tasks | long |
| cassandra.metrics.task.total.commitlogSize | total commitlog size of tasks | long |
| cassandra.metrics.threadPools.CounterMutationStage.request.ActiveTasks |  | long |
| cassandra.metrics.threadPools.CounterMutationStage.request.PendingTasks |  | long |
| cassandra.metrics.threadPools.MutationStage.request.ActiveTasks |  | long |
| cassandra.metrics.threadPools.MutationStage.request.PendingTasks |  | long |
| cassandra.metrics.threadPools.ReadRepairStage.request.ActiveTasks |  | long |
| cassandra.metrics.threadPools.ReadRepairStage.request.PendingTasks |  | long |
| cassandra.metrics.threadPools.ReadStage.request.ActiveTasks |  | long |
| cassandra.metrics.threadPools.ReadStage.request.PendingTasks |  | long |
| cassandra.metrics.threadPools.RequestResponseStage.request.ActiveTasks |  | long |
| cassandra.metrics.threadPools.RequestResponseStage.request.PendingTasks |  | long |
| cassandra.metrics.threadPools.mbean | Mbean that this event is related to | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.domain | Destination domain. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| http.request.method | HTTP request method. Prior to ECS 1.6.0 the following guidance was provided: "The field value must be normalized to lowercase for querying." As of ECS 1.6.0, the guidance is deprecated because the original case of the method may be useful in anomaly detection.  Original case will be mandated in ECS 2.0.0 | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| http.response.body.bytes | Size in bytes of the response body. | long |
| http.response.status_code | HTTP response status code. | long |
| http.version | HTTP version. | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | text |
| process.pid | Process id. | long |
| process.thread.id | Thread ID. | long |
| service.address | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service address. Example: If logs or metrics are collected from Elasticsearch, `service.address` would be `elasticsearch`. | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.domain | Source domain. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| tags | List of keywords used to tag each event. | keyword |
| tls.cipher | String indicating the cipher used during the current connection. | keyword |
| tls.version | Numeric part of the version parsed from the original string. | keyword |
| tls.version_protocol | Normalized lowercase protocol name parsed from original string. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | keyword |
| url.path | Path of the request, such as "/search". | keyword |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| user.name | Short name or login of the user. | keyword |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |

