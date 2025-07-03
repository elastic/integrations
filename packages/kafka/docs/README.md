# Kafka integration

This integration collects logs and metrics from [Kafka](https://kafka.apache.org) servers.

## Compatibility

The `log` dataset is tested with logs from Kafka 0.9, 1.1.0 and 2.0.0.

The `broker`, `consumergroup`, `partition`, `jvm`, `network`, `logmanager`, `replicamanager` datastreams are tested with Kafka 0.10.2.1, 1.1.0, 2.1.1, 2.2.2 and 3.6.0.

The `broker`, `jvm`, `network`, `logmanager`, and `replicamanager` metricsets require Jolokia to fetch JMX metrics. Refer to the Metricbeat documentation about Jolokia for more information.

## Logs

### log

The `log` dataset collects and parses logs from Kafka servers.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| kafka.log.class | Java class the log is coming from. | keyword |
| kafka.log.component | Component the log is coming from. | keyword |
| kafka.log.thread | Thread name the log is coming from. | keyword |
| kafka.log.trace.class | Java class the trace is coming from. | keyword |
| kafka.log.trace.message | Message part of the trace. | text |


## Metrics

### broker

The `broker` dataset collects JMX metrics from Kafka brokers using Jolokia.

An example event for `broker` looks as following:

```json
{
    "@timestamp": "2020-05-15T15:12:12.270Z",
    "agent": {
        "ephemeral_id": "178ff0e9-e3dd-4bdf-8e3d-8f67a6bd72ef",
        "id": "5aba67f2-2050-4d19-8953-ba20f0a5483c",
        "name": "kafka-01",
        "type": "metricbeat",
        "version": "8.0.0"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "dataset": "kafka.broker",
        "duration": 4572918,
        "module": "kafka"
    },
    "kafka": {
        "broker": {
            "mbean": "kafka.server:name=BytesOutPerSec,topic=messages,type=BrokerTopicMetrics",
            "topic": {
                "net": {
                    "out": {
                        "bytes_per_sec": 0.6089809926927563
                    }
                }
            }
        }
    },
    "metricset": {
        "name": "broker",
        "period": 10000
    },
    "service": {
        "address": "localhost:8778",
        "type": "kafka"
    }
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| agent.id |  | keyword |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment.  Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |
| cloud.region | Region in which this host is running. | keyword |  |
| container.id | Unique container id. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| event.dataset | Event dataset | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| host.containerized | If the host is a container. | boolean |  |
| host.name | Name of the host.  It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| kafka.broker.address | Broker advertised address | keyword |  |
| kafka.broker.id | Broker id | long |  |
| kafka.broker.log.flush_rate | The log flush rate | float | gauge |
| kafka.broker.mbean | Mbean that this event is related to | keyword |  |
| kafka.broker.messages_in | The incoming message rate | float | gauge |
| kafka.broker.net.in.bytes_per_sec | The incoming byte rate | float | gauge |
| kafka.broker.net.out.bytes_per_sec | The outgoing byte rate | float | gauge |
| kafka.broker.net.rejected.bytes_per_sec | The rejected byte rate | float | gauge |
| kafka.broker.replication.leader_elections | The leader election rate | float | gauge |
| kafka.broker.replication.unclean_leader_elections | The unclean leader election rate | float | gauge |
| kafka.broker.request.channel.queue.size | The size of the request queue | long | gauge |
| kafka.broker.request.fetch.failed | The number of client fetch request failures | float | counter |
| kafka.broker.request.fetch.failed_per_second | The rate of client fetch request failures per second | float | gauge |
| kafka.broker.request.produce.failed | The number of failed produce requests | float | counter |
| kafka.broker.request.produce.failed_per_second | The rate of failed produce requests per second | float | gauge |
| kafka.broker.session.zookeeper.disconnect | The ZooKeeper closed sessions per second | float | gauge |
| kafka.broker.session.zookeeper.expire | The ZooKeeper expired sessions per second | float | gauge |
| kafka.broker.session.zookeeper.readonly | The ZooKeeper readonly sessions per second | float | gauge |
| kafka.broker.session.zookeeper.sync | The ZooKeeper client connections per second | float | gauge |
| kafka.broker.topic.messages_in | The incoming message rate per topic | float | gauge |
| kafka.broker.topic.net.in.bytes_per_sec | The incoming byte rate per topic | float | gauge |
| kafka.broker.topic.net.out.bytes_per_sec | The outgoing byte rate per topic | float | gauge |
| kafka.broker.topic.net.rejected.bytes_per_sec | The rejected byte rate per topic | float | gauge |
| kafka.partition.id | Partition id. | long |  |
| kafka.partition.topic_broker_id | Unique id of the partition in the topic and the broker. | keyword |  |
| kafka.partition.topic_id | Unique id of the partition in the topic. | keyword |  |
| kafka.topic.error.code | Topic error code. | long |  |
| kafka.topic.name | Topic name | keyword |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |


### consumergroup

An example event for `consumergroup` looks as following:

```json
{
    "@timestamp": "2020-05-15T15:18:13.919Z",
    "agent": {
        "ephemeral_id": "178ff0e9-e3dd-4bdf-8e3d-8f67a6bd72ef",
        "id": "5aba67f2-2050-4d19-8953-ba20f0a5483c",
        "name": "kafka-01",
        "type": "metricbeat",
        "version": "8.0.0"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "dataset": "kafka.consumergroup",
        "duration": 8821045,
        "module": "kafka"
    },
    "kafka": {
        "broker": {
            "address": "kafka-01:9092",
            "id": 0
        },
        "consumergroup": {
            "client": {
                "host": "127.0.0.1",
                "id": "consumer-console-consumer-99447-1",
                "member_id": "consumer-console-consumer-99447-1-208fdf91-2f28-4336-a2ff-5e5f4b8b71e4"
            },
            "consumer_lag": 112,
            "error": {
                "code": 0
            },
            "id": "console-consumer-99447",
            "meta": "",
            "offset": -1
        },
        "partition": {
            "id": 0,
            "topic_id": "0-messages"
        },
        "topic": {
            "name": "messages"
        }
    },
    "metricset": {
        "name": "consumergroup",
        "period": 10000
    },
    "service": {
        "address": "localhost:9092",
        "type": "kafka"
    }
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| agent.id |  | keyword |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment.  Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |
| cloud.region | Region in which this host is running. | keyword |  |
| container.id | Unique container id. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| event.dataset | Event dataset | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| host.containerized | If the host is a container. | boolean |  |
| host.name | Name of the host.  It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| kafka.broker.address | Broker advertised address | keyword |  |
| kafka.broker.id | Broker id | long |  |
| kafka.consumergroup.client.host | Client host | keyword |  |
| kafka.consumergroup.client.id | Client ID (kafka setting client.id) | keyword |  |
| kafka.consumergroup.client.member_id | internal consumer group member ID | keyword |  |
| kafka.consumergroup.consumer_lag | consumer lag for partition/topic calculated as the difference between the partition offset and consumer offset | long | gauge |
| kafka.consumergroup.error.code | kafka consumer/partition error code. | long |  |
| kafka.consumergroup.id | Consumer Group ID | keyword |  |
| kafka.consumergroup.meta | custom consumer meta data string | keyword |  |
| kafka.consumergroup.offset | consumer offset into partition being read | long | gauge |
| kafka.partition.id | Partition id. | long |  |
| kafka.partition.topic_broker_id | Unique id of the partition in the topic and the broker. | keyword |  |
| kafka.partition.topic_id | Unique id of the partition in the topic. | keyword |  |
| kafka.topic.error.code | Topic error code. | long |  |
| kafka.topic.name | Topic name | keyword |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |


### partition

An example event for `partition` looks as following:

```json
{
    "@timestamp": "2020-05-15T15:19:44.240Z",
    "agent": {
        "ephemeral_id": "178ff0e9-e3dd-4bdf-8e3d-8f67a6bd72ef",
        "id": "5aba67f2-2050-4d19-8953-ba20f0a5483c",
        "name": "kafka-01",
        "type": "metricbeat",
        "version": "8.0.0"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "dataset": "kafka.partition",
        "duration": 11263377,
        "module": "kafka"
    },
    "kafka": {
        "broker": {
            "address": "kafka-01:9092",
            "id": 0
        },
        "partition": {
            "id": 0,
            "offset": {
                "newest": 111,
                "oldest": 0
            },
            "partition": {
                "insync_replica": true,
                "is_leader": true,
                "leader": 0,
                "replica": 0
            },
            "topic_broker_id": "0-messages-0",
            "topic_id": "0-messages"
        },
        "topic": {
            "name": "messages"
        }
    },
    "metricset": {
        "name": "partition",
        "period": 10000
    },
    "service": {
        "address": "localhost:9092",
        "type": "kafka"
    }
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| agent.id |  | keyword |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment.  Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |
| cloud.region | Region in which this host is running. | keyword |  |
| container.id | Unique container id. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| event.dataset | Event dataset | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| host.containerized | If the host is a container. | boolean |  |
| host.name | Name of the host.  It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| kafka.broker.address | Broker advertised address | keyword |  |
| kafka.broker.id | Broker id | long |  |
| kafka.partition.id | Partition id. | long |  |
| kafka.partition.offset.newest | Newest offset of the partition. | long | gauge |
| kafka.partition.offset.oldest | Oldest offset of the partition. | long | gauge |
| kafka.partition.partition.error.code | Error code from fetching partition. | long |  |
| kafka.partition.partition.insync_replica | Indicates if replica is included in the in-sync replicate set (ISR). | boolean |  |
| kafka.partition.partition.is_leader | Indicates if replica is the leader | boolean |  |
| kafka.partition.partition.leader | Leader id (broker). | long |  |
| kafka.partition.partition.replica | Replica id (broker). | long |  |
| kafka.partition.topic_broker_id | Unique id of the partition in the topic and the broker. | keyword |  |
| kafka.partition.topic_id | Unique id of the partition in the topic. | keyword |  |
| kafka.topic.error.code | Topic error code. | long |  |
| kafka.topic.name | Topic name | keyword |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |


### jvm

The `jvm` dataset collects JVM metrics from Kafka brokers using Jolokia. This includes information about buffer pools, class loading, compilation, garbage collection, memory usage, memory pools, runtime, and threading.

An example event for `jvm` looks as following:

```json
{
    "@timestamp": "2024-01-15T10:30:00.000Z",
    "data_stream": {
        "dataset": "kafka.jvm",
        "namespace": "default",
        "type": "metrics"
    },
    "metricset": {
        "name": "jmx",
        "period": 30000
    },
    "service": {
        "address": "localhost:8778",
        "type": "kafka"
    },
    "kafka": {
        "jvm": {
            "buffer_pool": {
                "name": "direct",
                "used": {
                    "bytes": 67108864
                },
                "capacity": {
                    "bytes": 67108864
                },
                "count": 8
            },
            "classes": {
                "loaded": {
                    "current": 8945,
                    "total": 9120
                },
                "unloaded": {
                    "total": 175
                }
            },
            "compilation": {
                "time": {
                    "ms": 2341
                }
            },
            "gc": {
                "name": "G1 Young Generation",
                "collection": {
                    "count": 42,
                    "time": {
                        "ms": 150
                    }
                }
            },
            "memory": {
                "heap": {
                    "committed": 1073741824,
                    "init": 134217728,
                    "max": 1073741824,
                    "used": 536870912
                },
                "non_heap": {
                    "committed": 67108864,
                    "init": 2555904,
                    "max": -1,
                    "used": 45088768
                },
                "objects_pending_finalization": 0
            },
            "memory_pool": {
                "name": "G1 Eden Space",
                "usage": {
                    "committed": 268435456,
                    "init": 67108864,
                    "max": -1,
                    "used": 134217728
                },
                "collection_usage": {
                    "committed": 268435456,
                    "init": 67108864,
                    "max": -1,
                    "used": 0
                }
            },
            "runtime": {
                "name": "OpenJDK 64-Bit Server VM",
                "vendor": "Eclipse Adoptium",
                "version": "11.0.19+7",
                "spec": {
                    "name": "Java Virtual Machine Specification",
                    "vendor": "Oracle Corporation",
                    "version": "11"
                }
            },
            "threads": {
                "count": 156,
                "daemon": 12,
                "peak": 158,
                "started": {
                    "total": 200
                }
            }
        }
    }
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| event.dataset | Event dataset | constant_keyword |  |  |
| event.module | Event module | constant_keyword |  |  |
| kafka.jvm.buffer_pool.capacity.bytes | Total capacity in bytes | long | byte | gauge |
| kafka.jvm.buffer_pool.count | Number of buffers | long |  | gauge |
| kafka.jvm.buffer_pool.name | Buffer pool name | keyword |  |  |
| kafka.jvm.buffer_pool.used.bytes | Used memory in bytes | long | byte | gauge |
| kafka.jvm.classes.loaded.current | Currently loaded classes | long |  | gauge |
| kafka.jvm.classes.loaded.total | Total classes loaded since JVM start | long |  | counter |
| kafka.jvm.classes.unloaded.total | Total classes unloaded since JVM start | long |  | counter |
| kafka.jvm.compilation.time.ms | Total compilation time in milliseconds | long | ms | counter |
| kafka.jvm.gc.collection.count | Number of GC collections | long |  | counter |
| kafka.jvm.gc.collection.time.ms | Total collection time in milliseconds | long | ms | counter |
| kafka.jvm.gc.name | GC collector name | keyword |  |  |
| kafka.jvm.memory.heap.committed | Committed heap memory | long | byte | gauge |
| kafka.jvm.memory.heap.init | Initial heap memory | long | byte | gauge |
| kafka.jvm.memory.heap.max | Maximum heap memory | long | byte | gauge |
| kafka.jvm.memory.heap.used | Used heap memory | long | byte | gauge |
| kafka.jvm.memory.non_heap.committed | Committed non-heap memory | long | byte | gauge |
| kafka.jvm.memory.non_heap.init | Initial non-heap memory | long | byte | gauge |
| kafka.jvm.memory.non_heap.max | Maximum non-heap memory | long | byte | gauge |
| kafka.jvm.memory.non_heap.used | Used non-heap memory | long | byte | gauge |
| kafka.jvm.memory.objects_pending_finalization | Objects pending finalization | long |  | gauge |
| kafka.jvm.memory_pool.collection_usage.committed | Committed bytes after GC | long | byte | gauge |
| kafka.jvm.memory_pool.collection_usage.init | Initial bytes after GC | long | byte | gauge |
| kafka.jvm.memory_pool.collection_usage.max | Maximum bytes after GC | long | byte | gauge |
| kafka.jvm.memory_pool.collection_usage.used | Used bytes after GC | long | byte | gauge |
| kafka.jvm.memory_pool.name | Memory pool name | keyword |  |  |
| kafka.jvm.memory_pool.usage.committed | Committed bytes in memory pool | long | byte | gauge |
| kafka.jvm.memory_pool.usage.init | Initial bytes in memory pool | long | byte | gauge |
| kafka.jvm.memory_pool.usage.max | Maximum bytes in memory pool | long | byte | gauge |
| kafka.jvm.memory_pool.usage.used | Used bytes in memory pool | long | byte | gauge |
| kafka.jvm.runtime.name | JVM name | keyword |  |  |
| kafka.jvm.runtime.spec.name | JVM specification name | keyword |  |  |
| kafka.jvm.runtime.spec.vendor | JVM specification vendor | keyword |  |  |
| kafka.jvm.runtime.spec.version | JVM specification version | keyword |  |  |
| kafka.jvm.runtime.vendor | JVM vendor | keyword |  |  |
| kafka.jvm.runtime.version | JVM version | keyword |  |  |
| kafka.jvm.threads.count | Current number of threads | long |  | gauge |
| kafka.jvm.threads.daemon | Number of daemon threads | long |  | gauge |
| kafka.jvm.threads.peak | Peak number of threads | long |  | gauge |
| kafka.jvm.threads.started.total | Total number of threads started | long |  | counter |


### network

The `network` dataset collects network metrics from Kafka brokers using Jolokia. This includes information about network acceptors, processors, request channels, request metrics, and socket servers.

An example event for `network` looks as following:

```json
{
    "@timestamp": "2024-01-15T10:30:00.000Z",
    "data_stream": {
        "dataset": "kafka.network",
        "namespace": "default",
        "type": "metrics"
    },
    "metricset": {
        "name": "jmx",
        "period": 30000
    },
    "service": {
        "address": "localhost:8778",
        "type": "kafka"
    },
    "kafka": {
        "network": {
            "acceptor": {
                "name": "acceptor-blocked-percent",
                "blocked_percent": 0.5
            },
            "processor": {
                "name": "processor-idle-percent",
                "idle_percent": 85.2
            },
            "request_channel": {
                "name": "request-queue-size",
                "request_queue_size": 15,
                "response_queue_size": 8
            },
            "request_metrics": {
                "name": "errors-per-sec",
                "errors_per_sec": 0.1,
                "local_time_ms": 45,
                "message_conversions_time_ms": 12,
                "remote_time_ms": 23,
                "request_bytes": 1024,
                "request_queue_time_ms": 5,
                "requests_per_sec": 150.5,
                "response_queue_time_ms": 3,
                "response_send_time_ms": 8,
                "temporary_memory_bytes": 2048,
                "throttle_time_ms": 0,
                "total_time_ms": 98
            },
            "socket_server": {
                "name": "expired-connections-killed-count",
                "expired_connections_killed_count": 2,
                "memory_pool_available": 67108864,
                "memory_pool_used": 33554432,
                "network_processor_avg_idle_percent": 82.3
            }
        }
    }
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| event.dataset | Event dataset | constant_keyword |  |  |
| event.module | Event module | constant_keyword |  |  |
| kafka.network.acceptor.blocked_percent | Percentage of time the acceptor was blocked | double | percent | gauge |
| kafka.network.acceptor.name | Acceptor name | keyword |  |  |
| kafka.network.processor.idle_percent | Percentage of time the processor was idle | double | percent | gauge |
| kafka.network.processor.name | Processor name | keyword |  |  |
| kafka.network.request_channel.name | Request channel name | keyword |  |  |
| kafka.network.request_channel.request_queue_size | Size of request queue | long |  | gauge |
| kafka.network.request_channel.response_queue_size | Size of response queue | long |  | gauge |
| kafka.network.request_metrics.errors_per_sec | Number of errors per second | double | s | gauge |
| kafka.network.request_metrics.local_time_ms | Local time in milliseconds | long | ms | gauge |
| kafka.network.request_metrics.message_conversions_time_ms | Message conversions time in milliseconds | long | ms | gauge |
| kafka.network.request_metrics.name | Request metric name | keyword |  |  |
| kafka.network.request_metrics.remote_time_ms | Remote time in milliseconds | long | ms | gauge |
| kafka.network.request_metrics.request_bytes | Request bytes | long | byte | gauge |
| kafka.network.request_metrics.request_queue_time_ms | Request queue time in milliseconds | long | ms | gauge |
| kafka.network.request_metrics.requests_per_sec | Number of requests per second | double | s | gauge |
| kafka.network.request_metrics.response_queue_time_ms | Response queue time in milliseconds | long | ms | gauge |
| kafka.network.request_metrics.response_send_time_ms | Response send time in milliseconds | long | ms | gauge |
| kafka.network.request_metrics.temporary_memory_bytes | Temporary memory bytes | long | byte | gauge |
| kafka.network.request_metrics.throttle_time_ms | Throttle time in milliseconds | long | ms | gauge |
| kafka.network.request_metrics.total_time_ms | Total time in milliseconds | long | ms | gauge |
| kafka.network.socket_server.expired_connections_killed_count | Number of expired connections killed | long |  | counter |
| kafka.network.socket_server.memory_pool_available | Available memory pool | long | byte | gauge |
| kafka.network.socket_server.memory_pool_used | Used memory pool | long | byte | gauge |
| kafka.network.socket_server.name | Socket server name | keyword |  |  |
| kafka.network.socket_server.network_processor_avg_idle_percent | Average idle percentage of network processors | double | percent | gauge |


### logmanager

The `logmanager` dataset collects log management metrics from Kafka brokers using Jolokia. This includes information about log segments, log cleaners, log cleaner managers, log flush statistics, and log managers.

An example event for `logmanager` looks as following:

```json
{
    "@timestamp": "2024-01-15T10:30:00.000Z",
    "data_stream": {
        "dataset": "kafka.logmanager",
        "namespace": "default",
        "type": "metrics"
    },
    "metricset": {
        "name": "jmx",
        "period": 30000
    },
    "service": {
        "address": "localhost:8778",
        "type": "kafka"
    },
    "kafka": {
        "logmanager": {
            "log": {
                "name": "log-end-offset",
                "log_end_offset": 1000000,
                "log_start_offset": 0,
                "num_log_segments": 5,
                "size": 1073741824
            },
            "log_cleaner": {
                "name": "cleaner-recopy-percent",
                "cleaner_recopy_percent": 15.5,
                "dead_thread_count": 0,
                "max_buffer_utilization_percent": 75.2,
                "max_clean_time_secs": 300,
                "max_compaction_delay_secs": 600
            },
            "log_cleaner_manager": {
                "name": "max-dirty-percent",
                "max_dirty_percent": 50.0,
                "time_since_last_run_ms": 30000,
                "uncleanable_bytes": 0,
                "uncleanable_partitions_count": 0
            },
            "log_flush_stats": {
                "name": "log-flush-rate-and-time-ms",
                "log_flush_rate_and_time_ms": 25
            },
            "log_manager": {
                "name": "log-directory-offline",
                "log_directory_offline": 0,
                "offline_log_directory_count": 0,
                "remaining_logs_to_recover": 0,
                "remaining_segments_to_recover": 0
            }
        }
    }
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| event.dataset | Event dataset | constant_keyword |  |  |
| event.module | Event module | constant_keyword |  |  |
| kafka.logmanager.log.log_end_offset | Log end offset | long |  | gauge |
| kafka.logmanager.log.log_start_offset | Log start offset | long |  | gauge |
| kafka.logmanager.log.name | Log name | keyword |  |  |
| kafka.logmanager.log.num_log_segments | Number of log segments | long |  | gauge |
| kafka.logmanager.log.size | Log size | long | byte | gauge |
| kafka.logmanager.log_cleaner.cleaner_recopy_percent | Cleaner recopy percentage | double | percent | gauge |
| kafka.logmanager.log_cleaner.dead_thread_count | Dead thread count | long |  | gauge |
| kafka.logmanager.log_cleaner.max_buffer_utilization_percent | Maximum buffer utilization percentage | double | percent | gauge |
| kafka.logmanager.log_cleaner.max_clean_time_secs | Maximum clean time in seconds | long | s | gauge |
| kafka.logmanager.log_cleaner.max_compaction_delay_secs | Maximum compaction delay in seconds | long | s | gauge |
| kafka.logmanager.log_cleaner.name | Log cleaner name | keyword |  |  |
| kafka.logmanager.log_cleaner_manager.max_dirty_percent | Maximum dirty percentage | double | percent | gauge |
| kafka.logmanager.log_cleaner_manager.name | Log cleaner manager name | keyword |  |  |
| kafka.logmanager.log_cleaner_manager.time_since_last_run_ms | Time since last run in milliseconds | long | ms | gauge |
| kafka.logmanager.log_cleaner_manager.uncleanable_bytes | Uncleanable bytes | long | byte | gauge |
| kafka.logmanager.log_cleaner_manager.uncleanable_partitions_count | Uncleanable partitions count | long |  | gauge |
| kafka.logmanager.log_flush_stats.log_flush_rate_and_time_ms | Log flush rate and time in milliseconds | long | ms | gauge |
| kafka.logmanager.log_flush_stats.name | Log flush stats name | keyword |  |  |
| kafka.logmanager.log_manager.log_directory_offline | Log directory offline status (0 for false, 1 for true) | long |  | gauge |
| kafka.logmanager.log_manager.name | Log manager name | keyword |  |  |
| kafka.logmanager.log_manager.offline_log_directory_count | Offline log directory count | long |  | gauge |
| kafka.logmanager.log_manager.remaining_logs_to_recover | Remaining logs to recover | long |  | gauge |
| kafka.logmanager.log_manager.remaining_segments_to_recover | Remaining segments to recover | long |  | gauge |


### replicamanager

The `replicamanager` dataset collects replica management metrics from Kafka brokers using Jolokia. This includes information about ISR (In-Sync Replicas), partition counts, leader replicas, offline replicas, and reassignment operations.

An example event for `replicamanager` looks as following:

```json
{
    "@timestamp": "2024-01-15T10:30:00.000Z",
    "data_stream": {
        "dataset": "kafka.replicamanager",
        "namespace": "default",
        "type": "metrics"
    },
    "metricset": {
        "name": "jmx",
        "period": 30000
    },
    "service": {
        "address": "localhost:8778",
        "type": "kafka"
    },
    "kafka": {
        "replicamanager": {
            "replica_manager": {
                "name": "at-min-isr-partition-count",
                "at_min_isr_partition_count": 50,
                "failed_isr_updates_per_sec": 0.1,
                "isr_expands_per_sec": 2.5,
                "isr_shrinks_per_sec": 1.2,
                "leader_count": 100,
                "offline_replica_count": 0,
                "partition_count": 150,
                "partitions_with_late_transactions_count": 2,
                "producer_id_count": 25,
                "reassigning_partitions": 0,
                "under_min_isr_partition_count": 5,
                "under_replicated_partitions": 3
            }
        }
    }
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| event.dataset | Event dataset | constant_keyword |  |  |
| event.module | Event module | constant_keyword |  |  |
| kafka.replicamanager.replica_manager.at_min_isr_partition_count | Number of partitions at minimum ISR | long |  | gauge |
| kafka.replicamanager.replica_manager.failed_isr_updates_per_sec | Failed ISR updates per second | double | s | gauge |
| kafka.replicamanager.replica_manager.isr_expands_per_sec | ISR expands per second | double | s | gauge |
| kafka.replicamanager.replica_manager.isr_shrinks_per_sec | ISR shrinks per second | double | s | gauge |
| kafka.replicamanager.replica_manager.leader_count | Number of leader replicas | long |  | gauge |
| kafka.replicamanager.replica_manager.name | Replica manager metric name | keyword |  |  |
| kafka.replicamanager.replica_manager.offline_replica_count | Number of offline replicas | long |  | gauge |
| kafka.replicamanager.replica_manager.partition_count | Number of partitions | long |  | gauge |
| kafka.replicamanager.replica_manager.partitions_with_late_transactions_count | Number of partitions with late transactions | long |  | gauge |
| kafka.replicamanager.replica_manager.producer_id_count | Number of producer IDs | long |  | gauge |
| kafka.replicamanager.replica_manager.reassigning_partitions | Number of reassigning partitions | long |  | gauge |
| kafka.replicamanager.replica_manager.under_min_isr_partition_count | Number of partitions under minimum ISR | long |  | gauge |
| kafka.replicamanager.replica_manager.under_replicated_partitions | Number of under-replicated partitions | long |  | gauge |
