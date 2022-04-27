# Kafka integration

This integration collects logs and metrics from [Kafka](https://kafka.apache.org) servers.

## Compatibility

The `log` dataset is tested with logs from Kafka 0.9, 1.1.0 and 2.0.0.

The `broker`, `consumergroup`, `partition` and `producer` metricsets are tested with Kafka 0.10.2.1, 1.1.0, 2.1.1, and 2.2.2.

The `broker` metricset requires Jolokia to fetch JMX metrics. Refer to the Metricbeat documentation about Jolokia for more information.

## Logs

### log

The `log` dataset collects and parses logs from Kafka servers.

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
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
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
| kafka.log.class | Java class the log is coming from. | keyword |
| kafka.log.component | Component the log is coming from. | keyword |
| kafka.log.thread | Thread name the log is coming from. | keyword |
| kafka.log.trace.class | Java class the trace is coming from. | keyword |
| kafka.log.trace.message | Message part of the trace. | text |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |


## Metrics

### broker

The `broker` dataset collects JMX metrics from Kafka brokers using Jolokia.

An example event for `broker` looks as following:

```json
{
    "@timestamp": "2020-05-15T15:12:12.270Z",
    "service": {
        "address": "localhost:8778",
        "type": "kafka"
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
    "event": {
        "dataset": "kafka.broker",
        "module": "kafka",
        "duration": 4572918
    },
    "metricset": {
        "period": 10000,
        "name": "broker"
    },
    "ecs": {
        "version": "1.5.0"
    },
    "agent": {
        "id": "5aba67f2-2050-4d19-8953-ba20f0a5483c",
        "name": "kafka-01",
        "type": "metricbeat",
        "version": "8.0.0",
        "ephemeral_id": "178ff0e9-e3dd-4bdf-8e3d-8f67a6bd72ef"
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
| kafka.broker.address | Broker advertised address | keyword |
| kafka.broker.id | Broker id | long |
| kafka.broker.log.flush_rate | The log flush rate | float |
| kafka.broker.mbean | Mbean that this event is related to | keyword |
| kafka.broker.messages_in | The incoming message rate | float |
| kafka.broker.net.in.bytes_per_sec | The incoming byte rate | float |
| kafka.broker.net.out.bytes_per_sec | The outgoing byte rate | float |
| kafka.broker.net.rejected.bytes_per_sec | The rejected byte rate | float |
| kafka.broker.replication.leader_elections | The leader election rate | float |
| kafka.broker.replication.unclean_leader_elections | The unclean leader election rate | float |
| kafka.broker.request.channel.queue.size | The size of the request queue | long |
| kafka.broker.request.fetch.failed | The number of client fetch request failures | float |
| kafka.broker.request.fetch.failed_per_second | The rate of client fetch request failures per second | float |
| kafka.broker.request.produce.failed | The number of failed produce requests | float |
| kafka.broker.request.produce.failed_per_second | The rate of failed produce requests per second | float |
| kafka.broker.session.zookeeper.disconnect | The ZooKeeper closed sessions per second | float |
| kafka.broker.session.zookeeper.expire | The ZooKeeper expired sessions per second | float |
| kafka.broker.session.zookeeper.readonly | The ZooKeeper readonly sessions per second | float |
| kafka.broker.session.zookeeper.sync | The ZooKeeper client connections per second | float |
| kafka.broker.topic.messages_in | The incoming message rate per topic | float |
| kafka.broker.topic.net.in.bytes_per_sec | The incoming byte rate per topic | float |
| kafka.broker.topic.net.out.bytes_per_sec | The outgoing byte rate per topic | float |
| kafka.broker.topic.net.rejected.bytes_per_sec | The rejected byte rate per topic | float |
| kafka.partition.id | Partition id. | long |
| kafka.partition.topic_broker_id | Unique id of the partition in the topic and the broker. | keyword |
| kafka.partition.topic_id | Unique id of the partition in the topic. | keyword |
| kafka.topic.error.code | Topic error code. | long |
| kafka.topic.name | Topic name | keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |


### consumergroup

An example event for `consumergroup` looks as following:

```json
{
    "@timestamp": "2020-05-15T15:18:13.919Z",
    "agent": {
        "name": "kafka-01",
        "type": "metricbeat",
        "version": "8.0.0",
        "ephemeral_id": "178ff0e9-e3dd-4bdf-8e3d-8f67a6bd72ef",
        "id": "5aba67f2-2050-4d19-8953-ba20f0a5483c"
    },
    "ecs": {
        "version": "1.5.0"
    },
    "kafka": {
        "consumergroup": {
            "topic": "messages",
            "error": {
                "code": 0
            },
            "broker": {
                "id": 0,
                "address": "kafka-01:9092"
            },
            "id": "console-consumer-99447",
            "offset": -1,
            "consumer_lag": 112,
            "client": {
                "member_id": "consumer-console-consumer-99447-1-208fdf91-2f28-4336-a2ff-5e5f4b8b71e4",
                "id": "consumer-console-consumer-99447-1",
                "host": "127.0.0.1"
            },
            "partition": 0,
            "meta": ""
        },
        "broker": {
            "id": 0,
            "address": "kafka-01:9092"
        },
        "topic": {
            "name": "messages"
        },
        "partition": {
            "id": 0,
            "topic_id": "0-messages"
        }
    },
    "event": {
        "dataset": "kafka.consumergroup",
        "module": "kafka",
        "duration": 8821045
    },
    "metricset": {
        "period": 10000,
        "name": "consumergroup"
    },
    "service": {
        "address": "localhost:9092",
        "type": "kafka"
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
| kafka.broker.address | Broker advertised address | keyword |
| kafka.broker.id | Broker id | long |
| kafka.consumergroup.broker.address | Broker address | keyword |
| kafka.consumergroup.broker.id | Broker id | long |
| kafka.consumergroup.client.host | Client host | keyword |
| kafka.consumergroup.client.id | Client ID (kafka setting client.id) | keyword |
| kafka.consumergroup.client.member_id | internal consumer group member ID | keyword |
| kafka.consumergroup.consumer_lag | consumer lag for partition/topic calculated as the difference between the partition offset and consumer offset | long |
| kafka.consumergroup.error.code | kafka consumer/partition error code. | long |
| kafka.consumergroup.id | Consumer Group ID | keyword |
| kafka.consumergroup.meta | custom consumer meta data string | keyword |
| kafka.consumergroup.offset | consumer offset into partition being read | long |
| kafka.consumergroup.partition | Partition ID | long |
| kafka.consumergroup.topic | Topic name | keyword |
| kafka.partition.id | Partition id. | long |
| kafka.partition.topic_broker_id | Unique id of the partition in the topic and the broker. | keyword |
| kafka.partition.topic_id | Unique id of the partition in the topic. | keyword |
| kafka.topic.error.code | Topic error code. | long |
| kafka.topic.name | Topic name | keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |


### partition

An example event for `partition` looks as following:

```json
{
    "@timestamp": "2020-05-15T15:19:44.240Z",
    "metricset": {
        "name": "partition",
        "period": 10000
    },
    "service": {
        "address": "localhost:9092",
        "type": "kafka"
    },
    "kafka": {
        "partition": {
            "offset": {
                "oldest": 0,
                "newest": 111
            },
            "id": 0,
            "topic_id": "0-messages",
            "topic_broker_id": "0-messages-0",
            "topic": {
                "name": "messages"
            },
            "broker": {
                "id": 0,
                "address": "kafka-01:9092"
            },
            "partition": {
                "is_leader": true,
                "insync_replica": true,
                "id": 0,
                "leader": 0,
                "replica": 0
            }
        },
        "broker": {
            "address": "kafka-01:9092",
            "id": 0
        },
        "topic": {
            "name": "messages"
        }
    },
    "ecs": {
        "version": "1.5.0"
    },
    "agent": {
        "ephemeral_id": "178ff0e9-e3dd-4bdf-8e3d-8f67a6bd72ef",
        "id": "5aba67f2-2050-4d19-8953-ba20f0a5483c",
        "name": "kafka-01",
        "type": "metricbeat",
        "version": "8.0.0"
    },
    "event": {
        "dataset": "kafka.partition",
        "module": "kafka",
        "duration": 11263377
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
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
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
| kafka.broker.address | Broker advertised address | keyword |
| kafka.broker.id | Broker id | long |
| kafka.partition.broker.address | Broker address | keyword |
| kafka.partition.broker.id | Broker id | long |
| kafka.partition.id | Partition id. | long |
| kafka.partition.offset.newest | Newest offset of the partition. | long |
| kafka.partition.offset.oldest | Oldest offset of the partition. | long |
| kafka.partition.partition.error.code | Error code from fetching partition. | long |
| kafka.partition.partition.id | Partition id. | long |
| kafka.partition.partition.insync_replica | Indicates if replica is included in the in-sync replicate set (ISR). | boolean |
| kafka.partition.partition.is_leader | Indicates if replica is the leader | boolean |
| kafka.partition.partition.isr | List of isr ids. | keyword |
| kafka.partition.partition.leader | Leader id (broker). | long |
| kafka.partition.partition.replica | Replica id (broker). | long |
| kafka.partition.topic.error.code | topic error code. | long |
| kafka.partition.topic.name | Topic name | keyword |
| kafka.partition.topic_broker_id | Unique id of the partition in the topic and the broker. | keyword |
| kafka.partition.topic_id | Unique id of the partition in the topic. | keyword |
| kafka.topic.error.code | Topic error code. | long |
| kafka.topic.name | Topic name | keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
