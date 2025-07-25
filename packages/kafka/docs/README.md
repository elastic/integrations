# Kafka integration

This integration collects logs and metrics from [Kafka](https://kafka.apache.org) servers.

## Compatibility

The `log` dataset is tested with logs from Kafka 0.9, 1.1.0 and 2.0.0.

The `broker`, `consumergroup`, `partition` datastreams are tested with Kafka 0.10.2.1, 1.1.0, 2.1.1, 2.2.2 and 3.6.0.

The `broker` metricset requires Jolokia to fetch JMX metrics. Refer to the Metricbeat documentation about Jolokia for more information.

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


### raft

The `raft` dataset collects metrics related to Kafka's Raft consensus algorithm implementation (KRaft), which is used for metadata management in Kafka without requiring ZooKeeper. KRaft mode is available in Kafka 3.0.0 and later versions.

This dataset includes metrics such as:
- Append and fetch records rates
- Commit latency (average and maximum)
- Current epoch, leader, and vote information
- Current epoch, leader, and vote information 
- High watermark and log offset metrics
- Node state and voter information
- Poll idle ratio

An example event for `raft` looks as following:

```json
{
    "@timestamp": "2025-07-21T08:52:02.169Z",
    "agent": {
        "ephemeral_id": "9b3488ec-43b2-4927-992d-66e7916db610",
        "id": "98300b09-b816-4ff7-87aa-a3dd3410656c",
        "name": "elastic-agent-92636",
        "type": "metricbeat",
        "version": "8.16.6"
    },
    "cloud": {
        "account": {
            "id": "elastic-obs-integrations-dev"
        },
        "availability_zone": "asia-south1-c",
        "instance": {
            "id": "5798221542184199336",
            "name": "service-integration-dev-idc-ubuntu25-4"
        },
        "machine": {
            "type": "n1-standard-4"
        },
        "project": {
            "id": "elastic-obs-integrations-dev"
        },
        "provider": "gcp",
        "region": "asia-south1",
        "service": {
            "name": "GCE"
        }
    },
    "data_stream": {
        "dataset": "kafka.raft",
        "namespace": "60294",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "98300b09-b816-4ff7-87aa-a3dd3410656c",
        "snapshot": false,
        "version": "8.16.6"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "kafka.raft",
        "duration": 29347144,
        "ingested": "2025-07-21T08:52:04Z",
        "module": "jolokia"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "elastic-agent-92636",
        "ip": [
            "172.21.0.2",
            "172.19.0.6"
        ],
        "mac": [
            "0A-4F-66-38-0A-41",
            "A2-41-CC-86-C2-F0"
        ],
        "name": "elastic-agent-92636",
        "os": {
            "family": "",
            "kernel": "6.14.0-1006-gcp",
            "name": "Wolfi",
            "platform": "wolfi",
            "type": "linux",
            "version": "20230201"
        }
    },
    "kafka": {
        "raft": {
            "append_records_rate": 0.672182006204757,
            "commit_latency_avg": 0,
            "commit_latency_max": 0,
            "current_epoch": 1,
            "current_leader": 1,
            "current_state": "leader",
            "current_vote": 1,
            "fetch_records_rate": 0,
            "high_watermark": 26,
            "log_end_epoch": 1,
            "log_end_offset": 26,
            "number_of_voters": 1,
            "number_unknown_voter_connections": 0,
            "poll_idle_ratio_avg": 0.9814143775569842
        }
    },
    "metricset": {
        "name": "jmx",
        "period": 10000
    },
    "service": {
        "address": "http://kafka:8779/jolokia",
        "type": "jolokia"
    }
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| agent.id |  | keyword |  |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment.  Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |  |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |  |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |  |
| cloud.region | Region in which this host is running. | keyword |  |  |
| container.id | Unique container id. | keyword |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| event.module | Event module | constant_keyword |  |  |
| host.containerized | If the host is a container. | boolean |  |  |
| host.name | Name of the host.  It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |  |
| host.os.build | OS build information. | keyword |  |  |
| host.os.codename | OS codename, if any. | keyword |  |  |
| kafka.raft.append_records_rate | The average number of records appended per sec as the leader of the raft quorum. | double |  | gauge |
| kafka.raft.commit_latency_avg | The average time in milliseconds to commit an entry in the raft log. | double | ms | gauge |
| kafka.raft.commit_latency_max | The maximum time in milliseconds to commit an entry in the raft log. | double | ms | gauge |
| kafka.raft.current_epoch | The current quorum epoch. | long |  | gauge |
| kafka.raft.current_leader | The current quorum leader's id; -1 indicates unknown. | long |  | gauge |
| kafka.raft.current_state | The current state of this member; possible values are leader, candidate, voted, follower, unattached, observer. | keyword |  |  |
| kafka.raft.current_vote | The current voted id. | long |  | gauge |
| kafka.raft.fetch_records_rate | The average number of records fetched from the leader of the raft quorum. | double |  | gauge |
| kafka.raft.high_watermark | The high watermark maintained on this member; -1 if it is unknown. | long |  | gauge |
| kafka.raft.log_end_epoch | The current raft log end epoch. | long |  | gauge |
| kafka.raft.log_end_offset | The current raft log end offset. | long |  | gauge |
| kafka.raft.number_of_voters | Number of voters for a KRaft topic partition. | double |  | gauge |
| kafka.raft.number_unknown_voter_connections | Number of unknown voters whose connection information is not cached; would never be larger than quorum-size. | double |  | gauge |
| kafka.raft.poll_idle_ratio_avg | The ratio of time the Raft IO thread is idle as opposed to doing work (e.g. handling requests or replicating from the leader). | double | percent | gauge |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
