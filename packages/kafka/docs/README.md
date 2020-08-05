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
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| kafka.log.class | Java class the log is coming from. | keyword |
| kafka.log.component | Component the log is coming from. | keyword |
| kafka.log.trace.class | Java class the trace is coming from. | keyword |
| kafka.log.trace.message | Message part of the trace. | text |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | text |


## Metrics

### broker

The `broker` dataset collects JMX metrics from Kafka brokers using Jolokia.

An example event for `broker` looks as following:

```$json
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
    "version": "1.5.0"
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
  },
  "stream": {
    "dataset": "kafka.broker",
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
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
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


### consumergroup

An example event for `consumergroup` looks as following:

```$json
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
    "version": "1.5.0"
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
      "broker": {
        "address": "kafka-01:9092",
        "id": 0
      },
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
      "offset": -1,
      "partition": 0,
      "topic": "messages"
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
  },
  "stream": {
    "dataset": "kafka.consumergroup",
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
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
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


### partition

An example event for `partition` looks as following:

```$json
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
    "version": "1.5.0"
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
      "broker": {
        "address": "kafka-01:9092",
        "id": 0
      },
      "id": 0,
      "offset": {
        "newest": 111,
        "oldest": 0
      },
      "partition": {
        "id": 0,
        "insync_replica": true,
        "is_leader": true,
        "leader": 0,
        "replica": 0
      },
      "topic": {
        "name": "messages"
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
  },
  "stream": {
    "dataset": "kafka.partition",
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
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
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
