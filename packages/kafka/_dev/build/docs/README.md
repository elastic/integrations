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

{{fields "log"}}

## Metrics

### broker

The `broker` dataset collects JMX metrics from Kafka brokers using Jolokia.

{{event "broker"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "broker"}}

### consumergroup

{{event "consumergroup"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "consumergroup"}}

### partition

{{event "partition"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "partition"}}

### raft

The `raft` dataset collects metrics related to Kafka's Raft consensus algorithm implementation (KRaft), which is used for metadata management in Kafka without requiring ZooKeeper. KRaft mode is available in Kafka 3.0.0 and later versions.

This dataset includes metrics such as:
- Append and fetch records rates
- Commit latency (average and maximum)
- Current epoch, leader, and vote information
- High watermark and log offset metrics
- Node state and voter information
- Poll idle ratio

{{event "raft"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "raft"}}

### controller

The `controller` dataset collects metrics related to the Kafka controller, which is responsible for managing broker states, partition assignments, and other administrative operations in the Kafka cluster.

This dataset includes metrics such as:
- Controller event manager metrics (queue processing and wait times)
- Cluster state metrics (active brokers, controllers, topics, and partitions)
- Record management metrics (lag, offset, and timestamp information)
- Error and health metrics (offline partitions, heartbeat timeouts, metadata errors)

{{event "controller"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "controller"}}

### replica_manager

The `replica_manager` dataset collects metrics related to Kafka's replica management system, which is responsible for handling data replication across brokers in the Kafka cluster.

This dataset includes metrics such as:
- ReplicaAlterLogDirsManager metrics (dead threads, failed partitions, lag, and fetch rates)
- ReplicaFetcherManager metrics (dead threads, failed partitions, lag, and fetch rates)
- In-Sync Replica (ISR) metrics (expansions, shrinks, and update failures)
- Partition metrics (leader count, offline replicas, under-replicated partitions)
- Reassignment and replication health metrics (reassigning partitions, under min ISR partition count)

{{event "replica_manager"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "replica_manager"}}

### jvm

The `jvm` dataset collects metrics related to the Java Virtual Machine (JVM) running the Kafka broker, providing insights into the performance and health of the Java runtime environment.

This dataset includes metrics such as:
- Runtime metrics (uptime, VM name, version, and vendor)
- Memory metrics (heap and non-heap usage, memory pool statistics)
- Threading metrics (thread counts, deadlocks, thread states)
- Garbage collection metrics (collection counts and times)
- Class loading metrics (loaded and unloaded class counts)
- Buffer pool metrics (memory usage and capacity)
- JIT compilation metrics (time spent in compilation)

{{event "jvm"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "jvm"}}

### log_manager

The `log_manager` dataset collects metrics related to Kafka's log management system, which is responsible for handling log segments, cleaning, and maintenance operations.

This dataset includes metrics such as:
- Log cleaner metrics (buffer utilization, cleaning times, recopy percentages)
- Cleaner manager metrics (dirty log percentages, uncleanable partitions)
- Log directory metrics (offline directories, directory status)
- Log flush statistics (flush rates and times)
- Log recovery metrics (remaining logs and segments to recover)

{{event "log_manager"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "log_manager"}}

### network

The `network` dataset collects metrics related to Kafka's network subsystem, providing insights into the broker's network performance, request handling, and socket server operations.

This dataset includes metrics such as:
- Socket server metrics (memory pool usage, expired connections)
- Network processor metrics (idle percentages, queue sizes)
- Request metrics for different request types (processing times, queue times)
- Throttle time metrics (how long requests are throttled)
- Request and response size metrics
- Request channel metrics (queue sizes and processing performance)

{{event "network"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "network"}}

### topic

The `topic` dataset collects metrics specific to Kafka topics and their partitions, providing insights into topic throughput, partition health, and log segment information.

This dataset includes metrics such as:
- Topic-level metrics (bytes in/out per second, message rates, fetch request rates)
- Partition metrics (in-sync replicas, under-replicated status, minimum ISR status)
- Log metrics (offset information, segment counts, log sizes)

{{event "topic"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "topic"}}

### consumer

The `consumer` dataset collects metrics specifically for monitoring the performance, throughput, and health of Kafka consumers. It provides key insights into how effectively consumers are processing data, their rate of interaction with brokers, and whether they are keeping up with message production.

This dataset includes metrics such as:
- Consumption Rates: Metrics like bytes_consumed, records_consumed, and in.bytes_per_sec track the throughput of the consumer in terms of both the number of messages and the volume of data processed per second.
- Consumer Lag: The max_lag metric is a critical indicator of consumer health, showing the maximum delay between the producer writing a message and the consumer reading it.
- Fetch Performance: The fetch_rate provides visibility into how frequently the consumer is requesting new messages from the broker.

**Usage**

The Consumer dataset relies on [Jolokia](https://www.elastic.co/docs/reference/integrations/jolokia) to fetch JMX metrics. Refer to the link for more information about Jolokia.

Note that the Jolokia agent is required to be deployed along with the JVM application. This can be achieved by using the KAFKA_OPTS environment variable when starting the Kafka consumer application:

```
export KAFKA_OPTS=-javaagent:/opt/jolokia-jvm-1.5.0-agent.jar=port=8774,host=localhost
./bin/kafka-console-consumer.sh --topic=test --bootstrap-server=localhost:9091
```

Then it will be possible to collect the JMX metrics from localhost:8774.

{{event "consumer"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "consumer"}}

### producer

The `producer` dataset gathers metrics focused on the performance, efficiency, and health of Kafka producers. This data is crucial for understanding message production rates, identifying potential bottlenecks, and ensuring reliable data ingestion into Kafka topics.

This dataset includes metrics such as:
- Throughput and Rate Metrics: Fields like record_send_rate, out.bytes_per_sec, and request_rate measure the producer's output, providing a clear view of how much data is being sent per second.
- Batching Performance: Metrics such as batch_size_avg, batch_size_max, and records_per_request offer insights into the effectiveness of batching, which is key for optimizing producer efficiency.
- Health and Error Indicators: The record_error_rate and record_retry_rate are vital for monitoring the health of the producer, highlighting issues that could lead to data loss or delays.
- Resource Utilization: Metrics like available_buffer_bytes and io_wait help track resource usage and identify performance constraints related to memory or I/O.
- Data Characteristics: Fields such as record_size_avg and record_size_max provide information about the size of the records being sent.

**Usage**

The Producer dataset relies on [Jolokia](https://www.elastic.co/docs/reference/integrations/jolokia) to fetch JMX metrics. Refer to the link for more information about Jolokia.

Note that the Jolokia agent is required to be deployed along with the JVM application. This can be achieved by using the KAFKA_OPTS environment variable when starting the Kafka producer application:

```
export KAFKA_OPTS=-javaagent:/opt/jolokia-jvm-1.5.0-agent.jar=port=8775,host=localhost
./bin/kafka-console-producer.sh --topic test --broker-list localhost:9091
```

Then it will be possible to collect the JMX metrics from localhost:8775.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "producer"}}
