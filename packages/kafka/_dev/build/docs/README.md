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

### jvm

The `jvm` dataset collects JVM metrics from Kafka brokers using Jolokia. This includes information about buffer pools, class loading, compilation, garbage collection, memory usage, memory pools, runtime, and threading.

{{event "jvm"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "jvm"}}

### network

The `network` dataset collects network metrics from Kafka brokers using Jolokia. This includes information about network acceptors, processors, request channels, request metrics, and socket servers.

{{event "network"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "network"}}

### logmanager

The `logmanager` dataset collects log management metrics from Kafka brokers using Jolokia. This includes information about log segments, log cleaners, log cleaner managers, log flush statistics, and log managers.

{{event "logmanager"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "logmanager"}}

### replicamanager

The `replicamanager` dataset collects replica management metrics from Kafka brokers using Jolokia. This includes information about ISR (In-Sync Replicas), partition counts, leader replicas, offline replicas, and reassignment operations.

{{event "replicamanager"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "replicamanager"}}