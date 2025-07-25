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
- Current epoch, leader, and vote information 
- High watermark and log offset metrics
- Node state and voter information
- Poll idle ratio

{{event "raft"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "raft"}}