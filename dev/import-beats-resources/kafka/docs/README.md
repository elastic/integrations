# Kafka integration

This integration collects logs and metrics from [https://kafka.apache.org](Kafka) servers.

## Compatibility

The `log` dataset is tested with logs from Kafka 0.9, 1.1.0 and 2.0.0.

The `broker`, `consumergroup`, `partition` and `producer` metricsets are tested with Kafka 0.10.2.1, 1.1.0, 2.1.1, and 2.2.2.

The `broker` metricset requires Jolokia to fetch JMX metrics. Refer to the Metricbeat documentation about Jolokia for more information.

## Logs

### log

The `log` dataset collects and parses logs from Kafka servers.

{{fields "log"}}

## Metrics

### broker

The `broker` dataset collects JMX metrics from Kafka brokers using Jolokia.

{{event "broker"}}

{{fields "broker"}}

### consumergroup

{{event "consumergroup"}}

{{fields "consumergroup"}}

### partition

{{event "partition"}}

{{fields "partition"}}