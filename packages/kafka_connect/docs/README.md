# Kafka Connect Integration

This integration collects metrics from Kafka Connect via the Jolokia JMX bridge.

## Compatibility

This integration has been tested with Kafka Connect version 2.8.x and 3.x, but should work with any version that exposes JMX metrics via Jolokia.

## Requirements

You need Elasticsearch to store and search your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Kafka Connect must be configured with the Jolokia JVM agent to expose JMX metrics over HTTP. Add the following to your Kafka Connect startup:

```
-javaagent:/path/to/jolokia-jvm-agent.jar=port=8778,host=0.0.0.0
```

## Metrics

### Worker

The `worker` data stream collects metrics related to the Kafka Connect worker, including connector and task counts, startup statistics, and rebalance information.

**ECS Field Reference**

Please refer to the following document for detailed information on ECS fields:
https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| kafka_connect.worker.connector_count | The number of connectors running on this worker | long | gauge |
| kafka_connect.worker.connector_startup_attempts_total | The total number of connector startups that this worker has attempted | long | counter |
| kafka_connect.worker.connector_startup_failure_total | The total number of connector starts that failed | long | counter |
| kafka_connect.worker.connector_startup_success_total | The total number of connector starts that succeeded | long | counter |
| kafka_connect.worker.connector_startup_failure_percentage | The average percentage of this worker's connectors starts that failed | double | gauge |
| kafka_connect.worker.task_count | The number of tasks running in this worker | long | gauge |
| kafka_connect.worker.task_startup_attempts_total | The total number of task startups that this worker has attempted | long | counter |
| kafka_connect.worker.task_startup_failure_total | The total number of task starts that failed | long | counter |
| kafka_connect.worker.task_startup_success_total | The total number of task starts that succeeded | long | counter |
| kafka_connect.worker.task_startup_success_percentage | The average percentage of this worker's tasks starts that succeeded | double | gauge |
| kafka_connect.worker.completed_rebalances_total | The total number of rebalances by this worker | long | counter |

### Connector

The `connector` data stream collects metrics related to individual connectors.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| kafka_connect.connector.status | The status of the connector | keyword |

### Task

The `task` data stream collects metrics related to connector tasks, including batch processing, offset commits, error handling, and sink/source task metrics.

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| kafka_connect.task.batch_size_avg | The average size of the batches processed by the connector | double | gauge |
| kafka_connect.task.batch_size_max | The maximum size of the batches processed by the connector | long | gauge |
| kafka_connect.task.offset_commit_avg_time_ms | The average time in milliseconds taken by this task to commit offsets | double | gauge |
| kafka_connect.task.offset_commit_failure_percentage | The average percentage of this task's offset commit attempts that failed | double | gauge |
| kafka_connect.task.offset_commit_max_time_ms | The maximum time in milliseconds taken by this task to commit offsets | double | gauge |
| kafka_connect.task.offset_commit_success_percentage | The average percentage of this task's offset commit attempts that succeeded | double | gauge |
| kafka_connect.task.pause_ratio | The fraction of time this task has spent in the pause state | double | gauge |
| kafka_connect.task.running_ratio | The fraction of time this task has spent in the running state | double | gauge |
| kafka_connect.task.status | The status of the connector task | keyword | - |
| kafka_connect.task.sink_record_read_total | Total number of records produced or polled by the task belonging to the named sink connector | long | counter |
| kafka_connect.task.sink_record_send_total | Total number of records output from the transformations and sent to the task belonging to the named sink connector | long | counter |
| kafka_connect.task.source_record_write_total | Number of records output from the transformations and written to Kafka for the task belonging to the named source connector | long | counter |
| kafka_connect.task.source_record_poll_total | Number of records produced or polled by the task belonging to the named source connector | long | counter |

### Client

The `client` data stream collects Kafka client metrics from the Kafka Connect worker, including connection, I/O, and request/response metrics.

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| kafka_connect.client.connection_close_rate | Connections closed per second in the window | double | gauge |
| kafka_connect.client.connection_count | Current number of active connections | long | gauge |
| kafka_connect.client.connection_creation_rate | New connections established per second in the window | double | gauge |
| kafka_connect.client.incoming_byte_rate | Bytes per second read off all sockets | double | gauge |
| kafka_connect.client.outgoing_byte_rate | Average number of outgoing bytes sent per second to all servers | double | gauge |
| kafka_connect.client.request_rate | Average number of requests sent per second | double | gauge |
| kafka_connect.client.response_rate | Responses received and sent per second | double | gauge |
| kafka_connect.client.network_io_rate | Average number of network operations on all connections per second | double | gauge |

## Configuration

Configure the Jolokia endpoint URL(s) for your Kafka Connect worker(s):

```yaml
hosts: 
  - "http://kafka-connect-01:8778"
  - "http://kafka-connect-02:8778"
path: "/jolokia/"
```

For HTTPS endpoints with custom certificates, configure SSL settings:

```yaml
ssl:
  verification_mode: full
  certificate_authorities: |
    -----BEGIN CERTIFICATE-----
    ...
    -----END CERTIFICATE-----
```

## Logs

This integration does not currently collect logs. It focuses on metrics collection via Jolokia.
