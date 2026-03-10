# Kafka Connect Integration

This integration collects metrics from Kafka Connect using the Jolokia JMX bridge.

## Compatibility

This integration has been tested with Kafka Connect version 2.8.x and 3.x, but should work with any version that exposes JMX metrics using Jolokia.

## Requirements

You need Elasticsearch to store and search your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Kafka Connect must be configured with the Jolokia JVM agent to expose JMX metrics over HTTP. Add the following to your Kafka Connect startup:

```
-javaagent:/path/to/jolokia-jvm-agent.jar=port=8778,host=0.0.0.0
```

## Metrics

### Worker

The `worker` data stream collects metrics related to the Kafka Connect worker, including connector and task counts, startup statistics, and rebalance information. These metrics are collected from the `kafka.connect:type=connect-worker-metrics` and `kafka.connect:type=connect-worker-rebalance-metrics` MBeans.

**ECS Field Reference**

Refer to the following document for detailed information on ECS fields:
https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html

**Exported fields**

| Field                                                     | Description                                                           | Type    | Metric Type |
| --------------------------------------------------------- | --------------------------------------------------------------------- | ------- | ----------- |
| kafka_connect.worker.address                              | The address of the Kafka Connect worker                               | keyword | -           |
| kafka_connect.worker.connector_count                      | The number of connectors running on this worker                       | long    | gauge       |
| kafka_connect.worker.connector_startup_attempts_total     | The total number of connector startups that this worker has attempted | long    | counter     |
| kafka_connect.worker.connector_startup_failure_total      | The total number of connector starts that failed                      | long    | counter     |
| kafka_connect.worker.connector_startup_success_total      | The total number of connector starts that succeeded                   | long    | counter     |
| kafka_connect.worker.connector_startup_failure_percentage | The average percentage of this worker's connectors starts that failed | double  | gauge       |
| kafka_connect.worker.task_count                           | The number of tasks running in this worker                            | long    | gauge       |
| kafka_connect.worker.task_startup_attempts_total          | The total number of task startups that this worker has attempted      | long    | counter     |
| kafka_connect.worker.task_startup_failure_total           | The total number of task starts that failed                           | long    | counter     |
| kafka_connect.worker.task_startup_success_total           | The total number of task starts that succeeded                        | long    | counter     |
| kafka_connect.worker.task_startup_success_percentage      | The average percentage of this worker's tasks starts that succeeded   | double  | gauge       |
| kafka_connect.worker.completed_rebalances_total           | The total number of rebalances completed by this worker               | long    | counter     |

### Connector

The `connector` data stream collects metrics related to individual connectors. These metrics are collected from the `kafka.connect:connector=*,type=connector-metrics` MBean.

**Exported fields**

| Field                           | Description                                                    | Type    |
| ------------------------------- | -------------------------------------------------------------- | ------- |
| kafka_connect.connector.name    | The name of the connector                                      | keyword |
| kafka_connect.connector.class   | The fully qualified class name of the connector implementation | keyword |
| kafka_connect.connector.type    | The type of the connector                                      | keyword |
| kafka_connect.connector.version | The version of the connector                                   | keyword |
| kafka_connect.connector.status  | The status of the connector (for example: running, paused, failed)    | keyword |

### Task

The `task` data stream collects metrics related to connector tasks, including batch processing, offset commits, error handling, and sink/source task metrics. These metrics are collected from the following MBeans:

- `kafka.connect:connector=*,task=*,type=connector-task-metrics`
- `kafka.connect:connector=*,task=*,type=sink-task-metrics`
- `kafka.connect:connector=*,task=*,type=source-task-metrics`
- `kafka.connect:connector=*,task=*,type=task-error-metrics`

**Exported fields**

| Field                                               | Description                                                                                                                                                                                    | Type    | Metric Type |
| --------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- | ----------- |
| kafka_connect.task.id                               | The task identifier                                                                                                                                                                            | keyword | -           |
| kafka_connect.task.batch_size_avg                   | The average size of the batches processed by the connector                                                                                                                                     | double  | gauge       |
| kafka_connect.task.batch_size_max                   | The maximum size of the batches processed by the connector                                                                                                                                     | long    | gauge       |
| kafka_connect.task.offset_commit_avg_time_ms        | The average time in milliseconds taken by this task to commit offsets                                                                                                                          | double  | gauge       |
| kafka_connect.task.offset_commit_failure_percentage | The average percentage of this task's offset commit attempts that failed                                                                                                                       | double  | gauge       |
| kafka_connect.task.offset_commit_max_time_ms        | The maximum time in milliseconds taken by this task to commit offsets                                                                                                                          | double  | gauge       |
| kafka_connect.task.offset_commit_success_percentage | The average percentage of this task's offset commit attempts that succeeded                                                                                                                    | double  | gauge       |
| kafka_connect.task.pause_ratio                      | The fraction of time this task has spent in the pause state                                                                                                                                    | double  | gauge       |
| kafka_connect.task.running_ratio                    | The fraction of time this task has spent in the running state                                                                                                                                  | double  | gauge       |
| kafka_connect.task.status                           | The status of the connector task. One of 'unassigned', 'running', 'paused', 'failed', or 'restarting'                                                                                          | keyword | -           |
| kafka_connect.task.sink_record_read_total           | Before transformations are applied, this is the total number of records produced or polled by the task belonging to the named sink connector in the worker (since the task was last restarted) | long    | counter     |
| kafka_connect.task.sink_record_send_total           | Total number of records output from the transformations and sent to the task belonging to the named sink connector in the worker (since the task was last restarted)                           | long    | counter     |
| kafka_connect.task.source_record_write_total        | Number of records output from the transformations and written to Kafka for the task belonging to the named source connector in the worker (since the task was last restarted)                  | long    | counter     |
| kafka_connect.task.source_record_poll_total         | Before transformations are applied, this is the number of records produced or polled by the task belonging to the named source connector in the worker (since the task was last restarted)     | long    | counter     |
| kafka_connect.task.deadletterqueue_produce_failures | The number of failed writes to the dead letter queue                                                                                                                                           | long    | counter     |
| kafka_connect.task.deadletterqueue_produce_requests | The number of attempted writes to the dead letter queue                                                                                                                                        | long    | counter     |
| kafka_connect.task.last_error_timestamp             | The epoch timestamp when this task last encountered an error                                                                                                                                   | long    | gauge       |
| kafka_connect.task.total_errors_logged              | The number of errors that were logged                                                                                                                                                          | long    | counter     |
| kafka_connect.task.total_record_errors              | The number of record processing errors in this task                                                                                                                                            | long    | counter     |
| kafka_connect.task.total_record_failures            | The number of record processing failures in this task                                                                                                                                          | long    | counter     |
| kafka_connect.task.total_records_skipped            | The number of records skipped due to errors                                                                                                                                                    | long    | counter     |
| kafka_connect.task.total_retries                    | The number of operations retried                                                                                                                                                               | long    | counter     |

### Client

The `client` data stream collects Kafka client metrics from the Kafka Connect worker, including connection, I/O, and request/response metrics. These metrics are collected from the `kafka.connect:type=connect-metrics,client-id=*` MBean.

**Exported fields**

| Field                                               | Description                                                                                               | Type    | Metric Type |
| --------------------------------------------------- | --------------------------------------------------------------------------------------------------------- | ------- | ----------- |
| kafka_connect.client.id                             | The client identifier                                                                                     | keyword | -           |
| kafka_connect.client.connection_close_rate          | Connections closed per second in the window                                                               | double  | gauge       |
| kafka_connect.client.connection_count               | Current number of active connections                                                                      | long    | gauge       |
| kafka_connect.client.connection_creation_rate       | New connections established per second in the window                                                      | double  | gauge       |
| kafka_connect.client.failed_authentication_rate     | Connections that failed authentication per second                                                         | double  | gauge       |
| kafka_connect.client.incoming_byte_rate             | Bytes per second read off all sockets                                                                     | double  | gauge       |
| kafka_connect.client.incoming_byte_total            | Total bytes read off all sockets                                                                          | long    | counter     |
| kafka_connect.client.io_ratio                       | Fraction of time the I/O thread spent doing I/O                                                           | double  | gauge       |
| kafka_connect.client.io_time_ns_avg                 | Average length of time for I/O per select call in nanoseconds                                             | double  | gauge       |
| kafka_connect.client.io_wait_ratio                  | Fraction of time the I/O thread spent waiting                                                             | double  | gauge       |
| kafka_connect.client.io_wait_time_ns_avg            | Average length of time the I/O thread spent waiting for a socket ready for reads or writes in nanoseconds | double  | gauge       |
| kafka_connect.client.network_io_rate                | Average number of network operations (reads or writes) on all connections per second                      | double  | gauge       |
| kafka_connect.client.outgoing_byte_rate             | Average number of outgoing bytes sent per second to all servers                                           | double  | gauge       |
| kafka_connect.client.outgoing_byte_total            | The total number of outgoing bytes sent to all servers                                                    | long    | counter     |
| kafka_connect.client.request_rate                   | Average number of requests sent per second                                                                | double  | gauge       |
| kafka_connect.client.request_size_avg               | Average size of all requests in the window                                                                | double  | gauge       |
| kafka_connect.client.request_size_max               | Maximum size of any request sent in the window                                                            | long    | gauge       |
| kafka_connect.client.request_total                  | The total number of requests sent                                                                         | long    | counter     |
| kafka_connect.client.response_rate                  | Responses received per second                                                                             | double  | gauge       |
| kafka_connect.client.response_total                 | Total responses received                                                                                  | long    | counter     |
| kafka_connect.client.select_rate                    | Number of times the I/O layer checked for new I/O to perform per second                                   | double  | gauge       |
| kafka_connect.client.successful_authentication_rate | Connections that were successfully authenticated using SASL or SSL per second                             | double  | gauge       |

## Logs

This integration does not currently collect logs. It focuses on metrics collection using Jolokia.
