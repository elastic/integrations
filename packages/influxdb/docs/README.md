# Influxdb Integration

This integration is for ingesting task, storage, golang, performance related metrics from Influxdb OSS 2.x databases. This integration provides  out-of-the-box dashboards named Status Metrics, Advanced Status Metrics.


## Requirements

This integration depends on prometheus endpoint (default: `http://<influxdbhost>:<port>/metrics`) of Influxdb for collecting status and advanced status metrics. 


## Compatibility

This integration has been tested against Influxdb OSS 2.4, Influxdb OSS 2.0


## Metrics

### Status Metrics

Status metrics include details of memory usage, OS thread usage, query statistics, organization & users statistics, tasks & task workers, WAL size etc.


**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |  |
| host.ip | Host ip addresses. | ip |  |  |
| influxdb.status.go_memstats_alloc_bytes | Number of bytes allocated and still in use. | double | byte | gauge |
| influxdb.status.go_memstats_alloc_bytes_total | Total number of bytes allocated, even if freed. | double | byte | counter |
| influxdb.status.go_memstats_heap_alloc_bytes | Number of heap bytes allocated and still in use. | double | byte | gauge |
| influxdb.status.go_memstats_heap_idle_bytes | Number of heap bytes waiting to be used. | double | byte | gauge |
| influxdb.status.go_memstats_heap_inuse_bytes | Number of heap bytes that are in use. | double | byte | gauge |
| influxdb.status.go_threads | Number of OS threads created. | double |  | gauge |
| influxdb.status.http_api_requests_total | Number of http requests received | double |  | counter |
| influxdb.status.influxdb_buckets_total | Number of total buckets on the server. | double |  | counter |
| influxdb.status.influxdb_dashboards_total | Number of total dashboards on the server. | double |  | counter |
| influxdb.status.influxdb_organizations_total | Number of total organizations on the server. | double |  | counter |
| influxdb.status.influxdb_scrapers_total | Number of total scrapers on the server. | double |  | counter |
| influxdb.status.influxdb_tokens_total | Number of total tokens on the server. | double |  | counter |
| influxdb.status.influxdb_uptime_seconds | influxdb process uptime in seconds. | double | s | gauge |
| influxdb.status.influxdb_users_total | Number of total users on the server. | double |  | counter |
| influxdb.status.instance | Influxdb instance. | keyword |  |  |
| influxdb.status.labels.bucket | Bucket id of the bucket where time series data is stored. | keyword |  |  |
| influxdb.status.labels.instance | Influxdb database instance. | keyword |  |  |
| influxdb.status.labels.method | HTTP request method. | keyword |  |  |
| influxdb.status.labels.org | Organization id of the Organization created in Influxdb. | keyword |  |  |
| influxdb.status.labels.path | HTTP request endpoint. | keyword |  |  |
| influxdb.status.labels.response_code | Response code of HTTP API request. | keyword |  |  |
| influxdb.status.labels.status | HTTP API request call status. | keyword |  |  |
| influxdb.status.labels.user_agent | HTTP API request call user agent. | keyword |  |  |
| influxdb.status.labels.walPath | Directory path where InfluxDB stores Write Ahead Log. | keyword |  |  |
| influxdb.status.qc_all_active | Number of queries in all states. | double |  | gauge |
| influxdb.status.qc_compiling_active | Number of queries actively compiling. | double |  | gauge |
| influxdb.status.qc_executing_active | Number of queries actively executing. | double |  | gauge |
| influxdb.status.storage_bucket_measurement_num | Gauge of measurement cardinality per bucket. | double |  | gauge |
| influxdb.status.storage_bucket_series_num | Gauge of series cardinality per bucket. | double |  | gauge |
| influxdb.status.storage_compactions_failed | Counter of TSM compactions by level that have failed due to error. | double |  | counter |
| influxdb.status.storage_shard_disk_size | Gauge of the disk size for the shard. | double |  | gauge |
| influxdb.status.storage_shard_write_count | Count of the number of write requests. | double |  | counter |
| influxdb.status.storage_shard_write_dropped_sum | Counter of the number of points dropped. | double |  | counter |
| influxdb.status.storage_shard_write_err_count | Count of the number of write requests with errors. | double |  | counter |
| influxdb.status.storage_tsm_files_disk_bytes | Gauge of data size in bytes for each shard. | double |  | gauge |
| influxdb.status.storage_tsm_files_total | Gauge of number of files per shard | double |  | gauge |
| influxdb.status.storage_wal_size | Gauge of size of WAL in bytes. | double | byte | gauge |
| influxdb.status.storage_wal_writes | Number of write attempts to the WAL. | double |  | counter |
| influxdb.status.storage_wal_writes_err | Number of failed write attempts to the WAL. | double |  | counter |
| influxdb.status.storage_writer_timeouts | Number of shard write request timeouts. | double |  | counter |
| influxdb.status.task_executor_errors_counter | The number of errors thrown by the executor with the type of error. Example - Invalid, Internal, etc. | double |  | counter |
| influxdb.status.task_executor_total_runs_active | Total number of workers currently running tasks. | double |  | gauge |
| influxdb.status.task_executor_total_runs_complete | Total number of runs completed across all tasks, split out by success or failure. | double |  | counter |
| influxdb.status.task_executor_workers_busy | Percent of total available workers that are currently busy. | double | percent | gauge |
| influxdb.status.task_scheduler_current_execution | Number of tasks currently being executed. | double |  | gauge |
| influxdb.status.task_scheduler_total_execute_failure | Total number of times an execution has failed. | double |  | counter |
| influxdb.status.task_scheduler_total_execution_calls | Total number of executions across all tasks. | double |  | counter |
| influxdb.status.task_scheduler_total_release_calls | Total number of release requests. | double |  | counter |
| influxdb.status.task_scheduler_total_schedule_calls | Total number of schedule requests. | double |  | counter |
| influxdb.status.task_scheduler_total_schedule_fails | Total number of schedule requests that fail to schedule. | double |  | counter |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |  |


An example event for `status` looks as following:

```json
{
    "influxdb": {
        "status": {
            "go_memstats_alloc_bytes_total": 1294112696,
            "instance": "localhost:8086",
            "task_scheduler_total_release_calls": 0,
            "go_memstats_alloc_bytes": 192188632,
            "influxdb_organizations_total": 1,
            "go_memstats_heap_idle_bytes": 34217984,
            "task_executor_workers_busy": 0,
            "task_executor_total_runs_active": 0,
            "influxdb_scrapers_total": 1,
            "influxdb_dashboards_total": 2,
            "task_scheduler_current_execution": 128,
            "go_threads": 17,
            "go_memstats_heap_inuse_bytes": 194961408,
            "task_scheduler_total_execution_calls": 7,
            "task_scheduler_total_schedule_fails": 0,
            "go_memstats_heap_alloc_bytes": 192188632,
            "influxdb_buckets_total": 3,
            "task_scheduler_total_execute_failure": 0,
            "influxdb_tokens_total": 6,
            "influxdb_users_total": 1
        }
    },
    "@timestamp": "2022-09-13T16:31:54.818Z",
    "ecs": {
        "version": "8.0.0"
    },
    "service": {
        "address": "http://localhost:8086/metrics",
        "type": "prometheus"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "influxdb.status"
    },
    "event": {
        "duration": 21381974,
        "agent_id_status": "verified",
        "ingested": "2022-09-13T16:31:55Z",
        "module": "prometheus",
        "dataset": "influxdb.status"
    }
}
```

### Advanced Status Metrics

Advanced status metric include details of query execution statistics, compaction levels, retention details, errors & partial writes, latency etc.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| host.ip | Host ip addresses. | ip |
| influxdb.advstatus.instance | Influxdb instance. | keyword |
| influxdb.advstatus.qc_all_duration_seconds.histogram | Histogram of total times spent in all query states. | histogram |
| influxdb.advstatus.qc_compiling_duration_seconds.histogram | Histogram of times spent compiling queries. | histogram |
| influxdb.advstatus.qc_executing_duration_seconds.histogram | Histogram of times spent executing queries. | histogram |
| influxdb.advstatus.storage_compactions_duration_seconds.histogram | Histogram of compactions by level since startup. | histogram |
| influxdb.advstatus.storage_retention_check_duration.histogram | Histogram of duration of retention check in seconds. | histogram |
| influxdb.advstatus.storage_writer_dropped_points.histogram | Histogram of number of points dropped due to partial writes. | histogram |
| influxdb.advstatus.storage_writer_err_points.histogram | Histogram of number of points in errored shard write requests. | histogram |
| influxdb.advstatus.storage_writer_ok_points.histogram | Histogram of number of points in successful shard write requests. | histogram |
| influxdb.advstatus.storage_writer_req_points.histogram | Histogram of number of points requested to be written. | histogram |
| influxdb.advstatus.task_executor_run_latency_seconds.histogram | Records the latency between the time the run was due to run and the time the task started execution, by task type. | histogram |
| influxdb.advstatus.task_executor_run_queue_delta.histogram | The duration in seconds between a run being due to start and actually starting. | histogram |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |


An example event for `advstatus` looks as following:

```json
{
    "influxdb": {
        "advstatus": {
            "task_executor_run_queue_delta_sum": {
                "rate": 0.004829314000000001,
                "counter": 0.036326417
            },
            "instance": "localhost:8086",
            "task_executor_run_queue_delta_count": {
                "rate": 1,
                "counter": 7
            },
            "labels": {
                "taskID": "09ef18921382f000"
            }
        }
    },
    "@timestamp": "2022-09-13T16:31:54.818Z",
    "ecs": {
        "version": "8.0.0"
    },
    "service": {
        "address": "http://localhost:8086/metrics",
        "type": "prometheus"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "influxdb.advstatus"
    },
    "event": {
        "duration": 21381974,
        "agent_id_status": "verified",
        "ingested": "2022-09-13T16:31:55Z",
        "module": "prometheus",
        "dataset": "influxdb.status"
    }
}
```

