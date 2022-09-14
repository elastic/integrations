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
    "@timestamp": "2022-09-14T06:28:12.039Z",
    "agent": {
        "ephemeral_id": "fcb44fde-0dbd-47ef-80ce-d5b2c216b24b",
        "id": "f995507b-788c-45db-8f98-5d0ca02b81fc",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.4.0"
    },
    "cloud": {
        "account": {
            "id": "elastic-obs-integrations-dev"
        },
        "availability_zone": "asia-south1-c",
        "instance": {
            "id": "3010911784348669868",
            "name": "service-integration-dev-idc-01"
        },
        "machine": {
            "type": "n1-standard-8"
        },
        "project": {
            "id": "elastic-obs-integrations-dev"
        },
        "provider": "gcp",
        "service": {
            "name": "GCE"
        }
    },
    "data_stream": {
        "dataset": "influxdb.status",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "f995507b-788c-45db-8f98-5d0ca02b81fc",
        "snapshot": true,
        "version": "8.4.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "influxdb.status",
        "duration": 8872965,
        "ingested": "2022-09-14T06:28:13Z",
        "module": "prometheus"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "172.25.0.7"
        ],
        "mac": [
            "02:42:ac:19:00:07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.4.0-1078-gcp",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.4 LTS (Focal Fossa)"
        }
    },
    "influxdb": {
        "status": {
            "influxdb_uptime_seconds": 31.499834078,
            "instance": "elastic-package-service_influxdb_1:8086"
        }
    },
    "metricset": {
        "name": "collector",
        "period": 60000
    },
    "prometheus": {
        "labels": {}
    },
    "service": {
        "address": "http://elastic-package-service_influxdb_1:8086/metrics",
        "type": "prometheus"
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
    "@timestamp": "2022-09-14T06:27:04.338Z",
    "agent": {
        "ephemeral_id": "ddec09d3-8ec5-4114-9887-23c481c7ced3",
        "id": "f995507b-788c-45db-8f98-5d0ca02b81fc",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.4.0"
    },
    "cloud": {
        "account": {
            "id": "elastic-obs-integrations-dev"
        },
        "availability_zone": "asia-south1-c",
        "instance": {
            "id": "3010911784348669868",
            "name": "service-integration-dev-idc-01"
        },
        "machine": {
            "type": "n1-standard-8"
        },
        "project": {
            "id": "elastic-obs-integrations-dev"
        },
        "provider": "gcp",
        "service": {
            "name": "GCE"
        }
    },
    "data_stream": {
        "dataset": "influxdb.advstatus",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "f995507b-788c-45db-8f98-5d0ca02b81fc",
        "snapshot": true,
        "version": "8.4.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "influxdb.advstatus",
        "duration": 6433830,
        "ingested": "2022-09-14T06:27:05Z",
        "module": "prometheus"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "172.25.0.7"
        ],
        "mac": [
            "02:42:ac:19:00:07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.4.0-1078-gcp",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.4 LTS (Focal Fossa)"
        }
    },
    "influxdb": {
        "advstatus": {
            "instance": "elastic-package-service_influxdb_1:8086",
            "labels": {},
            "storage_retention_check_duration": {
                "histogram": {
                    "counts": [
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0
                    ],
                    "values": [
                        0.0025,
                        0.0075,
                        0.0175,
                        0.037500000000000006,
                        0.07500000000000001,
                        0.175,
                        0.375,
                        0.75,
                        1.75,
                        3.75,
                        7.5,
                        15
                    ]
                }
            }
        }
    },
    "metricset": {
        "name": "collector",
        "period": 60000
    },
    "service": {
        "address": "http://elastic-package-service_influxdb_1:8086/metrics",
        "type": "prometheus"
    }
}
```


