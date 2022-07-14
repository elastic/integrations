# Elastic Package Registry

This integration collects metrics from Elastic Package Registry (EPR).
There is one data stream:

- metrics: Telemetry data from the /metrics API.

In order to enable this telemetry in your EPR instance, you must set the metrics
address parameter. Or, as an alternative, set the environment variable
`EPR_METRICS_ADDRESS`. As an example:

```bash
package-registry -metrics-address 0.0.0.0:9000

export EPR_METRICS_ADDRESS="0.0.0.0:9000" ; package-regsitry
```

Remember to expose the port used in the above setting (e.g. 9000) in your deployments
(k8s, docker-compose, etc.).

## Compatibility

This integration requires EPR >= 1.10.0.

## Metrics

Elastic Package Registry can provide Prometheus metrics in the `/metrics` endpoint.
You can verify that metrics endpoint is enabled by making an HTTP request to:
`http://localhost:9000/metrics` on your package registry instance.

There are two different data streams to split the different metrics available:

### Elastic Package Registry (EPR)

Metrics related to the Elastic Package Registry application itself:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| package_registry.epr_http_request_duration_seconds.histogram | A histogram of latencies for requests to the http server | histogram |
| package_registry.epr_http_request_duration_seconds.histogram.counts | Counters of the histogram of latencies for requests to the http server | long |
| package_registry.epr_http_request_duration_seconds.histogram.values | Bucket values of the histogram of latencies for requests to the http server | double |
| package_registry.epr_http_request_size_bytes.histogram | A histogram of sizes of requests to the http server | histogram |
| package_registry.epr_http_request_size_bytes.histogram.counts | Counters of the histogram of sizes of requests to the http server | histogram |
| package_registry.epr_http_request_size_bytes.histogram.values | Bucket values of the histogram of sizes of requests to the http server | histogram |
| package_registry.epr_http_requests_total.counter | Counter for requests to the http server | long |
| package_registry.epr_http_response_size_bytes.histogram | A histogram of response sizes for requests to the http server | histogram |
| package_registry.epr_http_response_size_bytes.histogram.counts | Counters fo the histogram of response sizes for requests to the http server | histogram |
| package_registry.epr_http_response_size_bytes.histogram.values | Bucket values of the the histogram of response sizes for requests to the http server | histogram |
| package_registry.epr_in_flight_requests.value | Requests currently being served by the http server | double |
| package_registry.epr_number_indexed_packages.value | Number of indexed packages | integer |
| package_registry.epr_service_info.value | Version information about Elastic Package Registry | short |
| package_registry.epr_storage_requests_total.counter | Counter for requests performed to the storage | long |
| package_registry.labels.code | HTTP Code | keyword |
| package_registry.labels.component | Component type of the storage (statics, artifacts, signature...) | keyword |
| package_registry.labels.instance | Elastic Package Registry instance | keyword |
| package_registry.labels.job |  | keyword |
| package_registry.labels.location | Storage location (remote or local) | keyword |
| package_registry.labels.method | HTTP method | keyword |
| package_registry.labels.path | Path of the HTTP request. | keyword |
| package_registry.labels.version | Elastic Package Registry version. | keyword |
| package_registry.process_cpu_seconds_total.counter | Total user and system CPU time spent in seconds | double |
| package_registry.process_max_fds.value | Maximum number of open file descriptors | double |
| package_registry.process_open_fds.value | Number of open file descriptors | double |
| package_registry.process_resident_memory_bytes.value | Resident memory size in bytes | double |
| package_registry.process_start_time_seconds.value | Start time of the process since unix epoch in seconds | double |
| package_registry.process_virtual_memory_bytes.value | Virtual memory size in bytes | double |
| package_registry.process_virtual_memory_max_bytes.value | Maximum amount of virtual memory available in bytes | double |
| package_registry.storage_indexer.get_duration_seconds.histogram | A histogram of latencies for get processes run by the indexer | histogram |
| package_registry.storage_indexer.get_duration_seconds.histogram.counts | Counters of the histogram of latencies for get processes run by the indexer | histogram |
| package_registry.storage_indexer.get_duration_seconds.histogram.values | Bucket values of the histogram of latencies for get processes run by the indexer | histogram |
| package_registry.storage_indexer.update_index_duration_seconds.histogram | A histogram of latencies for update index processes run by the indexer | histogram |
| package_registry.storage_indexer.update_index_duration_seconds.histogram.counts | Counters of the histogram of latencies for update index processes run by the indexer | histogram |
| package_registry.storage_indexer.update_index_duration_seconds.histogram.values | Bucket values of the histogram of latencies for update index processes run by the indexer | histogram |
| package_registry.storage_indexer.update_index_error_total.counter | A counter for all the update index processes that finished with error | long |
| package_registry.storage_indexer.update_index_success_total.counter | A counter for all the update index processes that finished with error | long |
| package_registry.up.value | Monitoring up metric | short |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| tags | List of keywords used to tag each event. | keyword |


### Go metrics

Metrics related to the Go processes:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| package_registry.go_gc_duration_seconds.value | a summary of the pause duration of garbage collection cycle | double |
| package_registry.go_gc_duration_seconds_count.counter | count of the pause duration of garbage collection cycle | double |
| package_registry.go_gc_duration_seconds_sum.counter | Sum of pause duration of garbage collection cycle | double |
| package_registry.go_goroutines.value | Number of goroutines that currently exist | long |
| package_registry.go_info.value | Information about the Go environment | short |
| package_registry.go_memstats_alloc_bytes.value | Number of bytes allocated and still in use | double |
| package_registry.go_memstats_alloc_bytes_total.counter | Total number of bytes allocated, even if freed | double |
| package_registry.go_memstats_buck_hash_sys_bytes.value | Number of bytes used by the profiling bucket hash table | double |
| package_registry.go_memstats_frees_total.counter | Total number of frees. | double |
| package_registry.go_memstats_gc_sys_bytes.value | Number of bytes used for garbage collection system metadata | double |
| package_registry.go_memstats_heap_alloc_bytes.value | Number of heap bytes allocated and still in use | double |
| package_registry.go_memstats_heap_idle_bytes.value | Number of heap bytes waiting to be used | double |
| package_registry.go_memstats_heap_inuse_bytes.value | Number of heap bytes that are in use | double |
| package_registry.go_memstats_heap_objects.value | Number of allocated objects | double |
| package_registry.go_memstats_heap_released_bytes.value | Number of heap bytes released to OS | double |
| package_registry.go_memstats_heap_sys_bytes.value | Number of heap bytes obtained from system | double |
| package_registry.go_memstats_last_gc_time_seconds.value | Number of seconds since 1970 of last garbage collection | double |
| package_registry.go_memstats_lookups_total.counter | Total number of pointer lookups | double |
| package_registry.go_memstats_mallocs_total.counter | Total number of mallocs | double |
| package_registry.go_memstats_mcache_inuse_bytes.value | Number of bytes in use by mcache structures | double |
| package_registry.go_memstats_mcache_sys_bytes.value | Number of bytes used for mcache structures obtained from system | double |
| package_registry.go_memstats_mspan_inuse_bytes.value | Number of bytes in use by mspan structures | double |
| package_registry.go_memstats_mspan_sys_bytes.value | Number of bytes used for mspan structures obtained from system | double |
| package_registry.go_memstats_next_gc_bytes.value | Number of heap bytes when next garbage collection will take place | double |
| package_registry.go_memstats_other_sys_bytes.value | Number of bytes used for other system allocations | double |
| package_registry.go_memstats_stack_inuse_bytes.value | Number of bytes in use by the stack allocator | double |
| package_registry.go_memstats_stack_sys_bytes.value | Number of bytes obtained from system for stack allocator | double |
| package_registry.go_memstats_sys_bytes.value | Number of bytes obtained from system | double |
| package_registry.go_threads.value | Number of OS threads created | long |
| package_registry.labels.instance |  | keyword |
| package_registry.labels.job |  | keyword |
| package_registry.labels.quantile |  | keyword |
| package_registry.labels.version |  | keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| tags | List of keywords used to tag each event. | keyword |


Example of event:
An example event for `gometrics` looks as following:

```json
{
    "@timestamp": "2022-07-13T16:28:18.795Z",
    "agent": {
        "ephemeral_id": "17583903-3feb-4f01-b64c-2a9613d50887",
        "id": "547ea925-6f6c-42ac-8de3-eea642fd06b3",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.3.2"
    },
    "data_stream": {
        "dataset": "elastic_package_registry.gometrics",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "547ea925-6f6c-42ac-8de3-eea642fd06b3",
        "snapshot": false,
        "version": "8.3.2"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "elastic_package_registry.gometrics",
        "duration": 2931901,
        "ingested": "2022-07-13T16:28:19Z",
        "module": "prometheus"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
        "ip": [
            "172.26.0.4"
        ],
        "mac": [
            "02:42:ac:1a:00:04"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.104-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.4 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "collector",
        "period": 10000
    },
    "package_registry": {
        "go_gc_duration_seconds": {
            "value": 0.008521534
        },
        "labels": {
            "instance": "elastic-package-service_elastic_package_registry_1:9110",
            "job": "prometheus",
            "quantile": "1"
        }
    },
    "service": {
        "address": "http://elastic-package-service_elastic_package_registry_1:9110/metrics",
        "type": "elastic_package_registry"
    }
}
```
