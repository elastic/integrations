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

### Elastic Package Registry (EPR)

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
| package_registry.\*.\* | Package Registry telemetry data from the Prometheus endpoint. |  |
| package_registry.epr_http_request_duration_seconds.histogram | A histogram of latencies for requests to the http server | object |
| package_registry.epr_http_request_size_bytes.histogram | A histogram of sizes of requests to the http server | object |
| package_registry.epr_http_requests_total.\* | Counter for requests to the http server | object |
| package_registry.epr_http_response_size_bytes.histogram | A histogram of response sizes for requests to the http server | object |
| package_registry.epr_in_flight_requests.value | Requests currently being served by the http server | object |
| package_registry.epr_number_indexed_packages.value | Number of indexed packages | object |
| package_registry.epr_service_info.value | Version information about Elastic Package Registry | object |
| package_registry.epr_storage_indexer_get_duration_seconds.histogram | A histogram of latencies for get processes run by the indexer | object |
| package_registry.epr_storage_indexer_update_index_duration_seconds.histogram | A histogram of latencies for update index processes run by the indexer | object |
| package_registry.epr_storage_indexer_update_index_error_total.\* | A counter for all the update index processes that finished with error | object |
| package_registry.epr_storage_indexer_update_index_success_total.\* | A counter for all the update index processes that finished with error | object |
| package_registry.labels.code | HTTP Code | keyword |
| package_registry.labels.component | Component type of the storage (statics, artifacts, signature...) | keyword |
| package_registry.labels.instance | Elastic Package Registry instance | keyword |
| package_registry.labels.job |  | keyword |
| package_registry.labels.location | Storage location (remote or local) | keyword |
| package_registry.labels.method | HTTP method | keyword |
| package_registry.labels.path | Path of the HTTP request. | keyword |
| package_registry.process_cpu_seconds_total.\* | Total user and system CPU time spent in seconds | object |
| package_registry.process_max_fds.value | Maximum number of open file descriptors | object |
| package_registry.process_open_fds.value | Number of open file descriptors | object |
| package_registry.process_resident_memory_bytes.value | Resident memory size in bytes | object |
| package_registry.process_start_time_seconds.value | Start time of the process since unix epoch in seconds | object |
| package_registry.process_virtual_memorty_bytes.value | Virtual memory size in bytes | object |
| package_registry.process_virtual_memorty_max_bytes.value | Maximum amount of virtual memory available in bytes | object |
| package_registry.storage_requests_total.\* | Counter for requests performed to the storage | object |
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
| package_registry.\*.\* | Package Registry telemetry data from the Prometheus endpoint. |  |
| package_registry.go_gc_duration_seconds.value | A summary of the pause duration of garbage collection cycle | object |
| package_registry.go_gc_duration_seconds_count.\* | Count of the pause duration of garbage collection cycle | object |
| package_registry.go_gc_duration_seconds_sum.\* | Sum of pause duration of garbage collection cycle | object |
| package_registry.go_goroutines.value | Number of goroutines that currently exist | object |
| package_registry.go_info.value | Information about the Go environment | object |
| package_registry.go_memstats_alloc_bytes.value | Number of bytes allocated and still in use | object |
| package_registry.go_memstats_alloc_bytes_total.counter | Total number of bytes allocated, even if freed | object |
| package_registry.go_memstats_alloc_bytes_total.rate | Rate of the total number of bytes allocated, even if freed | object |
| package_registry.go_memstats_buck_hash_sys_bytes.value | Number of bytes used by the profiling bucket hash table | object |
| package_registry.go_memstats_frees_total.\* | Total number of frees. | object |
| package_registry.go_memstats_gc_sys_bytes.value | Number of bytes used for garbage collection system metadata | object |
| package_registry.go_memstats_heap_alloc_bytes.value | Number of heap bytes allocated and still in use | object |
| package_registry.go_memstats_heap_idle_bytes.value | Number of heap bytes waiting to be used | object |
| package_registry.go_memstats_heap_inuse_bytes.value | Number of heap bytes that are in use | object |
| package_registry.go_memstats_heap_objects.value | Number of allocated objects | object |
| package_registry.go_memstats_heap_released_bytes.value | Number of heap bytes released to OS | object |
| package_registry.go_memstats_heap_sys_bytes.value | Number of heap bytes obtained from system | object |
| package_registry.go_memstats_last_gc_time_seconds.value | Number of seconds since 1970 of last garbage collection | object |
| package_registry.go_memstats_lookups_total.value | Total number of pointer lookups | object |
| package_registry.go_memstats_mallocs_total.value | Total number of mallocs | object |
| package_registry.go_memstats_mcache_inuse_bytes.value | Number of bytes in use by mcache structures | object |
| package_registry.go_memstats_mcache_sys_bytes.value | Number of bytes used for mcache structures obtained from system | object |
| package_registry.go_memstats_mspan_inuse_bytes.value | Number of bytes in use by mspan structures | object |
| package_registry.go_memstats_mspan_sys_bytes.value | Number of bytes used for mspan structures obtained from system | object |
| package_registry.go_memstats_next_gc_bytes.value | Number of heap bytes when next garbage collection will take place | object |
| package_registry.go_memstats_other_sys_bytes.value | Number of bytes used for other system allocations | object |
| package_registry.go_memstats_stack_inuse_bytes.value | Number of bytes in use by the stack allocator | object |
| package_registry.go_memstats_stack_sys_bytes.value | Number of bytes obtained from system for stack allocator | object |
| package_registry.go_memstats_sys_bytes.value | Number of bytes obtained from system | object |
| package_registry.go_threads.value | Number of OS threads created | object |
| package_registry.labels.instance |  | keyword |
| package_registry.labels.job |  | keyword |
| package_registry.labels.quantile |  | keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| tags | List of keywords used to tag each event. | keyword |

