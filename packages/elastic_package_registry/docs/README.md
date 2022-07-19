# Elastic Package Registry

This integration collects metrics from [Elastic Package Registry](https://github.com/elastic/package-registry).
There is one data stream:

- metrics: Telemetry data from the /metrics API.

In order to enable this telemetry in your Elastic Package Registry instance, you must set the metrics
address parameter. Or, as an alternative, set the environment variable
`EPR_METRICS_ADDRESS`. As an example:

```bash
package-registry -metrics-address 0.0.0.0:9000

EPR_METRICS_ADDRESS="0.0.0.0:9000" package-regsitry
```

Remember to expose the port used in the above setting (e.g. 9000) in your deployments:
k8s, docker-compose, etc..

## Compatibility

This integration requires Elastic Package Registry version >= 1.10.0.

## Metrics

Elastic Package Registry can provide Prometheus metrics in the `/metrics` endpoint.
You can verify that metrics endpoint is enabled by making an HTTP request to
`http://localhost:9000/metrics` on your package registry instance.


### Elastic Package Registry metrics

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |  |
| error.message | Error message. | match_only_text |  |  |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |  |  |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |  |  |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |  |  |
| package_registry.http.request_duration_seconds.histogram | A histogram of latencies for requests to the http server | histogram |  |  |
| package_registry.http.request_duration_seconds.histogram.counts | Counters of the histogram of latencies for requests to the http server | long |  |  |
| package_registry.http.request_duration_seconds.histogram.values | Bucket values of the histogram of latencies for requests to the http server | double |  |  |
| package_registry.http.request_size_bytes.histogram | A histogram of sizes of requests to the http server | histogram |  |  |
| package_registry.http.request_size_bytes.histogram.counts | Counters of the histogram of sizes of requests to the http server | histogram |  |  |
| package_registry.http.request_size_bytes.histogram.values | Bucket values of the histogram of sizes of requests to the http server | histogram |  |  |
| package_registry.http.response_size_bytes.histogram | A histogram of response sizes for requests to the http server | histogram |  |  |
| package_registry.http.response_size_bytes.histogram.counts | Counters fo the histogram of response sizes for requests to the http server | histogram |  |  |
| package_registry.http.response_size_bytes.histogram.values | Bucket values of the the histogram of response sizes for requests to the http server | histogram |  |  |
| package_registry.http_requests_total.counter | Counter for requests to the http server | double |  | counter |
| package_registry.in_flight_requests | Requests currently being served by the http server | double |  | gauge |
| package_registry.labels.code | HTTP Code | keyword |  |  |
| package_registry.labels.component | Component type of the storage (statics, artifacts, signature...) | keyword |  |  |
| package_registry.labels.instance | Elastic Package Registry instance | keyword |  |  |
| package_registry.labels.job |  | keyword |  |  |
| package_registry.labels.location | Storage location (remote or local) | keyword |  |  |
| package_registry.labels.method | HTTP method | keyword |  |  |
| package_registry.labels.path | Path of the HTTP request. | keyword |  |  |
| package_registry.labels.version | Elastic Package Registry version. | keyword |  |  |
| package_registry.number_indexed_packages | Number of indexed packages | integer |  | gauge |
| package_registry.start_time_seconds | Start time of the process since unix epoch in seconds | double | s | gauge |
| package_registry.storage_indexer.get_duration_seconds.histogram | A histogram of latencies for get processes run by the indexer | histogram |  |  |
| package_registry.storage_indexer.get_duration_seconds.histogram.counts | Counters of the histogram of latencies for get processes run by the indexer | histogram |  |  |
| package_registry.storage_indexer.get_duration_seconds.histogram.values | Bucket values of the histogram of latencies for get processes run by the indexer | histogram |  |  |
| package_registry.storage_indexer.update_index_duration_seconds.histogram | A histogram of latencies for update index processes run by the indexer | histogram |  |  |
| package_registry.storage_indexer.update_index_duration_seconds.histogram.counts | Counters of the histogram of latencies for update index processes run by the indexer | histogram |  |  |
| package_registry.storage_indexer.update_index_duration_seconds.histogram.values | Bucket values of the histogram of latencies for update index processes run by the indexer | histogram |  |  |
| package_registry.storage_indexer.update_index_error_total.counter | A counter for all the update index processes that finished with error | long |  |  |
| package_registry.storage_indexer.update_index_success_total.counter | A counter for all the update index processes that finished with error | long |  |  |
| package_registry.storage_requests_total.counter | Counter for requests performed to the storage | long |  | counter |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |  |
| tags | List of keywords used to tag each event. | keyword |  |  |


An example event for `metrics` looks as following:

```json
{
    "@timestamp": "2022-07-19T15:38:36.605Z",
    "agent": {
        "ephemeral_id": "6ddaaa99-8a54-435d-a36a-cee8bad84f01",
        "id": "0bb271e0-9540-4c53-b44b-a197503085ad",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.3.2"
    },
    "data_stream": {
        "dataset": "elastic_package_registry.metrics",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "0bb271e0-9540-4c53-b44b-a197503085ad",
        "snapshot": false,
        "version": "8.3.2"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "elastic_package_registry.metrics",
        "duration": 2813144,
        "ingested": "2022-07-19T15:38:37Z",
        "kind": "metric",
        "module": "prometheus"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
        "ip": [
            "192.168.224.4"
        ],
        "mac": [
            "02:42:c0:a8:e0:04"
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
        "period": 30000
    },
    "package_registry": {
        "epr_in_flight_requests": {
            "value": 0
        },
        "epr_number_indexed_packages": {
            "value": 1434
        },
        "labels": {
            "instance": "elastic-package-service_elastic_package_registry_1:9110",
            "job": "prometheus"
        },
        "process_cpu_seconds_total": {
            "counter": 7.62
        },
        "process_max_fds": {
            "value": 1048576
        },
        "process_open_fds": {
            "value": 10
        },
        "process_resident_memory_bytes": {
            "value": 100343808
        },
        "process_start_time_seconds": {
            "value": 1658245088.52
        },
        "process_virtual_memory_bytes": {
            "value": 1419386880
        },
        "process_virtual_memory_max_bytes": {
            "value": 18446744073709552000
        },
        "storage_indexer": {
            "get_duration_seconds": {
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
            },
            "update_index_duration_seconds": {
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
            },
            "update_index_error_total": {
                "counter": 0
            },
            "update_index_success_total": {
                "counter": 0
            }
        }
    },
    "service": {
        "address": "http://elastic-package-service_elastic_package_registry_1:9110/metrics",
        "type": "elastic_package_registry"
    }
}
```
