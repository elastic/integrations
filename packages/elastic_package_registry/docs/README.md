# Elastic Package Registry

This Elastic Package Registry integration collects metrics from your [Elastic Package Registry](https://github.com/elastic/package-registry) service.

For example, you could use the data from this integration to know the status of your services. For instance, how many packages are indexed, what version
are running your services, or if there are too many requests with 404 or 500 code status.

## Data streams

The Elastic Package Registry collects one type of data stream: metrics.

- metrics: Telemetry data from the `/metrics` endpoint that give you insight into the state of the services.
  See more details in the [Metrics reference](#metrics-reference).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

This integration also requires Elastic Package Registry version >= 1.10.0.

## Setup

In order to enable this telemetry in your Elastic Package Registry instance, you must set the metrics
address parameter. Or, as an alternative, set the environment variable
`EPR_METRICS_ADDRESS`. As an example:

```bash
package-registry -metrics-address 0.0.0.0:9000

EPR_METRICS_ADDRESS="0.0.0.0:9000" package-regsitry
```

Remember to expose the port used in the above setting (e.g. 9000) in your deployments:
k8s, docker-compose, etc..

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Metrics reference

### Metrics

Elastic Package Registry can provide Prometheus metrics in the `/metrics` endpoint.
You can verify that metrics endpoint is enabled by making an HTTP request to
`http://localhost:9000/metrics` on your package registry instance.

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
| package_registry.http.request_size_bytes.histogram | A histogram of sizes of requests to the http server | histogram |  |  |
| package_registry.http.response_size_bytes.histogram | A histogram of response sizes for requests to the http server | histogram |  |  |
| package_registry.http_requests_total.counter | Counter for requests to the http server | double |  | counter |
| package_registry.in_flight_requests | Requests currently being served by the http server | double |  | gauge |
| package_registry.indexer.get_duration_seconds.histogram | A histogram of latencies for get processes run by the indexer | histogram |  |  |
| package_registry.labels.code | HTTP Code | keyword |  |  |
| package_registry.labels.component | Component type of the storage (statics, artifacts, signature...) | keyword |  |  |
| package_registry.labels.indexer | Indexer type | keyword |  |  |
| package_registry.labels.instance | Elastic Package Registry instance | keyword |  |  |
| package_registry.labels.job |  | keyword |  |  |
| package_registry.labels.location | Storage location (remote or local) | keyword |  |  |
| package_registry.labels.method | HTTP method | keyword |  |  |
| package_registry.labels.path | Path of the HTTP request. | keyword |  |  |
| package_registry.labels.version | Elastic Package Registry version. | keyword |  |  |
| package_registry.number_indexed_packages | Number of indexed packages | integer |  | gauge |
| package_registry.start_time | Date where Elastic Package Registry started | date |  |  |
| package_registry.start_time_seconds | Start time of the process since unix epoch in seconds | double | s | gauge |
| package_registry.storage_indexer.update_index_duration_seconds.histogram | A histogram of latencies for update index processes run by the storage indexer | histogram |  |  |
| package_registry.storage_indexer.update_index_error_total.counter | A counter for all the update index processes that finished with error in the storage indexer | long |  |  |
| package_registry.storage_indexer.update_index_success_total.counter | A counter for all the update index processes that finished with success in the storage indexer | long |  |  |
| package_registry.storage_requests_total.counter | Counter for requests performed to the storage | long |  | counter |
| package_registry.uptime | Elastic Package Registry uptime in seconds | long | s | counter |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |  |
| tags | List of keywords used to tag each event. | keyword |  |  |


#### Example

An example event for `metrics` looks as following:

```json
{
    "@timestamp": "2022-07-28T09:54:47.993Z",
    "agent": {
        "ephemeral_id": "fb0962b4-3f3f-48d6-81d6-3df63366f744",
        "id": "97cba3e2-ea7d-4d80-aa69-75752faa1576",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.0.0"
    },
    "data_stream": {
        "dataset": "elastic_package_registry.metrics",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.3.1"
    },
    "elastic_agent": {
        "id": "97cba3e2-ea7d-4d80-aa69-75752faa1576",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "elastic_package_registry.metrics",
        "duration": 7602509,
        "ingested": "2022-07-28T09:54:51Z",
        "kind": "metric",
        "module": "prometheus"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
        "ip": [
            "172.31.0.7"
        ],
        "mac": [
            "02:42:ac:1f:00:07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.104-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.3 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "collector",
        "period": 30000
    },
    "package_registry": {
        "http": {
            "request_duration_seconds": {
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
            "request_size_bytes": {
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
                        0
                    ],
                    "values": [
                        8,
                        24,
                        48,
                        96,
                        192,
                        384,
                        768,
                        33280,
                        163840,
                        458752
                    ]
                }
            },
            "response_size_bytes": {
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
                        0
                    ],
                    "values": [
                        8,
                        24,
                        48,
                        96,
                        192,
                        384,
                        768,
                        33280,
                        163840,
                        458752
                    ]
                }
            }
        },
        "http_requests_total": {
            "counter": 20
        },
        "labels": {
            "code": "200",
            "instance": "elastic-package-service_elastic_package_registry_1:9110",
            "job": "prometheus",
            "method": "get",
            "path": "/"
        }
    },
    "service": {
        "address": "http://elastic-package-service_elastic_package_registry_1:9110/metrics",
        "type": "elastic_package_registry"
    }
}
```

