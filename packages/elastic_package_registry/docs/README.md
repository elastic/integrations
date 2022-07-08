# Elastic Package Registry

This integration collects metrics from Elastic Package Registry (EPR).
There is one data stream:

- metrics: Telemetry data from the /metrics API.

## Compatibility

This integration requires EPR >= 1.10.0.

## Metrics

Elastic Package Registry can provide Prometheus metrics in the `/metrics` endpoint.
You can verify that metrics are enabled by making an HTTP request to:
`http://localhost:9000/metrics` on your package registry instance.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| package_registry.\*.\* | Elastic Package Registry data from the Prometheus endpoint. |  |
| prometheus.\*.counter | Prometheus counter metric | object |
| prometheus.\*.histogram | Prometheus histogram metric | object |
| prometheus.\*.rate | Prometheus rated counter metric | object |
| prometheus.\*.value | Prometheus gauge metric | object |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| tags | List of keywords used to tag each event. | keyword |

