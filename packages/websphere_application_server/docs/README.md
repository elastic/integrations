# WebSphere Application Server

This elastic integration is used to collect [WebSphere Application Server](https://www.ibm.com/cloud/websphere-application-server) metrics as follows:

   - Servlet metrics

This integration uses Prometheus to collect above metrics.

To open Prometheus endpoint read following [instructions](https://www.ibm.com/docs/en/was/9.0.5?topic=mosh-displaying-pmi-metrics-in-prometheus-format-metrics-app).

## Servlet

This data stream collects Servlet metrics.

An example event for `servlet` looks as following:

```json
{
    "@timestamp": "2022-04-22T09:17:36.290Z",
    "agent": {
        "ephemeral_id": "92afaec7-277c-48ca-bc74-1e9827c4ba02",
        "id": "9b88da1e-6314-4974-9e53-032e334b9305",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.1.0"
    },
    "data_stream": {
        "dataset": "websphere_application_server.servlet",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.2.0"
    },
    "elastic_agent": {
        "id": "9b88da1e-6314-4974-9e53-032e334b9305",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "web",
        "dataset": "websphere_application_server.servlet",
        "duration": 122318164,
        "ingested": "2022-04-22T09:17:39Z",
        "kind": "metric",
        "module": "websphere_application_server",
        "type": "info"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "192.168.16.5"
        ],
        "mac": [
            "02:42:c0:a8:10:05"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.45.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.3 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "collector",
        "period": 60000
    },
    "server": {
        "address": "elastic-package-service_websphere_application_server_1:9080"
    },
    "service": {
        "address": "http://elastic-package-service_websphere_application_server_1:9080/metrics",
        "type": "prometheus"
    },
    "tags": [
        "forwarded",
        "websphere_application_server-servlet",
        "prometheus"
    ],
    "websphere_application_server": {
        "servlet": {
            "appname": "ibmasyncrsp#ibmasyncrsp.war",
            "loaded": 0,
            "reloaded": 0
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| server.address | Some event server addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| url.path | Path of the request, such as "/search". | wildcard |
| websphere_application_server.servlet.appname | Application name. | keyword |
| websphere_application_server.servlet.async_context.response_time_seconds | The total time spent(in seconds) per servlet for the AsyncContext response to complete. | double |
| websphere_application_server.servlet.async_context.total_responses | The total number of AsyncContext responses for the specified URL. | long |
| websphere_application_server.servlet.concurrent_requests | Number of concurrent requests sent to the servlet. | long |
| websphere_application_server.servlet.errors | Number of errors that were generated while responding to a request. | long |
| websphere_application_server.servlet.loaded | The number of servlets that were loaded. | long |
| websphere_application_server.servlet.reloaded | The number of servlets that were reloaded. | long |
| websphere_application_server.servlet.requests_processed | The total number of requests that a servlet processed. | long |
| websphere_application_server.servlet.response_time_seconds | The total response time (in seconds) to process servlet requests. | double |
| websphere_application_server.servlet.responses_processed | The total number of responses that a servlet processed. | long |
| websphere_application_server.servlet.uri.async_context.response_time_seconds | The total time spent(in seconds) per URL for the AsyncContext response to complete. | double |
| websphere_application_server.servlet.uri.async_context.total_responses | The total number of AsyncContext responses for the specified URL. | long |
| websphere_application_server.servlet.uri.concurrent_requests | The number of requests that were concurrently processed for the specified URL. | long |
| websphere_application_server.servlet.uri.response_time_seconds | The total response time (in seconds) to process the requests for the specified URL. | double |
| websphere_application_server.servlet.uri.total_requests | total number of requests that a servlet processed for the specified URL. | long |
| websphere_application_server.servlet.uri.total_responses | The total number of responses for the specified URL. | long |

