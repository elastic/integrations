# WebSphere Application Server

This Elastic integration is used to collect the following metrics from [IBM WebSphere Application Server](https://www.ibm.com/cloud/websphere-application-server):

   - JDBC metrics
   - Servlet metrics

This integration uses Prometheus to collect above metrics.

To open Prometheus endpoint read following [instructions](https://www.ibm.com/docs/en/was/9.0.5?topic=mosh-displaying-pmi-metrics-in-prometheus-format-metrics-app).

## JDBC

This data stream collects JDBC (Java Database Connectivity) related metrics.

An example event for `jdbc` looks as following:

```json
{
    "@timestamp": "2022-05-19T13:33:01.029Z",
    "agent": {
        "ephemeral_id": "7fca7599-6641-4340-ab44-e026d1b4935a",
        "id": "a0386d69-0749-44b4-8487-9b92e66852a1",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.2.0"
    },
    "data_stream": {
        "dataset": "websphere_application_server.jdbc",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.2.0"
    },
    "elastic_agent": {
        "id": "a0386d69-0749-44b4-8487-9b92e66852a1",
        "snapshot": false,
        "version": "8.2.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "web",
        "dataset": "websphere_application_server.jdbc",
        "duration": 364066933,
        "ingested": "2022-05-19T13:33:04Z",
        "kind": "metric",
        "module": "websphere_application_server",
        "type": "info"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "172.31.0.5"
        ],
        "mac": [
            "02:42:ac:1f:00:05"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.45.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.4 LTS (Focal Fossa)"
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
        "websphere_application_server-jdbc",
        "prometheus"
    ],
    "websphere_application_server": {
        "jdbc": {
            "connection": {
                "allocated": 0,
                "closed": 0,
                "created": 0,
                "free": 0,
                "handles": 0,
                "managed": 0,
                "returned": 0,
                "total": {
                    "fault": 0,
                    "in_use": 0,
                    "seconds_in_use": 0,
                    "wait": 0,
                    "wait_seconds": 0
                },
                "waiting_threads": 0
            },
            "data_source": "jms/built-in-jms-connectionfactory",
            "percent_used": 0,
            "pool_size": 0
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
| event.category | Event category. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | Event kind | constant_keyword |
| event.module | Event module | constant_keyword |
| event.type | Event type | constant_keyword |
| server.address | Some event server addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| websphere_application_server.jdbc.connection.allocated | The total number of connections that were allocated. | long |
| websphere_application_server.jdbc.connection.closed | The total number of connections that were closed. | long |
| websphere_application_server.jdbc.connection.created | The total number of connections that were created. | long |
| websphere_application_server.jdbc.connection.free | The number of free connections in the pool. | long |
| websphere_application_server.jdbc.connection.handles | The number of Connection objects in use for a particular connection pool. The number applies to V5.0 data sources only. | long |
| websphere_application_server.jdbc.connection.managed | The number of ManagedConnection objects that are in use for a particular connection pool. The number applies to V5.0 data sources only. | long |
| websphere_application_server.jdbc.connection.returned | The total number of connections that were returned to the pool. | long |
| websphere_application_server.jdbc.connection.total.fault | The number of connection timeouts in the pool. | long |
| websphere_application_server.jdbc.connection.total.in_use | The total number of times that a connection was in use. | long |
| websphere_application_server.jdbc.connection.total.operations_calls | The number of JDBC calls. | long |
| websphere_application_server.jdbc.connection.total.operations_seconds | The total time (in seconds) that was spent running the JDBC calls, including the time spent in the JDBC driver, network, and database. The total time applies to V5.0 data sources only. | double |
| websphere_application_server.jdbc.connection.total.seconds_in_use | The total time (in seconds) that a connection was used. The total time is difference between the time at which the connection is allocated and returned. This value includes the JBDC operation time. | double |
| websphere_application_server.jdbc.connection.total.wait | The number of times a request was waited for a connection to be granted. | long |
| websphere_application_server.jdbc.connection.total.wait_seconds | The total wait time (in seconds) until a connection is granted. | double |
| websphere_application_server.jdbc.connection.waiting_threads | The number of threads that are concurrently waiting for a connection. | long |
| websphere_application_server.jdbc.data_source | Name of data source. | keyword |
| websphere_application_server.jdbc.percent_used | Percent of the pool that was in use. The value is based on the total number of configured connections in the ConnectionPool, not the current number of connections. | long |
| websphere_application_server.jdbc.pool_size | The size of the connection pool. | long |
| websphere_application_server.jdbc.total_cache_discarded | The number of statements that were discarded because the cache is full. | long |


## Servlet

This data stream collects Servlet related metrics.

An example event for `servlet` looks as following:

```json
{
    "@timestamp": "2022-05-20T11:44:31.768Z",
    "agent": {
        "ephemeral_id": "2cc9ade1-a44e-4151-91bf-1e4865a9e57e",
        "id": "c05318bf-e468-4a7a-bd1d-7c7e4320cbde",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.2.0"
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
        "id": "c05318bf-e468-4a7a-bd1d-7c7e4320cbde",
        "snapshot": false,
        "version": "8.2.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "web",
        "dataset": "websphere_application_server.servlet",
        "duration": 153850315,
        "ingested": "2022-05-20T11:44:35Z",
        "kind": "metric",
        "module": "websphere_application_server",
        "type": "info"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "192.168.112.7"
        ],
        "mac": [
            "02:42:c0:a8:70:07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.45.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.4 LTS (Focal Fossa)"
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
            "app_name": "isclite#isclite.war",
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
| event.category | Event category. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | Event kind | constant_keyword |
| event.module | Event module | constant_keyword |
| event.type | Event type | constant_keyword |
| server.address | Some event server addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| url.path | Path of the request, such as "/search". | wildcard |
| websphere_application_server.servlet.app_name | Application name. | keyword |
| websphere_application_server.servlet.async_context.response_time_seconds | The total time spent (in seconds) per servlet for the AsyncContext response to complete. | double |
| websphere_application_server.servlet.async_context.responses.total | The total number of AsyncContext responses for the specified URL. | long |
| websphere_application_server.servlet.errors | Number of errors that were generated while responding to a request. | long |
| websphere_application_server.servlet.loaded | The number of servlets that were loaded. | long |
| websphere_application_server.servlet.reloaded | The number of servlets that were reloaded. | long |
| websphere_application_server.servlet.requests.concurrent | Number of concurrent requests sent to the servlet. | long |
| websphere_application_server.servlet.requests.processed | The total number of requests that a servlet processed. | long |
| websphere_application_server.servlet.response_time_seconds | The total response time (in seconds) to process servlet requests. | double |
| websphere_application_server.servlet.responses.processed | The total number of responses that a servlet processed. | long |
| websphere_application_server.servlet.uri.async_context.response_time_seconds | The total time spent (in seconds) per URL for the AsyncContext response to complete. | double |
| websphere_application_server.servlet.uri.async_context.responses.total | The total number of AsyncContext responses for the specified URL. | long |
| websphere_application_server.servlet.uri.requests.concurrent | The number of requests that were concurrently processed for the specified URL. | long |
| websphere_application_server.servlet.uri.requests.total | Total number of requests that a servlet processed for the specified URL. | long |
| websphere_application_server.servlet.uri.response_time_seconds | The total response time (in seconds) to process the requests for the specified URL. | double |
| websphere_application_server.servlet.uri.responses.total | The total number of responses for the specified URL. | long |
