# WebSphere Application Server

This Elastic integration is used to collect [WebSphere Application Server](https://www.ibm.com/cloud/websphere-application-server) metrics as follows:

   - JDBC metrics

This integration uses Prometheus to collect above metrics.

To open Prometheus endpoint read following [instructions](https://www.ibm.com/docs/en/was/9.0.5?topic=mosh-displaying-pmi-metrics-in-prometheus-format-metrics-app).

## JDBC

This data stream collects JDBC (Java Database Connectivity) related metrics.

An example event for `jdbc` looks as following:

```json
{
    "@timestamp": "2022-04-22T08:37:45.273Z",
    "agent": {
        "ephemeral_id": "add1889c-ae8c-4c6b-928f-047be04c7887",
        "id": "3d0b5b96-e9ff-4560-8cd8-9261ded61509",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.1.0"
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
        "id": "3d0b5b96-e9ff-4560-8cd8-9261ded61509",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "web",
        "dataset": "websphere_application_server.jdbc",
        "duration": 239432765,
        "ingested": "2022-04-22T08:37:48Z",
        "kind": "metric",
        "module": "websphere_application_server",
        "type": "info"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "172.30.0.7"
        ],
        "mac": [
            "02:42:ac:1e:00:07"
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
        "websphere_application_server-jdbc",
        "prometheus"
    ],
    "websphere_application_server": {
        "jdbc": {
            "connection": {
                "allocated": 0,
                "closed": 0,
                "created": 0,
                "fault_total": 0,
                "free": 0,
                "handles": 0,
                "managed": 0,
                "returned": 0,
                "total_in_use": 0,
                "total_operations_calls": 0,
                "total_operations_seconds": 0,
                "total_seconds_in_use": 0,
                "wait_seconds_total": 0,
                "wait_total": 0,
                "waiting_threads": 0
            },
            "datasource": "jdbc/DefaultEJBTimerDataSource",
            "percent_used": 0,
            "pool_size": 0,
            "total_cache_discarded": 0
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
| websphere_application_server.jdbc.connection.allocated | The total number of connections that were allocated. | long |
| websphere_application_server.jdbc.connection.closed | The total number of connections that were closed. | long |
| websphere_application_server.jdbc.connection.created | The total number of connections that were created. | long |
| websphere_application_server.jdbc.connection.fault_total | The number of connection timeouts in the pool. | long |
| websphere_application_server.jdbc.connection.free | The number of free connections in the pool. | long |
| websphere_application_server.jdbc.connection.handles | The number of Connection objects in use for a particular connection pool. The number applies to V5.0 data sources only. | long |
| websphere_application_server.jdbc.connection.managed | The number of ManagedConnection objects that are in use for a particular connection pool. The number applies to V5.0 data sources only. | long |
| websphere_application_server.jdbc.connection.returned | The total number of connections that were returned to the pool. | long |
| websphere_application_server.jdbc.connection.total_in_use | The total number of times that a connection was in use. | long |
| websphere_application_server.jdbc.connection.total_operations_calls | The number of JDBC calls. | long |
| websphere_application_server.jdbc.connection.total_operations_seconds | The total time (in seconds) that was spent running the JDBC calls, including the time spent in the JDBC driver, network, and database. The total time applies to V5.0 data sources only. | double |
| websphere_application_server.jdbc.connection.total_seconds_in_use | The total time (in seconds) that a connection was used. The total time is difference between the time at which the connection is allocated and returned. This value includes the JBDC operation time. | double |
| websphere_application_server.jdbc.connection.wait_seconds_total | The total wait time (in seconds) until a connection is granted. | double |
| websphere_application_server.jdbc.connection.wait_total | The number of times a request was waited for a connection to be granted. | long |
| websphere_application_server.jdbc.connection.waiting_threads | The number of threads that are concurrently waiting for a connection. | long |
| websphere_application_server.jdbc.datasource | Name of datasource. | keyword |
| websphere_application_server.jdbc.percent_used | Percent of the pool that was in use. The value is based on the total number of configured connections in the ConnectionPool, not the current number of connections. | long |
| websphere_application_server.jdbc.pool_size | The size of the connection pool. | long |
| websphere_application_server.jdbc.total_cache_discarded | The number of statements that were discarded because the cache is full. | long |

