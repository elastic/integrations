# WebSphere Application Server

This Elastic integration is used to collect [WebSphere Application Server](https://www.ibm.com/cloud/websphere-application-server) metrics as follows:

   - Session Manager metrics

This integration uses Prometheus to collect above metrics.

To open Prometheus endpoint read following [instructions](https://www.ibm.com/docs/en/was/9.0.5?topic=mosh-displaying-pmi-metrics-in-prometheus-format-metrics-app).

### Session Manager

This data stream collects metrics related to Sessions.

An example event for `session_manager` looks as following:

```json
{
    "@timestamp": "2022-04-25T12:40:46.413Z",
    "agent": {
        "ephemeral_id": "d5572e4c-4045-455b-abab-3954dda97e39",
        "id": "b26c384c-6b4b-4c58-92bb-782548bf402a",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.1.0"
    },
    "data_stream": {
        "dataset": "websphere_application_server.session_manager",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.2.0"
    },
    "elastic_agent": {
        "id": "b26c384c-6b4b-4c58-92bb-782548bf402a",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "web",
        "dataset": "websphere_application_server.session_manager",
        "duration": 36585023,
        "ingested": "2022-04-25T12:40:49Z",
        "kind": "metric",
        "module": "websphere_application_server",
        "type": "info"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "172.19.0.7"
        ],
        "mac": [
            "02:42:ac:13:00:07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.59.1.el7.x86_64",
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
        "websphere_application_server-session_manager",
        "prometheus"
    ],
    "websphere_application_server": {
        "session_manager": {
            "activated_non_existent_sessions": 0,
            "affinity_breaks": 0,
            "app_name": "isclite#wasportlet.war",
            "cache_discarded": 0,
            "external": {
                "bytes": {
                    "read": 0,
                    "written": 0
                },
                "time_seconds": {
                    "read": 0,
                    "written": 0
                }
            },
            "no_room_for_new_sessions": 0,
            "persistent_stores": {
                "data_read": 0,
                "data_written": 0
            },
            "sessions": {
                "active": 0,
                "create": 0,
                "current": 0,
                "invalidated": {
                    "by_timeouts": 0,
                    "total": 0
                },
                "life_time": 0
            },
            "time_since_session_last_activated": 0
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
| websphere_application_server.session_manager.activated_non_existent_sessions | The number of non-existent sessions that are activated. | long |
| websphere_application_server.session_manager.affinity_breaks | The number of session affinity breaks. | long |
| websphere_application_server.session_manager.app_name | Name of the Application. | keyword |
| websphere_application_server.session_manager.cache_discarded | The number of times that the cache was discarded. | long |
| websphere_application_server.session_manager.external.bytes.read | Size of the session data (in bytes) read from persistent stores. This size is applicable only for serialized persistent sessions and similar to the externalReadTime field. | long |
| websphere_application_server.session_manager.external.bytes.written | Size of the session data (in bytes) written to persistent stores. This size is applicable only for serialized persistent sessions and similar to the externalReadTime field. | long |
| websphere_application_server.session_manager.external.time_seconds.read | Time (in seconds) taken to read the session data from persistent store. For the Multirow session, the metrics are for the attribute; for the SingleRow session the metrics are for the whole session. The time is applicable only for persistent sessions. When you use a JMS persistent store, if you choose not to serialize the data, the counter is not available. | long |
| websphere_application_server.session_manager.external.time_seconds.written | Time (in seconds) taken to write the session data from persistent stores. This time is applicable only for (serialized) persistent sessions and is similar to the externalReadTime field. | long |
| websphere_application_server.session_manager.no_room_for_new_sessions | The number of times that a request for a new session cannot be handled because this value exceeds the maximum session count. | long |
| websphere_application_server.session_manager.persistent_stores.data_read | Total number of times the session data was read from persistent stores. | long |
| websphere_application_server.session_manager.persistent_stores.data_written | Total number of times the session data being written to persistent store. | long |
| websphere_application_server.session_manager.sessions.active | The number of sessions that are currently accessed by requests. | long |
| websphere_application_server.session_manager.sessions.create | The number of session objects that were created by the server. | long |
| websphere_application_server.session_manager.sessions.current | The number of live sessions till date. | long |
| websphere_application_server.session_manager.sessions.invalidated.by_timeouts | The number of sessions that were invalidated by timeouts. | long |
| websphere_application_server.session_manager.sessions.invalidated.total | The total number of sessions that were invalidated. | long |
| websphere_application_server.session_manager.sessions.life_time | Life time of the session. | double |
| websphere_application_server.session_manager.time_since_session_last_activated | Time since this session was last activated. | double |

