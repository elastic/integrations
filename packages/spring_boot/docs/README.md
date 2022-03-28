# Spring Boot Integration

The Spring Boot Integration is used to fetch observability data from [Spring Boot Actuators web endpoints](https://docs.spring.io/spring-boot/docs/2.6.3/actuator-api/htmlsingle/) and ingest it into Elasticsearch.

## Compatibility

This module has been tested against Spring Boot v2.3.12.

## Requirements

In order to ingest data from Spring Boot:
- You must know the host for Spring Boot application, add that host while configuring the integration package.
- Add default path for jolokia.
- Spring-boot-actuator module provides all Spring Boot’s production-ready features. So add below dependency in `pom.xml` file.
```
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-actuator</artifactId>
</dependency>
```
- For access of jolokia add below dependency in `pom.xml` of Spring Boot Application.
```
<dependency>
	<groupId>org.jolokia</groupId>
	<artifactId>jolokia-core</artifactId>
</dependency>
```

## Logs

### Info logs

This is the `info` dataset.

- This dataset gives arbitrary application info.

An example event for `info` looks as following:

```json
{
    "@timestamp": "2022-03-28T11:23:36.536Z",
    "agent": {
        "ephemeral_id": "453c6c18-e8a1-4d86-bf0e-5c3c4dec4542",
        "id": "91638438-73e5-4a6a-9b0e-d78d9c581397",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0"
    },
    "data_stream": {
        "dataset": "spring_boot.info",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "91638438-73e5-4a6a-9b0e-d78d9c581397",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "database",
        "created": "2022-03-28T11:23:36.536Z",
        "dataset": "spring_boot.info",
        "ingested": "2022-03-28T11:23:40Z",
        "kind": "metric",
        "module": "spring_boot",
        "type": "info"
    },
    "spring_boot": {
        "info": {
            "description": "Spring Boot Actuator Project",
            "encoding": "UTF-8",
            "java": {
                "version": "1.8.0_322"
            },
            "name": "actuator-demo",
            "version": "0.0.1-Release"
        }
    },
    "tags": [
        "forwarded",
        "spring_boot.info"
    ]
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
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| spring_boot.info.description |  | text |
| spring_boot.info.encoding |  | text |
| spring_boot.info.java.version |  | text |
| spring_boot.info.name |  | text |
| spring_boot.info.version |  | text |
| tags | List of keywords used to tag each event. | keyword |


### Audit Events logs

This is the `audit_events` dataset.

- This dataset exposes audit events information for the current application.

An example event for `audit_events` looks as following:

```json
{
    "@timestamp": "2022-03-28T11:21:11.593Z",
    "agent": {
        "ephemeral_id": "b8de1af0-7162-4301-9f4a-731e1f0fd4f5",
        "id": "91638438-73e5-4a6a-9b0e-d78d9c581397",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0"
    },
    "data_stream": {
        "dataset": "spring_boot.audit_events",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "91638438-73e5-4a6a-9b0e-d78d9c581397",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "database",
        "created": "2022-03-28T11:21:11.593Z",
        "dataset": "spring_boot.audit_events",
        "ingested": "2022-03-28T11:21:15Z",
        "kind": "metric",
        "module": "spring_boot",
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
            "kernel": "3.10.0-1160.59.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.3 LTS (Focal Fossa)"
        }
    },
    "spring_boot": {
        "auditevents": {
            "principal": "actuator",
            "type": "AUTHENTICATION_SUCCESS"
        }
    },
    "tags": [
        "spring_boot.audit_events.metrics"
    ]
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
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| spring_boot.auditevents.principal |  | keyword |
| spring_boot.auditevents.type |  | keyword |
| tags | List of keywords used to tag each event. | keyword |


### HTTP Trace logs

This is the `http_trace` dataset.

- This dataset displays HTTP trace information.

An example event for `http_trace` looks as following:

```json
{
    "@timestamp": "2022-03-28T11:22:46.997Z",
    "agent": {
        "ephemeral_id": "e7fa07be-1cb5-4762-bf12-191f4fd2818d",
        "id": "91638438-73e5-4a6a-9b0e-d78d9c581397",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0"
    },
    "data_stream": {
        "dataset": "spring_boot.http_trace",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "91638438-73e5-4a6a-9b0e-d78d9c581397",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "database",
        "created": "2022-03-28T11:22:46.997Z",
        "dataset": "spring_boot.http_trace",
        "ingested": "2022-03-28T11:22:50Z",
        "kind": "metric",
        "module": "spring_boot",
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
            "kernel": "3.10.0-1160.59.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.3 LTS (Focal Fossa)"
        }
    },
    "http": {
        "request": {
            "method": "GET"
        },
        "response": {
            "status_code": 200
        }
    },
    "spring_boot": {
        "http_trace": {
            "request": {
                "uri": "http://springboot:8090/actuator/info"
            },
            "time_taken": 3
        }
    },
    "tags": [
        "spring_boot.http_trace.metrics"
    ]
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
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| http.response.status_code | HTTP response status code. | long |
| spring_boot.http_trace.principal |  | long |
| spring_boot.http_trace.request.remote_address |  | text |
| spring_boot.http_trace.request.uri |  | text |
| spring_boot.http_trace.session |  | long |
| spring_boot.http_trace.time_taken |  | long |
| tags | List of keywords used to tag each event. | keyword |


## Metrics

### Memory Metrics

This is the `memory` dataset.

- This dataset gives Memory information.

An example event for `memory` looks as following:

```json
{
    "@timestamp": "2022-03-28T11:25:16.527Z",
    "agent": {
        "ephemeral_id": "43c34d9f-b379-41d5-bacf-583a1303fbd0",
        "id": "91638438-73e5-4a6a-9b0e-d78d9c581397",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.0.0"
    },
    "data_stream": {
        "dataset": "spring_boot.memory",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "91638438-73e5-4a6a-9b0e-d78d9c581397",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "database",
        "dataset": "spring_boot.memory",
        "duration": 484168963,
        "ingested": "2022-03-28T11:25:19Z",
        "kind": "metric",
        "module": "spring_boot",
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
            "kernel": "3.10.0-1160.59.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.3 LTS (Focal Fossa)"
        }
    },
    "jolokia": {},
    "metricset": {
        "name": "jmx",
        "period": 60000
    },
    "service": {
        "address": "http://springboot:8090/actuator/jolokia",
        "type": "jolokia"
    },
    "spring_boot": {
        "memory": {
            "buffer_pool": {
                "direct": {
                    "count": 10,
                    "memory_used": 81920,
                    "total_capacity": 81920
                }
            }
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
| destination.domain | The domain name of the destination system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| http.response.body.bytes | Size in bytes of the response body. | long |
| http.response.status_code | HTTP response status code. | long |
| http.version | HTTP version. | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| os.name | Operating system name, without the version. | keyword |
| os.version | Operating system version as a raw string. | keyword |
| process.pid | Process id. | long |
| process.thread.id | Thread ID. | long |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.domain | The domain name of the source system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| spring_boot.memory.buffer_pool.direct.count |  | long |
| spring_boot.memory.buffer_pool.direct.memory_used |  | long |
| spring_boot.memory.buffer_pool.direct.total_capacity |  | long |
| spring_boot.memory.buffer_pool.mapped.count |  | long |
| spring_boot.memory.buffer_pool.mapped.memory_used |  | long |
| spring_boot.memory.buffer_pool.mapped.total_capacity |  | long |
| spring_boot.memory.memory.heap_memory_usage.committed |  | long |
| spring_boot.memory.memory.heap_memory_usage.init |  | long |
| spring_boot.memory.memory.heap_memory_usage.max |  | long |
| spring_boot.memory.memory.heap_memory_usage.used |  | long |
| spring_boot.memory.memory.non_heap_memory_usage.committed |  | long |
| spring_boot.memory.memory.non_heap_memory_usage.init |  | long |
| spring_boot.memory.memory.non_heap_memory_usage.max |  | long |
| spring_boot.memory.memory.non_heap_memory_usage.used |  | long |
| spring_boot.memory.memory.object_pending_finalization_count |  | long |
| spring_boot.memory.memory.verbose |  | boolean |
| spring_boot.memory.memory_manager.code_cache_manager.name |  | keyword |
| spring_boot.memory.memory_manager.code_cache_manager.valid |  | boolean |
| spring_boot.memory.memory_manager.metaspace_manager.name |  | keyword |
| spring_boot.memory.memory_manager.metaspace_manager.valid |  | boolean |
| tags | List of keywords used to tag each event. | keyword |
| tls.cipher | String indicating the cipher used during the current connection. | keyword |
| tls.version | Numeric part of the version parsed from the original string. | keyword |
| tls.version_protocol | Normalized lowercase protocol name parsed from original string. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.path | Path of the request, such as "/search". | wildcard |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| user.name | Short name or login of the user. | keyword |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |


### OS Metrics

This is the `os` dataset.

- This dataset gives OS related information.

An example event for `os` looks as following:

```json
{
    "@timestamp": "2022-03-28T11:26:03.012Z",
    "agent": {
        "ephemeral_id": "dced1d2d-0a6e-4355-92cc-4ec2243d1601",
        "id": "91638438-73e5-4a6a-9b0e-d78d9c581397",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.0.0"
    },
    "data_stream": {
        "dataset": "spring_boot.os",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "91638438-73e5-4a6a-9b0e-d78d9c581397",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "database",
        "dataset": "spring_boot.os",
        "duration": 199165663,
        "ingested": "2022-03-28T11:26:06Z",
        "kind": "metric",
        "module": "spring_boot",
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
            "kernel": "3.10.0-1160.59.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.3 LTS (Focal Fossa)"
        }
    },
    "jolokia": {},
    "metricset": {
        "name": "jmx",
        "period": 60000
    },
    "os": {
        "name": "Linux",
        "version": "3.10.0-1160.59.1.el7.x86_64"
    },
    "service": {
        "address": "http://springboot:8090/actuator/jolokia",
        "type": "jolokia"
    },
    "spring_boot": {
        "os": {
            "operating_system": {
                "arch": "amd64",
                "available_processors": 4,
                "committed_virtual_memory_size": 5042962432,
                "free": {
                    "physical_memory_size": 414687232,
                    "swap_space_size": 3384836096
                },
                "max_file_descriptor_count": 1048576,
                "open_file_descriptor_count": 27,
                "process": {
                    "cpu_load": 0.04482294935006723,
                    "cpu_time": 17570000000
                },
                "system": {
                    "cpu_load": 0.2671447781264007,
                    "load_average": 2.48
                },
                "total": {
                    "physical_memory_size": 6067863552,
                    "swap_space_size": 4160745472
                }
            }
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
| destination.domain | The domain name of the destination system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| http.response.body.bytes | Size in bytes of the response body. | long |
| http.response.status_code | HTTP response status code. | long |
| http.version | HTTP version. | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| os.name | Operating system name, without the version. | keyword |
| os.version | Operating system version as a raw string. | keyword |
| process.pid | Process id. | long |
| process.thread.id | Thread ID. | long |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.domain | The domain name of the source system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| spring_boot.os.operating_system.arch |  | keyword |
| spring_boot.os.operating_system.available_processors |  | long |
| spring_boot.os.operating_system.committed_virtual_memory_size |  | long |
| spring_boot.os.operating_system.free.physical_memory_size |  | long |
| spring_boot.os.operating_system.free.swap_space_size |  | long |
| spring_boot.os.operating_system.max_file_descriptor_count |  | long |
| spring_boot.os.operating_system.open_file_descriptor_count |  | long |
| spring_boot.os.operating_system.process.cpu_load |  | long |
| spring_boot.os.operating_system.process.cpu_time |  | long |
| spring_boot.os.operating_system.system.cpu_load |  | long |
| spring_boot.os.operating_system.system.load_average |  | long |
| spring_boot.os.operating_system.total.physical_memory_size |  | long |
| spring_boot.os.operating_system.total.swap_space_size |  | long |
| spring_boot.os.runtime.boot_class.path |  | keyword |
| spring_boot.os.runtime.boot_class.path_supported |  | boolean |
| spring_boot.os.runtime.class_path |  | keyword |
| spring_boot.os.runtime.library_path |  | keyword |
| spring_boot.os.runtime.management_spec_version |  | keyword |
| spring_boot.os.runtime.name |  | keyword |
| spring_boot.os.runtime.spec.name |  | keyword |
| spring_boot.os.runtime.spec.vendor |  | keyword |
| spring_boot.os.runtime.spec.version |  | keyword |
| spring_boot.os.runtime.start_time |  | long |
| spring_boot.os.runtime.system_properties.awt_toolkit |  | keyword |
| spring_boot.os.runtime.system_properties.catalina_base |  | keyword |
| spring_boot.os.runtime.system_properties.catalina_home |  | keyword |
| spring_boot.os.runtime.system_properties.catalina_use_naming |  | keyword |
| spring_boot.os.runtime.system_properties.file_encoding |  | keyword |
| spring_boot.os.runtime.system_properties.file_encoding_pkg |  | keyword |
| spring_boot.os.runtime.system_properties.file_separator |  | keyword |
| spring_boot.os.runtime.system_properties.java_awt_graphicsenv |  | keyword |
| spring_boot.os.runtime.system_properties.java_awt_headless |  | keyword |
| spring_boot.os.runtime.system_properties.java_awt_printerjob |  | keyword |
| spring_boot.os.runtime.system_properties.java_class_path |  | keyword |
| spring_boot.os.runtime.system_properties.java_class_version |  | keyword |
| spring_boot.os.runtime.system_properties.java_endorsed_dirs |  | keyword |
| spring_boot.os.runtime.system_properties.java_ext_dirs |  | keyword |
| spring_boot.os.runtime.system_properties.java_home |  | keyword |
| spring_boot.os.runtime.system_properties.java_io_tmpdir |  | keyword |
| spring_boot.os.runtime.system_properties.java_library_path |  | keyword |
| spring_boot.os.runtime.system_properties.java_protocol_handler_pkgs |  | keyword |
| spring_boot.os.runtime.system_properties.java_runtime_name |  | keyword |
| spring_boot.os.runtime.system_properties.java_runtime_version |  | keyword |
| spring_boot.os.runtime.system_properties.java_specification_name |  | keyword |
| spring_boot.os.runtime.system_properties.java_specification_vendor |  | keyword |
| spring_boot.os.runtime.system_properties.java_specification_version |  | keyword |
| spring_boot.os.runtime.system_properties.java_vendor |  | keyword |
| spring_boot.os.runtime.system_properties.java_vendor_url |  | keyword |
| spring_boot.os.runtime.system_properties.java_vendor_url_bug |  | keyword |
| spring_boot.os.runtime.system_properties.java_vendor_version |  | keyword |
| spring_boot.os.runtime.system_properties.java_version |  | keyword |
| spring_boot.os.runtime.system_properties.java_version_date |  | keyword |
| spring_boot.os.runtime.system_properties.java_vm_info |  | keyword |
| spring_boot.os.runtime.system_properties.java_vm_name |  | keyword |
| spring_boot.os.runtime.system_properties.java_vm_specification_name |  | keyword |
| spring_boot.os.runtime.system_properties.java_vm_specification_vendor |  | keyword |
| spring_boot.os.runtime.system_properties.java_vm_specification_version |  | keyword |
| spring_boot.os.runtime.system_properties.java_vm_vendor |  | keyword |
| spring_boot.os.runtime.system_properties.java_vm_version |  | keyword |
| spring_boot.os.runtime.system_properties.jdk_debug |  | keyword |
| spring_boot.os.runtime.system_properties.line_separator |  | keyword |
| spring_boot.os.runtime.system_properties.log_file |  | keyword |
| spring_boot.os.runtime.system_properties.os_arch |  | keyword |
| spring_boot.os.runtime.system_properties.os_name |  | keyword |
| spring_boot.os.runtime.system_properties.os_version |  | keyword |
| spring_boot.os.runtime.system_properties.path_separator |  | keyword |
| spring_boot.os.runtime.system_properties.pid |  | keyword |
| spring_boot.os.runtime.system_properties.spring_beaninfo_ignore |  | keyword |
| spring_boot.os.runtime.system_properties.sun_arch_data_model |  | keyword |
| spring_boot.os.runtime.system_properties.sun_boot_class_path |  | keyword |
| spring_boot.os.runtime.system_properties.sun_boot_library_path |  | keyword |
| spring_boot.os.runtime.system_properties.sun_cpu_endian |  | keyword |
| spring_boot.os.runtime.system_properties.sun_cpu_isalist |  | keyword |
| spring_boot.os.runtime.system_properties.sun_io_unicode_encoding |  | keyword |
| spring_boot.os.runtime.system_properties.sun_java_command |  | keyword |
| spring_boot.os.runtime.system_properties.sun_java_launcher |  | keyword |
| spring_boot.os.runtime.system_properties.sun_jnu_encoding |  | keyword |
| spring_boot.os.runtime.system_properties.sun_management_compiler |  | keyword |
| spring_boot.os.runtime.system_properties.sun_os_patch_level |  | keyword |
| spring_boot.os.runtime.system_properties.user_country |  | keyword |
| spring_boot.os.runtime.system_properties.user_dir |  | keyword |
| spring_boot.os.runtime.system_properties.user_home |  | keyword |
| spring_boot.os.runtime.system_properties.user_language |  | keyword |
| spring_boot.os.runtime.system_properties.user_name |  | keyword |
| spring_boot.os.runtime.system_properties.user_timezone |  | keyword |
| spring_boot.os.runtime.uptime |  | long |
| spring_boot.os.runtime.vm.name |  | keyword |
| spring_boot.os.runtime.vm.vendor |  | keyword |
| spring_boot.os.runtime.vm.version |  | keyword |
| tags | List of keywords used to tag each event. | keyword |
| tls.cipher | String indicating the cipher used during the current connection. | keyword |
| tls.version | Numeric part of the version parsed from the original string. | keyword |
| tls.version_protocol | Normalized lowercase protocol name parsed from original string. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.path | Path of the request, such as "/search". | wildcard |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| user.name | Short name or login of the user. | keyword |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |


### Threads Metrics

This is the `threads` dataset.

- This dataset gives details of threads.

An example event for `threads` looks as following:

```json
{
    "@timestamp": "2022-03-28T11:27:39.605Z",
    "agent": {
        "ephemeral_id": "f20f638a-566a-4317-9cd9-f5cf73973b99",
        "id": "91638438-73e5-4a6a-9b0e-d78d9c581397",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.0.0"
    },
    "data_stream": {
        "dataset": "spring_boot.threads",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "91638438-73e5-4a6a-9b0e-d78d9c581397",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "database",
        "dataset": "spring_boot.threads",
        "duration": 97644083,
        "ingested": "2022-03-28T11:27:43Z",
        "kind": "metric",
        "module": "spring_boot",
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
            "kernel": "3.10.0-1160.59.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.3 LTS (Focal Fossa)"
        }
    },
    "jolokia": {},
    "metricset": {
        "name": "jmx",
        "period": 60000
    },
    "service": {
        "address": "http://springboot:8090/actuator/jolokia",
        "type": "jolokia"
    },
    "spring_boot": {
        "threads": {
            "threading": {
                "current_thread": {
                    "allocated_bytes": 226144,
                    "cpu_time": 95404339,
                    "cpu_time_supported": true,
                    "user_time": 90000000
                },
                "daemon_thread_count": 16,
                "object_monitor_usage_supported": true,
                "peak_thread_count": 20,
                "synchronizer_usage_supported": true,
                "thread": {
                    "allocated_memory_enabled": true,
                    "allocated_memory_supported": true,
                    "contention_monitoring_enabled": false,
                    "contention_monitoring_supported": true,
                    "count": 20,
                    "cpu_time_enabled": true,
                    "cpu_time_supported": true
                },
                "total_started_thread_count": 23
            }
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
| destination.domain | The domain name of the destination system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| http.response.body.bytes | Size in bytes of the response body. | long |
| http.response.status_code | HTTP response status code. | long |
| http.version | HTTP version. | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| os.name | Operating system name, without the version. | keyword |
| os.version | Operating system version as a raw string. | keyword |
| process.pid | Process id. | long |
| process.thread.id | Thread ID. | long |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.domain | The domain name of the source system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| spring_boot.threads.threading.current_thread.allocated_bytes |  | double |
| spring_boot.threads.threading.current_thread.cpu_time |  | long |
| spring_boot.threads.threading.current_thread.cpu_time_supported |  | boolean |
| spring_boot.threads.threading.current_thread.user_time |  | long |
| spring_boot.threads.threading.daemon_thread_count |  | long |
| spring_boot.threads.threading.object_monitor_usage_supported |  | boolean |
| spring_boot.threads.threading.peak_thread_count |  | long |
| spring_boot.threads.threading.synchronizer_usage_supported |  | boolean |
| spring_boot.threads.threading.thread.allocated_memory_enabled |  | boolean |
| spring_boot.threads.threading.thread.allocated_memory_supported |  | boolean |
| spring_boot.threads.threading.thread.contention_monitoring_enabled |  | boolean |
| spring_boot.threads.threading.thread.contention_monitoring_supported |  | boolean |
| spring_boot.threads.threading.thread.count |  | long |
| spring_boot.threads.threading.thread.cpu_time_enabled |  | boolean |
| spring_boot.threads.threading.thread.cpu_time_supported |  | boolean |
| spring_boot.threads.threading.total_started_thread_count |  | long |
| tags | List of keywords used to tag each event. | keyword |
| tls.cipher | String indicating the cipher used during the current connection. | keyword |
| tls.version | Numeric part of the version parsed from the original string. | keyword |
| tls.version_protocol | Normalized lowercase protocol name parsed from original string. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.path | Path of the request, such as "/search". | wildcard |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| user.name | Short name or login of the user. | keyword |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |


### GC Metrics

This is the `gc` dataset.

- This dataset gives data of GC Memory.

An example event for `gc` looks as following:

```json
{
    "@timestamp": "2022-03-28T11:22:00.598Z",
    "agent": {
        "ephemeral_id": "e1c8c531-dabd-4a69-b99a-efdb2b1cab03",
        "id": "91638438-73e5-4a6a-9b0e-d78d9c581397",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.0.0"
    },
    "data_stream": {
        "dataset": "spring_boot.gc",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "91638438-73e5-4a6a-9b0e-d78d9c581397",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "database",
        "dataset": "spring_boot.gc",
        "duration": 217674627,
        "ingested": "2022-03-28T11:22:04Z",
        "kind": "metric",
        "module": "spring_boot",
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
            "kernel": "3.10.0-1160.59.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.3 LTS (Focal Fossa)"
        }
    },
    "jolokia": {},
    "metricset": {
        "name": "jmx",
        "period": 60000
    },
    "service": {
        "address": "http://springboot:8090/actuator/jolokia",
        "type": "jolokia"
    },
    "spring_boot": {
        "gc": {
            "garbage_collector": {
                "collection": {
                    "count": 2,
                    "time": 123
                },
                "last_gc_info": {
                    "duration": 71,
                    "end_time": 4741,
                    "gc_thread_count": 4,
                    "id": 2,
                    "memory_usage_after_gc": {
                        "code_cache": {
                            "committed": 12845056,
                            "init": 2555904,
                            "max": 251658240,
                            "used": 12745152
                        },
                        "compressed_class_space": {
                            "committed": 4980736,
                            "init": 0,
                            "max": 1073741824,
                            "used": 4450512
                        },
                        "metaspace": {
                            "committed": 36265984,
                            "init": 0,
                            "max": -1,
                            "used": 33798280
                        },
                        "ps_eden_space": {
                            "committed": 331350016,
                            "init": 24641536,
                            "max": 479723520,
                            "used": 0
                        },
                        "ps_old_gen": {
                            "committed": 63438848,
                            "init": 64487424,
                            "max": 1012400128,
                            "used": 14914688
                        },
                        "ps_survivor_space": {
                            "committed": 12582912,
                            "init": 3670016,
                            "max": 12582912,
                            "used": 0
                        }
                    },
                    "memory_usage_before_gc": {
                        "code_cache": {
                            "committed": 12845056,
                            "init": 2555904,
                            "max": 251658240,
                            "used": 12745152
                        },
                        "compressed_class_space": {
                            "committed": 4980736,
                            "init": 0,
                            "max": 1073741824,
                            "used": 4450512
                        },
                        "metaspace": {
                            "committed": 36265984,
                            "init": 0,
                            "max": -1,
                            "used": 33798280
                        },
                        "ps_eden_space": {
                            "committed": 331350016,
                            "init": 24641536,
                            "max": 479723520,
                            "used": 0
                        },
                        "ps_old_gen": {
                            "committed": 50331648,
                            "init": 64487424,
                            "max": 1012400128,
                            "used": 13970936
                        },
                        "ps_survivor_space": {
                            "committed": 12582912,
                            "init": 3670016,
                            "max": 12582912,
                            "used": 9621584
                        }
                    },
                    "start_time": 4670
                },
                "name": "PS MarkSweep",
                "valid": true
            }
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
| destination.domain | The domain name of the destination system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| http.response.body.bytes | Size in bytes of the response body. | long |
| http.response.status_code | HTTP response status code. | long |
| http.version | HTTP version. | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| os.name | Operating system name, without the version. | keyword |
| os.version | Operating system version as a raw string. | keyword |
| process.pid | Process id. | long |
| process.thread.id | Thread ID. | long |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.domain | The domain name of the source system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| spring_boot.gc.garbage_collector.collection.count |  | long |
| spring_boot.gc.garbage_collector.collection.time |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.duration |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.end_time |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.gc_thread_count |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.id |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_after_gc.code_cache.committed |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_after_gc.code_cache.init |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_after_gc.code_cache.max |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_after_gc.code_cache.used |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_after_gc.compressed_class_space.committed |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_after_gc.compressed_class_space.init |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_after_gc.compressed_class_space.max |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_after_gc.compressed_class_space.used |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_after_gc.metaspace.committed |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_after_gc.metaspace.init |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_after_gc.metaspace.max |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_after_gc.metaspace.used |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_after_gc.ps_eden_space.committed |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_after_gc.ps_eden_space.init |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_after_gc.ps_eden_space.max |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_after_gc.ps_eden_space.used |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_after_gc.ps_old_gen.committed |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_after_gc.ps_old_gen.init |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_after_gc.ps_old_gen.max |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_after_gc.ps_old_gen.used |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_after_gc.ps_survivor_space.committed |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_after_gc.ps_survivor_space.init |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_after_gc.ps_survivor_space.max |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_after_gc.ps_survivor_space.used |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_before_gc.code_cache.committed |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_before_gc.code_cache.init |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_before_gc.code_cache.max |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_before_gc.code_cache.used |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_before_gc.compressed_class_space.committed |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_before_gc.compressed_class_space.init |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_before_gc.compressed_class_space.max |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_before_gc.compressed_class_space.used |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_before_gc.metaspace.committed |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_before_gc.metaspace.init |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_before_gc.metaspace.max |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_before_gc.metaspace.used |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_before_gc.ps_eden_space.committed |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_before_gc.ps_eden_space.init |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_before_gc.ps_eden_space.max |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_before_gc.ps_eden_space.used |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_before_gc.ps_old_gen.committed |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_before_gc.ps_old_gen.init |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_before_gc.ps_old_gen.max |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_before_gc.ps_old_gen.used |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_before_gc.ps_survivor_space.committed |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_before_gc.ps_survivor_space.init |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_before_gc.ps_survivor_space.max |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.memory_usage_before_gc.ps_survivor_space.used |  | long |
| spring_boot.gc.garbage_collector.last_gc_info.start_time |  | long |
| spring_boot.gc.garbage_collector.name |  | keyword |
| spring_boot.gc.garbage_collector.valid |  | boolean |
| spring_boot.gc.memory_pool.collection_usage.committed |  | long |
| spring_boot.gc.memory_pool.collection_usage.init |  | long |
| spring_boot.gc.memory_pool.collection_usage.max |  | long |
| spring_boot.gc.memory_pool.collection_usage.used |  | long |
| spring_boot.gc.memory_pool.collection_usage_threshold.count |  | long |
| spring_boot.gc.memory_pool.collection_usage_threshold.exceeded |  | boolean |
| spring_boot.gc.memory_pool.collection_usage_threshold.supported |  | boolean |
| spring_boot.gc.memory_pool.collection_usage_threshold.threshold |  | long |
| spring_boot.gc.memory_pool.name |  | keyword |
| spring_boot.gc.memory_pool.peak_usage.committed |  | long |
| spring_boot.gc.memory_pool.peak_usage.init |  | long |
| spring_boot.gc.memory_pool.peak_usage.max |  | long |
| spring_boot.gc.memory_pool.peak_usage.used |  | long |
| spring_boot.gc.memory_pool.type |  | keyword |
| spring_boot.gc.memory_pool.usage.committed |  | long |
| spring_boot.gc.memory_pool.usage.init |  | long |
| spring_boot.gc.memory_pool.usage.max |  | long |
| spring_boot.gc.memory_pool.usage.used |  | long |
| spring_boot.gc.memory_pool.usage_threshold.count |  | long |
| spring_boot.gc.memory_pool.usage_threshold.exceeded |  | boolean |
| spring_boot.gc.memory_pool.usage_threshold.supported |  | boolean |
| spring_boot.gc.memory_pool.usage_threshold.threshold |  | long |
| spring_boot.gc.memory_pool.valid |  | boolean |
| tags | List of keywords used to tag each event. | keyword |
| tls.cipher | String indicating the cipher used during the current connection. | keyword |
| tls.version | Numeric part of the version parsed from the original string. | keyword |
| tls.version_protocol | Normalized lowercase protocol name parsed from original string. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.path | Path of the request, such as "/search". | wildcard |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| user.name | Short name or login of the user. | keyword |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |


### JVM Metrics

This is the `jvm` dataset.

- This dataset gives data of JVM Memory.

An example event for `jvm` looks as following:

```json
{
    "@timestamp": "2022-03-28T11:24:25.786Z",
    "agent": {
        "ephemeral_id": "e0723ad1-423d-471d-9910-1ffeadbab5c5",
        "id": "91638438-73e5-4a6a-9b0e-d78d9c581397",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.0.0"
    },
    "data_stream": {
        "dataset": "spring_boot.jvm",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "91638438-73e5-4a6a-9b0e-d78d9c581397",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "spring_boot.jvm",
        "duration": 102331106,
        "ingested": "2022-03-28T11:24:29Z",
        "kind": "metric",
        "module": "prometheus"
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
            "kernel": "3.10.0-1160.59.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.3 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "period": 20000
    },
    "service": {
        "type": "spring_boot"
    },
    "spring_boot": {
        "jvm": {
            "labels": {
                "instance": "springboot:8090",
                "job": "prometheus",
                "state": "runnable"
            },
            "metrics": {
                "jvm": {
                    "threads": {
                        "states_threads": 6
                    }
                }
            }
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
| labels | Custom key/value pairs. Can be used to add meta information to events. Should not contain nested objects. All values are stored as keyword. Example: `docker` and `k8s` labels. | object |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| spring_boot.jvm.labels.action |  | keyword |
| spring_boot.jvm.labels.area |  | keyword |
| spring_boot.jvm.labels.cause |  | keyword |
| spring_boot.jvm.labels.exception |  | keyword |
| spring_boot.jvm.labels.id |  | keyword |
| spring_boot.jvm.labels.instance |  | keyword |
| spring_boot.jvm.labels.job |  | keyword |
| spring_boot.jvm.labels.level |  | keyword |
| spring_boot.jvm.labels.method |  | keyword |
| spring_boot.jvm.labels.outcome |  | keyword |
| spring_boot.jvm.labels.state |  | keyword |
| spring_boot.jvm.labels.status |  | keyword |
| spring_boot.jvm.labels.uri |  | keyword |
| spring_boot.jvm.metrics.jvm.buffer.count_buffers |  | long |
| spring_boot.jvm.metrics.jvm.buffer.memory_used_bytes |  | long |
| spring_boot.jvm.metrics.jvm.buffer.total_capacity_bytes |  | long |
| spring_boot.jvm.metrics.jvm.classes.loaded_classes |  | long |
| spring_boot.jvm.metrics.jvm.classes.unloaded_classes_total |  | long |
| spring_boot.jvm.metrics.jvm.gc.live_data_size_bytes |  | long |
| spring_boot.jvm.metrics.jvm.gc.max_data_size_bytes |  | long |
| spring_boot.jvm.metrics.jvm.gc.memory.allocated_bytes_total |  | long |
| spring_boot.jvm.metrics.jvm.gc.memory.promoted_bytes_total |  | long |
| spring_boot.jvm.metrics.jvm.gc.pause_seconds.count |  | long |
| spring_boot.jvm.metrics.jvm.gc.pause_seconds.max |  | long |
| spring_boot.jvm.metrics.jvm.gc.pause_seconds.sum |  | long |
| spring_boot.jvm.metrics.jvm.memory.committed_bytes |  | long |
| spring_boot.jvm.metrics.jvm.memory.max_bytes |  | long |
| spring_boot.jvm.metrics.jvm.memory.used_bytes |  | long |
| spring_boot.jvm.metrics.jvm.threads.daemon_threads |  | long |
| spring_boot.jvm.metrics.jvm.threads.live_threads |  | long |
| spring_boot.jvm.metrics.jvm.threads.peak_threads |  | long |
| spring_boot.jvm.metrics.jvm.threads.states_threads |  | long |


### Server Metrics

This is the `server` dataset.

- This dataset gives information of Server.

An example event for `server` looks as following:

```json
{
    "@timestamp": "2022-03-28T11:26:51.895Z",
    "agent": {
        "ephemeral_id": "62781031-f23f-4439-862c-337fddf40679",
        "id": "91638438-73e5-4a6a-9b0e-d78d9c581397",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.0.0"
    },
    "data_stream": {
        "dataset": "spring_boot.server",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "91638438-73e5-4a6a-9b0e-d78d9c581397",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "spring_boot.server",
        "duration": 102381358,
        "ingested": "2022-03-28T11:26:55Z",
        "kind": "metric",
        "module": "prometheus"
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
            "kernel": "3.10.0-1160.59.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.3 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "period": 20000
    },
    "service": {
        "type": "spring_boot"
    },
    "spring_boot": {
        "server": {
            "labels": {
                "instance": "springboot:8090",
                "job": "prometheus",
                "level": "debug"
            },
            "metrics": {
                "logback_events_total": 0
            }
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
| labels | Custom key/value pairs. Can be used to add meta information to events. Should not contain nested objects. All values are stored as keyword. Example: `docker` and `k8s` labels. | object |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| spring_boot.server.labels.action |  | keyword |
| spring_boot.server.labels.area |  | keyword |
| spring_boot.server.labels.cause |  | keyword |
| spring_boot.server.labels.exception |  | keyword |
| spring_boot.server.labels.id |  | keyword |
| spring_boot.server.labels.instance |  | keyword |
| spring_boot.server.labels.job |  | keyword |
| spring_boot.server.labels.level |  | keyword |
| spring_boot.server.labels.method |  | keyword |
| spring_boot.server.labels.outcome |  | keyword |
| spring_boot.server.labels.state |  | keyword |
| spring_boot.server.labels.status |  | keyword |
| spring_boot.server.labels.uri |  | keyword |
| spring_boot.server.metrics.http_server_requests_seconds.max |  | long |
| spring_boot.server.metrics.http_server_requests_seconds.sum |  | long |
| spring_boot.server.metrics.logback_events_total |  | long |
| spring_boot.server.metrics.process.cpu_usage |  | long |
| spring_boot.server.metrics.process.files.max_files |  | long |
| spring_boot.server.metrics.process.files.open_files |  | long |
| spring_boot.server.metrics.process.start_time_seconds |  | long |
| spring_boot.server.metrics.process.uptime_seconds |  | long |
| spring_boot.server.metrics.system.cpu.count |  | long |
| spring_boot.server.metrics.system.cpu.usage |  | long |
| spring_boot.server.metrics.system.load_average_1m |  | long |
| spring_boot.server.metrics.tomcat_sessions.active.current_sessions |  | long |
| spring_boot.server.metrics.tomcat_sessions.active.max_sessions |  | long |
| spring_boot.server.metrics.tomcat_sessions.alive_max_seconds |  | long |
| spring_boot.server.metrics.tomcat_sessions.created_sessions_total |  | long |
| spring_boot.server.metrics.tomcat_sessions.expired_sessions_total |  | long |
| spring_boot.server.metrics.tomcat_sessions.rejected_sessions_total |  | long |
| spring_boot.server.metrics.up |  | long |

