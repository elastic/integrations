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


