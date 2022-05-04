# Cassandra Integration

This integration periodically fetches metrics from [Cassandra](https://cassandra.apache.org/) using jolokia agent. It can parse System logs.

## Logs

Cassandra system logs from cassandra.log files.

An example event for `log` looks as following:

```json
{
    "@timestamp": "2022-01-10T06:21:52.507Z",
    "agent": {
        "ephemeral_id": "a8a31530-f653-49ff-9daf-b691bb365ddb",
        "id": "25ee0259-10b8-4a16-9f80-d18ce8ad6442",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0-beta1"
    },
    "cassandra": {
        "log": {
            "meta": ""
        }
    },
    "data_stream": {
        "dataset": "cassandra.log",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "25ee0259-10b8-4a16-9f80-d18ce8ad6442",
        "snapshot": false,
        "version": "8.0.0-beta1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "database"
        ],
        "dataset": "cassandra.log",
        "ingested": "2022-01-10T06:22:16Z",
        "kind": "event",
        "original": "INFO  [main] 2022-01-10 06:21:52,507 YamlConfigurationLoader.java:92 - Configuration location: file:/etc/cassandra/cassandra.yaml",
        "type": "info"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "4ccba669f0df47fa3f57a9e4169ae7f1",
        "ip": [
            "172.18.0.7"
        ],
        "mac": [
            "02:42:ac:12:00:07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "Core",
            "family": "redhat",
            "kernel": "5.11.0-43-generic",
            "name": "CentOS Linux",
            "platform": "centos",
            "type": "linux",
            "version": "7 (Core)"
        }
    },
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/cassandra/system.log"
        },
        "level": "INFO",
        "offset": 0,
        "origin": {
            "file": {
                "line": 92,
                "name": "YamlConfigurationLoader.java"
            }
        }
    },
    "message": "Configuration location: file:/etc/cassandra/cassandra.yaml",
    "process": {
        "thread": {
            "name": "main"
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cassandra.log.meta | Log meta infos like java stack_trace | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| input.type | Input type | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.flags | Log flags | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.offset | Log offset | long |
| log.origin.file.line | The line number of the file containing the source code which originated the log event. | long |
| log.origin.file.name | The name of the file containing the source code which originated the log event. Note that this field is not meant to capture the log file. The correct field to capture the log file is `log.file.path`. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| process.thread.name | Thread name. | keyword |
| tags | List of keywords used to tag each event. | keyword |


## Metrics

Cassandra metrics using jolokia agent installed on cassandra.

An example event for `metrics` looks as following:

```json
{
    "@timestamp": "2022-01-10T06:23:22.646Z",
    "agent": {
        "ephemeral_id": "08d38295-0572-4d39-8456-23e0414fe734",
        "id": "25ee0259-10b8-4a16-9f80-d18ce8ad6442",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.0.0-beta1"
    },
    "cassandra": {
        "metrics": {
            "cache": {
                "key_cache": {
                    "capacity": 104857600,
                    "one_minute_hit_rate": 0.819047619047619,
                    "requests": {
                        "one_minute_rate": 21
                    }
                },
                "row_cache": {
                    "capacity": 0,
                    "requests": {
                        "one_minute_rate": 0
                    }
                }
            },
            "client_request": {
                "casread": {
                    "one_minute_rate": 0
                },
                "caswrite": {
                    "one_minute_rate": 0
                },
                "range_slice": {
                    "one_minute_rate": 0,
                    "total_latency": 0
                },
                "read": {
                    "count": 0,
                    "one_minute_rate": 0,
                    "timeouts": 0,
                    "total_latency": 0,
                    "unavailables": 0
                },
                "write": {
                    "count": 0,
                    "one_minute_rate": 0,
                    "timeouts": 0,
                    "timeoutsms": 0,
                    "total_latency": 0,
                    "unavailables": 0,
                    "unavailablesms": 0
                }
            },
            "column_family": {
                "total_disk_space_used": 102605
            },
            "compaction": {
                "completed": 7,
                "pending": 0
            },
            "dropped_message": {
                "batch_remove": 0,
                "batch_store": 0,
                "counter_mutation": 0,
                "hint": 0,
                "mutation": 0,
                "paged_range": 0,
                "range_slice": 0,
                "read": 0,
                "read_repair": 0,
                "request_response": 0,
                "trace": 0
            },
            "gc": {
                "concurrent_mark_sweep": {
                    "collection_count": 1,
                    "collection_time": 85
                },
                "par_new": {
                    "collection_count": 7,
                    "collection_time": 908
                }
            },
            "memory": {
                "heap_usage": {
                    "committed": 4181721088,
                    "init": 4192206848,
                    "max": 4181721088,
                    "used": 99833480
                },
                "other_usage": {
                    "committed": 58044416,
                    "init": 2555904,
                    "max": -1,
                    "used": 56197968
                }
            },
            "storage": {
                "exceptions": 0,
                "load": 102605,
                "total_hint_in_progress": 0,
                "total_hints": 0
            },
            "system": {
                "cluster": "Test Cluster",
                "data_center": "datacenter1",
                "joining_nodes": [],
                "leaving_nodes": [],
                "live_nodes": [
                    "172.19.0.2"
                ],
                "moving_nodes": [],
                "rack": "rack1",
                "unreachable_nodes": [],
                "version": "3.11.11"
            },
            "table": {
                "all_memtables_heap_size": 1528,
                "all_memtables_off_heap_size": 0,
                "live_disk_space_used": 102605,
                "live_ss_table_count": 17
            },
            "task": {
                "complete": 45,
                "pending": 0,
                "total_commitlog_size": 67108864
            },
            "thread_pools": {
                "counter_mutation_stage": {
                    "request": {
                        "active": 0,
                        "pending": 0
                    }
                },
                "mutation_stage": {
                    "request": {
                        "active": 0,
                        "pending": 0
                    }
                },
                "read_repair_stage": {
                    "request": {
                        "active": 0,
                        "pending": 0
                    }
                },
                "read_stage": {
                    "request": {
                        "active": 0,
                        "pending": 0
                    }
                },
                "request_response_stage": {
                    "request": {
                        "active": 0,
                        "pending": 0
                    }
                }
            }
        }
    },
    "data_stream": {
        "dataset": "cassandra.metrics",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "25ee0259-10b8-4a16-9f80-d18ce8ad6442",
        "snapshot": false,
        "version": "8.0.0-beta1"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "cassandra.metrics",
        "duration": 467706982,
        "ingested": "2022-01-10T06:23:24Z",
        "module": "jolokia"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "4ccba669f0df47fa3f57a9e4169ae7f1",
        "ip": [
            "172.18.0.7"
        ],
        "mac": [
            "02:42:ac:12:00:07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "Core",
            "family": "redhat",
            "kernel": "5.11.0-43-generic",
            "name": "CentOS Linux",
            "platform": "centos",
            "type": "linux",
            "version": "7 (Core)"
        }
    },
    "metricset": {
        "name": "jmx",
        "period": 10000
    },
    "service": {
        "address": "http://elastic-package-service-cassandra-1:8778/jolokia/%3FignoreErrors=true\u0026canonicalNaming=false",
        "type": "jolokia"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cassandra.metrics.cache.key_cache.capacity |  | long |
| cassandra.metrics.cache.key_cache.one_minute_hit_rate |  | long |
| cassandra.metrics.cache.key_cache.requests.one_minute_rate |  | long |
| cassandra.metrics.cache.row_cache.capacity |  | long |
| cassandra.metrics.cache.row_cache.one_minute_hit_rate |  | long |
| cassandra.metrics.cache.row_cache.requests.one_minute_rate |  | long |
| cassandra.metrics.client.connected_native_clients |  | long |
| cassandra.metrics.client_request.casread.one_minute_rate |  | double |
| cassandra.metrics.client_request.caswrite.one_minute_rate |  | double |
| cassandra.metrics.client_request.range_slice.one_minute_rate |  | double |
| cassandra.metrics.client_request.range_slice.total_latency |  | double |
| cassandra.metrics.client_request.read.count |  | long |
| cassandra.metrics.client_request.read.one_minute_rate |  | double |
| cassandra.metrics.client_request.read.timeouts | Number of read timeouts encountered | double |
| cassandra.metrics.client_request.read.timeoutsms |  | double |
| cassandra.metrics.client_request.read.total_latency |  | double |
| cassandra.metrics.client_request.read.unavailables | Number of read unavailables encountered | double |
| cassandra.metrics.client_request.read.unavailablesms |  | double |
| cassandra.metrics.client_request.write.count |  | long |
| cassandra.metrics.client_request.write.one_minute_rate |  | double |
| cassandra.metrics.client_request.write.timeouts |  | double |
| cassandra.metrics.client_request.write.timeoutsms |  | double |
| cassandra.metrics.client_request.write.total_latency |  | double |
| cassandra.metrics.client_request.write.unavailables |  | double |
| cassandra.metrics.client_request.write.unavailablesms |  | double |
| cassandra.metrics.column_family.total_disk_space_used |  | long |
| cassandra.metrics.compaction.completed | compaction completed tasks | long |
| cassandra.metrics.compaction.pending | compaction pending tasks | long |
| cassandra.metrics.dropped_message.batch_remove |  | long |
| cassandra.metrics.dropped_message.batch_store |  | long |
| cassandra.metrics.dropped_message.counter_mutation |  | long |
| cassandra.metrics.dropped_message.hint |  | long |
| cassandra.metrics.dropped_message.mutation |  | long |
| cassandra.metrics.dropped_message.paged_range |  | long |
| cassandra.metrics.dropped_message.range_slice |  | long |
| cassandra.metrics.dropped_message.read |  | long |
| cassandra.metrics.dropped_message.read_repair |  | long |
| cassandra.metrics.dropped_message.request_response |  | long |
| cassandra.metrics.dropped_message.trace |  | long |
| cassandra.metrics.gc.concurrent_mark_sweep.collection_count | Total number of CMS collections that have occurred. | long |
| cassandra.metrics.gc.concurrent_mark_sweep.collection_time | Approximate accumulated CMS collection elapsed time in milliseconds. | long |
| cassandra.metrics.gc.mbean | Mbean that this event is related to | keyword |
| cassandra.metrics.gc.par_new.collection_count | Total number of ParNew collections that have occurred. | long |
| cassandra.metrics.gc.par_new.collection_time | Approximate accumulated ParNew collection elapsed time in milliseconds. | long |
| cassandra.metrics.memory.heap_usage.committed | Committed heap memory usage | long |
| cassandra.metrics.memory.heap_usage.init | Initial heap memory usage | long |
| cassandra.metrics.memory.heap_usage.max | Max heap memory usage | long |
| cassandra.metrics.memory.heap_usage.used | Used heap memory usage | long |
| cassandra.metrics.memory.mbean | Mbean that this event is related to | keyword |
| cassandra.metrics.memory.other_usage.committed | Committed non-heap memory usage | long |
| cassandra.metrics.memory.other_usage.init | Initial non-heap memory usage | long |
| cassandra.metrics.memory.other_usage.max | Max non-heap memory usage | long |
| cassandra.metrics.memory.other_usage.used | Used non-heap memory usage | long |
| cassandra.metrics.storage.exceptions | The number of the total exceptions | long |
| cassandra.metrics.storage.load | Storage used for Cassandra data in bytes | long |
| cassandra.metrics.storage.mbean | Mbean that this event is related to | keyword |
| cassandra.metrics.storage.total_hint_in_progress | The number of the total hits in progress | long |
| cassandra.metrics.storage.total_hints | The number of the total hits | long |
| cassandra.metrics.system.cluster |  | keyword |
| cassandra.metrics.system.data_center |  | keyword |
| cassandra.metrics.system.joining_nodes |  | keyword |
| cassandra.metrics.system.leaving_nodes |  | keyword |
| cassandra.metrics.system.live_nodes |  | keyword |
| cassandra.metrics.system.moving_nodes |  | keyword |
| cassandra.metrics.system.rack |  | keyword |
| cassandra.metrics.system.unreachable_nodes |  | keyword |
| cassandra.metrics.system.version |  | keyword |
| cassandra.metrics.table.all_memtables_heap_size |  | long |
| cassandra.metrics.table.all_memtables_off_heap_size |  | long |
| cassandra.metrics.table.live_disk_space_used |  | long |
| cassandra.metrics.table.live_ss_table_count |  | long |
| cassandra.metrics.task.complete | completed tasks | long |
| cassandra.metrics.task.pending | pending tasks | long |
| cassandra.metrics.task.total_commitlog_size | total commitlog size of tasks | long |
| cassandra.metrics.thread_pools.counter_mutation_stage.request.active |  | long |
| cassandra.metrics.thread_pools.counter_mutation_stage.request.pending |  | long |
| cassandra.metrics.thread_pools.mutation_stage.request.active |  | long |
| cassandra.metrics.thread_pools.mutation_stage.request.pending |  | long |
| cassandra.metrics.thread_pools.read_repair_stage.request.active |  | long |
| cassandra.metrics.thread_pools.read_repair_stage.request.pending |  | long |
| cassandra.metrics.thread_pools.read_stage.request.active |  | long |
| cassandra.metrics.thread_pools.read_stage.request.pending |  | long |
| cassandra.metrics.thread_pools.request_response_stage.request.active |  | long |
| cassandra.metrics.thread_pools.request_response_stage.request.pending |  | long |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.domain | The domain name of the destination system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| http.response.body.bytes | Size in bytes of the response body. | long |
| http.response.status_code | HTTP response status code. | long |
| http.version | HTTP version. | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| process.pid | Process id. | long |
| process.thread.id | Thread ID. | long |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.domain | The domain name of the source system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| tags | List of keywords used to tag each event. | keyword |
| tls.cipher | String indicating the cipher used during the current connection. | keyword |
| tls.version | Numeric part of the version parsed from the original string. | keyword |
| tls.version_protocol | Normalized lowercase protocol name parsed from original string. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.original.text | Multi-field of `url.original`. | match_only_text |
| url.path | Path of the request, such as "/search". | wildcard |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.full.text | Multi-field of `user_agent.os.full`. | match_only_text |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.name.text | Multi-field of `user_agent.os.name`. | match_only_text |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |

