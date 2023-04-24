# Spring Boot integration

The Spring Boot integration is used to fetch observability data from [Spring Boot Actuator web endpoints](https://docs.spring.io/spring-boot/docs/2.6.3/actuator-api/htmlsingle/) and ingest it into Elasticsearch.

## Compatibility

This integration has been tested against Spring Boot v2.3.12.

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

### Troubleshooting

If **[Spring Boot] Audit Events panel** does not display older documents after upgrading to ``0.9.0`` or later versions, then this issue can be solved by reindexing the ``audit_events`` data stream's indices.

To reindex the data, the following steps must be performed.

1. Stop the data stream by going to `Integrations -> Spring Boot -> Integration policies` open the configuration of Spring Boot and disable the `Spring Boot Audit Events metrics` toggle to reindex ``audit_events`` data stream and save the integration.

2. Perform the following steps in the Dev tools.

```
POST _reindex
{
  "source": {
    "index": "<index_name>"
  },
  "dest": {
    "index": "temp_index"
  }
}
```
Example:
```
POST _reindex
{
  "source": {
    "index": "logs-spring_boot.audit_events-default"
  },
  "dest": {
    "index": "temp_index"
  }
}
```

```
DELETE /_data_stream/<data_stream>
```
Example:
```
DELETE /_data_stream/logs-spring_boot.audit_events-default
```

```
DELETE _index_template/<index_template>
```
Example:
```
DELETE _index_template/logs-spring_boot.audit_events
```
3. Go to `Integrations ->  Spring Boot  -> Settings` and click on `Reinstall Spring Boot`.

4. Perform the following steps in the Dev tools.

```
POST _reindex
{
  "source": {
    "index": "temp_index"
  },
  "dest": {
    "index": "<index_name>",
    "op_type": "create"

  }
}
```
Example:
```
POST _reindex
{
  "source": {
    "index": "temp_index"
  },
  "dest": {
    "index": "logs-spring_boot.audit_events-default",
    "op_type": "create"

  }
}
```

5. Verify data is reindexed completely.

6. Start the data stream by going to the `Integrations -> Spring Boot -> Integration policies` and open configuration of integration and enable the `Spring Boot Audit Events metrics` toggle.

7. Perform the following step in the Dev tools

```
DELETE temp_index
```

More details about reindexing can be found [here](https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-reindex.html).

## Logs

### Audit Events logs

This is the `audit_events` data stream.

- This data stream exposes audit events information for the current application.

An example event for `audit_events` looks as following:

```json
{
    "@timestamp": "2022-08-05T09:30:10.644Z",
    "agent": {
        "ephemeral_id": "575ffec5-bd74-4689-8baa-8486735193f3",
        "id": "3ab22ca1-4caf-465f-8789-2a45a81ed9b1",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.1.0"
    },
    "data_stream": {
        "dataset": "spring_boot.audit_events",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.5.1"
    },
    "elastic_agent": {
        "id": "3ab22ca1-4caf-465f-8789-2a45a81ed9b1",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "web",
        "created": "2022-08-05T09:30:10.644Z",
        "dataset": "spring_boot.audit_events",
        "ingested": "2022-08-05T09:30:14Z",
        "kind": "event",
        "module": "spring_boot",
        "type": "info"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "192.168.112.5"
        ],
        "mac": [
            "02:42:c0:a8:70:05"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.71.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.4 LTS (Focal Fossa)"
        }
    },
    "spring_boot": {
        "audit_events": {
            "data": {
                "remote_address": "192.168.144.2"
            },
            "document_id": "Es32QTyIFsbGsH5nlZQxBDYnf18=",
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
| spring_boot.audit_events.data.remote_address | Remote Address of the Spring Boot application user. | keyword |
| spring_boot.audit_events.data.session_id | Session ID of the Spring Boot application user. | keyword |
| spring_boot.audit_events.document_id | Unique document id generated by Elasticsearch. | keyword |
| spring_boot.audit_events.principal | Restricts the events to those with the given principal. | keyword |
| spring_boot.audit_events.type | Authentication type. | keyword |
| tags | List of keywords used to tag each event. | keyword |


### HTTP Trace logs

This is the `http_trace` data stream.

- This data stream displays HTTP trace information.

An example event for `http_trace` looks as following:

```json
{
    "@timestamp": "2022-08-05T09:31:44.895Z",
    "agent": {
        "ephemeral_id": "d55155ad-e1c4-4c29-a809-1d8b7b539e39",
        "id": "3ab22ca1-4caf-465f-8789-2a45a81ed9b1",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.1.0"
    },
    "data_stream": {
        "dataset": "spring_boot.http_trace",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.5.1"
    },
    "elastic_agent": {
        "id": "3ab22ca1-4caf-465f-8789-2a45a81ed9b1",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "web",
        "created": "2022-08-05T09:31:44.895Z",
        "dataset": "spring_boot.http_trace",
        "duration": 2,
        "ingested": "2022-08-05T09:31:48Z",
        "kind": "event",
        "module": "spring_boot",
        "type": "info"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "192.168.112.5"
        ],
        "mac": [
            "02:42:c0:a8:70:05"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.71.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.4 LTS (Focal Fossa)"
        }
    },
    "http": {
        "request": {
            "method": "GET",
            "referrer": "http://springboot:8090/actuator/info"
        },
        "response": {
            "status_code": 200
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
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| host.ip | Host ip addresses. | ip |
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| http.response.status_code | HTTP response status code. | long |
| spring_boot.http_trace.principal | Principal of the exchange. | keyword |
| spring_boot.http_trace.session | Session associated with the exchange. | keyword |
| tags | List of keywords used to tag each event. | keyword |


## Metrics

### Memory Metrics

This is the `memory` data stream.

- This data stream gives metrics related to heap and non-heap memory, buffer pool and manager.

An example event for `memory` looks as following:

```json
{
    "@timestamp": "2022-07-26T09:22:36.388Z",
    "agent": {
        "ephemeral_id": "8a027bae-63d7-4116-afe4-62859acce4cc",
        "id": "b82deaa8-f456-40b6-9265-b33c84cf0590",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.1.0"
    },
    "data_stream": {
        "dataset": "spring_boot.memory",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.5.1"
    },
    "elastic_agent": {
        "id": "b82deaa8-f456-40b6-9265-b33c84cf0590",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "web",
        "dataset": "spring_boot.memory",
        "duration": 469690835,
        "ingested": "2022-07-26T09:22:39Z",
        "kind": "metric",
        "module": "spring_boot",
        "type": "info"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "192.168.16.7"
        ],
        "mac": [
            "02:42:c0:a8:10:07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.71.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.3 LTS (Focal Fossa)"
        }
    },
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
            "heap": {
                "committed": 434634752,
                "init": 161480704,
                "max": 2289565696,
                "used": 151002384
            },
            "non_heap": {
                "committed": 63438848,
                "init": 2555904,
                "max": -1,
                "used": 57516496
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
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| spring_boot.memory.buffer_pool.direct.count | Count of direct buffer pool memory. | long |
| spring_boot.memory.buffer_pool.direct.total_capacity | Total capacity of direct buffer pool memory. | long |
| spring_boot.memory.buffer_pool.direct.used | Used memory of direct buffer pool. | long |
| spring_boot.memory.buffer_pool.mapped.count | Count of mapped buffer pool memory. | long |
| spring_boot.memory.buffer_pool.mapped.total_capacity | Total capacity of mapped buffer pool memory. | long |
| spring_boot.memory.buffer_pool.mapped.used | Used memory of mapped buffer pool. | long |
| spring_boot.memory.heap.committed | Committed heap memory usage of JVM. | long |
| spring_boot.memory.heap.init | Init heap memory usage of JVM. | long |
| spring_boot.memory.heap.max | Max heap memory usage of JVM. | long |
| spring_boot.memory.heap.used | Used heap memory usage of JVM. | long |
| spring_boot.memory.manager.code_cache.name | Name of the cacheManager to qualify the cache. | keyword |
| spring_boot.memory.manager.code_cache.valid | Validation of code cache. | boolean |
| spring_boot.memory.manager.metaspace.name | Name of the Metaspace Manager to qualify the cache. | keyword |
| spring_boot.memory.manager.metaspace.valid | Validation of metaspace manager. | boolean |
| spring_boot.memory.non_heap.committed | Committed non-heap memory usage of JVM. | long |
| spring_boot.memory.non_heap.init | Init non-heap memory usage of JVM. | long |
| spring_boot.memory.non_heap.max | Max non-heap memory usage of JVM. | long |
| spring_boot.memory.non_heap.used | Used non-heap memory usage of JVM. | long |


### Threading Metrics

This is the `threading` data stream.

- This data stream gives metrics related to thread allocations, monitoring and CPU times.

An example event for `threading` looks as following:

```json
{
    "@timestamp": "2022-07-26T09:23:23.966Z",
    "agent": {
        "ephemeral_id": "f5e26cd6-fcf9-4508-af92-e62d403c37a0",
        "id": "b82deaa8-f456-40b6-9265-b33c84cf0590",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.1.0"
    },
    "data_stream": {
        "dataset": "spring_boot.threading",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.5.1"
    },
    "elastic_agent": {
        "id": "b82deaa8-f456-40b6-9265-b33c84cf0590",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "web",
        "dataset": "spring_boot.threading",
        "duration": 96299770,
        "ingested": "2022-07-26T09:23:27Z",
        "kind": "metric",
        "module": "spring_boot",
        "type": "info"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "192.168.16.7"
        ],
        "mac": [
            "02:42:c0:a8:10:07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.71.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.3 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "jmx",
        "period": 60000
    },
    "service": {
        "address": "http://springboot:8090/actuator/jolokia",
        "type": "jolokia"
    },
    "spring_boot": {
        "threading": {
            "threads": {
                "count": 20,
                "current": {
                    "allocated_bytes": 540520,
                    "time": {
                        "cpu": 281828822,
                        "user": 280000000
                    }
                },
                "daemon": 16,
                "started": 23
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
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| spring_boot.threading.threads.count | Current number of live threads including both daemon and non-daemon threads. | long |
| spring_boot.threading.threads.current.allocated_bytes | Allocated bytes for the current thread. | double |
| spring_boot.threading.threads.current.time.cpu | CPU time for the current thread in nanoseconds. | long |
| spring_boot.threading.threads.current.time.user | User time for the current thread. | long |
| spring_boot.threading.threads.daemon | Current number of live daemon threads. | long |
| spring_boot.threading.threads.started | Total number of threads created and also started since the Java virtual machine started. | long |


### GC Metrics

This is the `gc` data stream.

- This data stream gives metrics related to Garbage Collector (GC) Memory.

An example event for `gc` looks as following:

```json
{
    "@timestamp": "2022-07-26T09:21:00.452Z",
    "agent": {
        "ephemeral_id": "db88f994-5a48-40d9-ad03-6b590820ed0b",
        "id": "b82deaa8-f456-40b6-9265-b33c84cf0590",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.1.0"
    },
    "data_stream": {
        "dataset": "spring_boot.gc",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.5.1"
    },
    "elastic_agent": {
        "id": "b82deaa8-f456-40b6-9265-b33c84cf0590",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "web",
        "dataset": "spring_boot.gc",
        "duration": 103569878,
        "ingested": "2022-07-26T09:21:03Z",
        "kind": "metric",
        "module": "spring_boot",
        "type": "info"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "192.168.16.7"
        ],
        "mac": [
            "02:42:c0:a8:10:07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.71.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.3 LTS (Focal Fossa)"
        }
    },
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
            "last_info": {
                "id": 2,
                "memory_usage": {
                    "after": {
                        "code_cache": {
                            "committed": 14155776,
                            "init": 2555904,
                            "max": 251658240,
                            "used": 14077312
                        },
                        "compressed_class_space": {
                            "committed": 4980736,
                            "init": 0,
                            "max": 1073741824,
                            "used": 4442832
                        },
                        "metaspace": {
                            "committed": 36265984,
                            "init": 0,
                            "max": -1,
                            "used": 33744032
                        },
                        "ps_eden_space": {
                            "committed": 323485696,
                            "init": 40894464,
                            "max": 832045056,
                            "used": 0
                        },
                        "ps_old_gen": {
                            "committed": 100663296,
                            "init": 108003328,
                            "max": 1717043200,
                            "used": 15834712
                        },
                        "ps_survivor_space": {
                            "committed": 12582912,
                            "init": 6291456,
                            "max": 12582912,
                            "used": 0
                        }
                    },
                    "before": {
                        "code_cache": {
                            "committed": 14155776,
                            "init": 2555904,
                            "max": 251658240,
                            "used": 14077312
                        },
                        "compressed_class_space": {
                            "committed": 4980736,
                            "init": 0,
                            "max": 1073741824,
                            "used": 4442832
                        },
                        "metaspace": {
                            "committed": 36265984,
                            "init": 0,
                            "max": -1,
                            "used": 33744032
                        },
                        "ps_eden_space": {
                            "committed": 323485696,
                            "init": 40894464,
                            "max": 832045056,
                            "used": 0
                        },
                        "ps_old_gen": {
                            "committed": 70778880,
                            "init": 108003328,
                            "max": 1717043200,
                            "used": 10811944
                        },
                        "ps_survivor_space": {
                            "committed": 12582912,
                            "init": 6291456,
                            "max": 12582912,
                            "used": 10582400
                        }
                    }
                },
                "thread_count": 10,
                "time": {
                    "duration": 53,
                    "end": 3654,
                    "start": 3601
                }
            },
            "name": "PS MarkSweep"
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
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| spring_boot.gc.last_info.id | ID of the GC. | long |
| spring_boot.gc.last_info.memory_usage.after.code_cache.committed | Committed memory of the code cache memory pool after GC started. | long |
| spring_boot.gc.last_info.memory_usage.after.code_cache.init | Init memory of the code cache memory pool after GC started. | long |
| spring_boot.gc.last_info.memory_usage.after.code_cache.max | Max memory of the code cache memory pool after GC started. | long |
| spring_boot.gc.last_info.memory_usage.after.code_cache.used | Used memory of the code cache memory pool after GC started. | long |
| spring_boot.gc.last_info.memory_usage.after.compressed_class_space.committed | Committed memory of the compressed class space memory pool after GC started. | long |
| spring_boot.gc.last_info.memory_usage.after.compressed_class_space.init | Init memory of the compressed class space memory pool after GC started. | long |
| spring_boot.gc.last_info.memory_usage.after.compressed_class_space.max | Max memory of the compressed class space memory pool after GC started. | long |
| spring_boot.gc.last_info.memory_usage.after.compressed_class_space.used | Used memory of the compressed class space memory pool after GC started. | long |
| spring_boot.gc.last_info.memory_usage.after.metaspace.committed | Committed memory of the metaspace memory pool after GC started. | long |
| spring_boot.gc.last_info.memory_usage.after.metaspace.init | Init memory of the metaspace memory pool after GC started. | long |
| spring_boot.gc.last_info.memory_usage.after.metaspace.max | Max memory of the metaspace memory pool after GC started. | long |
| spring_boot.gc.last_info.memory_usage.after.metaspace.used | Used memory of the metaspace memory pool after GC started. | long |
| spring_boot.gc.last_info.memory_usage.after.ps_eden_space.committed | Committed memory of the PS Eden Space memory pool after GC started. | long |
| spring_boot.gc.last_info.memory_usage.after.ps_eden_space.init | Init memory of the PS Eden Space memory pool after GC started. | long |
| spring_boot.gc.last_info.memory_usage.after.ps_eden_space.max | Max memory of the PS Eden Space memory pool after GC started. | long |
| spring_boot.gc.last_info.memory_usage.after.ps_eden_space.used | Used memory of the PS Eden Space memory pool after GC started. | long |
| spring_boot.gc.last_info.memory_usage.after.ps_old_gen.committed | Committed memory of the PS Old Gen memory pool after GC started. | long |
| spring_boot.gc.last_info.memory_usage.after.ps_old_gen.init | Init memory of the PS Old Gen memory pool after GC started. | long |
| spring_boot.gc.last_info.memory_usage.after.ps_old_gen.max | Max memory of the PS Old Gen memory pool after GC started. | long |
| spring_boot.gc.last_info.memory_usage.after.ps_old_gen.used | Used memory of the PS Old Gen memory pool after GC started. | long |
| spring_boot.gc.last_info.memory_usage.after.ps_survivor_space.committed | Committed memory of the PS Survivor Space memory pool after GC started. | long |
| spring_boot.gc.last_info.memory_usage.after.ps_survivor_space.init | Init memory of the PS Survivor Space memory pool after GC started. | long |
| spring_boot.gc.last_info.memory_usage.after.ps_survivor_space.max | Max memory of the PS Survivor Space memory pool after GC started. | long |
| spring_boot.gc.last_info.memory_usage.after.ps_survivor_space.used | Used memory of the PS Survivor Space memory pool after GC started. | long |
| spring_boot.gc.last_info.memory_usage.before.code_cache.committed | Committed memory of the code cache memory pool before GC starts. | long |
| spring_boot.gc.last_info.memory_usage.before.code_cache.init | Init memory of the code cache memory pool before GC starts. | long |
| spring_boot.gc.last_info.memory_usage.before.code_cache.max | Max memory of the code cache memory pool before GC starts. | long |
| spring_boot.gc.last_info.memory_usage.before.code_cache.used | Used memory of the code cache memory pool before GC starts. | long |
| spring_boot.gc.last_info.memory_usage.before.compressed_class_space.committed | Committed memory of the compressed class space memory pool before GC starts. | long |
| spring_boot.gc.last_info.memory_usage.before.compressed_class_space.init | Init memory of the compressed class space memory pool before GC starts. | long |
| spring_boot.gc.last_info.memory_usage.before.compressed_class_space.max | Max memory of the compressed class space memory pool before GC starts. | long |
| spring_boot.gc.last_info.memory_usage.before.compressed_class_space.used | Used memory of the compressed class space memory pool before GC starts. | long |
| spring_boot.gc.last_info.memory_usage.before.metaspace.committed | Committed memory of the metaspace memory pool before GC starts. | long |
| spring_boot.gc.last_info.memory_usage.before.metaspace.init | Init memory of the metaspace memory pool before GC starts. | long |
| spring_boot.gc.last_info.memory_usage.before.metaspace.max | Max memory of the metaspace memory pool before GC starts. | long |
| spring_boot.gc.last_info.memory_usage.before.metaspace.used | Used memory of the metaspace memory pool before GC starts. | long |
| spring_boot.gc.last_info.memory_usage.before.ps_eden_space.committed | Committed memory of the PS Eden Space memory pool before GC starts. | long |
| spring_boot.gc.last_info.memory_usage.before.ps_eden_space.init | Init memory of the PS Eden Space memory pool before GC starts. | long |
| spring_boot.gc.last_info.memory_usage.before.ps_eden_space.max | Max memory of the PS Eden Space memory pool before GC starts. | long |
| spring_boot.gc.last_info.memory_usage.before.ps_eden_space.used | Used memory of the PS Eden Space memory pool before GC starts. | long |
| spring_boot.gc.last_info.memory_usage.before.ps_old_gen.committed | Committed memory of the PS Old Gen memory pool before GC starts. | long |
| spring_boot.gc.last_info.memory_usage.before.ps_old_gen.init | Init memory of the PS Old Gen memory pool before GC starts. | long |
| spring_boot.gc.last_info.memory_usage.before.ps_old_gen.max | Max memory of the PS Old Gen memory pool before GC starts. | long |
| spring_boot.gc.last_info.memory_usage.before.ps_old_gen.used | Used memory of the PS Old Gen memory pool before GC starts. | long |
| spring_boot.gc.last_info.memory_usage.before.ps_survivor_space.committed | Committed memory of the PS Survivor Space memory pool before GC starts. | long |
| spring_boot.gc.last_info.memory_usage.before.ps_survivor_space.init | Init memory of the PS Survivor Space memory pool before GC starts. | long |
| spring_boot.gc.last_info.memory_usage.before.ps_survivor_space.max | Max memory of the PS Survivor Space memory pool before GC starts. | long |
| spring_boot.gc.last_info.memory_usage.before.ps_survivor_space.used | Used memory of the PS Survivor Space memory pool before GC starts. | long |
| spring_boot.gc.last_info.thread_count | Thread count of the GC. | long |
| spring_boot.gc.last_info.time.duration | Elapsed time of the GC in milliseconds. | long |
| spring_boot.gc.last_info.time.end | End time of the GC. | long |
| spring_boot.gc.last_info.time.start | Start time of the GC. | long |
| spring_boot.gc.name | Name of the GC. | keyword |

