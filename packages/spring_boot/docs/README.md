# Spring Boot integration

## Overview

The Spring Boot integration is used to fetch observability data from [Spring Boot Actuator web endpoints](https://docs.spring.io/spring-boot/docs/2.6.3/actuator-api/htmlsingle/) and ingest it into Elasticsearch.

Use the Spring Boot integration to:

- Collect logs related to audit events, HTTP trace, and metrics related to garbage collection(gc), memory, and threading.
- Create visualizations to monitor, measure, and analyze usage trends and key data, deriving business insights.
- Create alerts to reduce the MTTD and MTTR by referencing relevant logs when troubleshooting an issue.

## Data streams

The Spring Boot integration collects logs and metrics data.

Logs help you keep a record of events that occur on your machine. The Log data streams collected by Spring Boot integration are `auditevents` and `httptrace`, allowing users to track authentication events, HTTP request and response details, enabling comprehensive monitoring and security auditing.

Metrics provide insight into the statistics of Spring Boot. The Metrics data streams collected by the Spring Boot integration include auditevents, gc, httptrace, memory, and threading, enabling users to monitor and troubleshoot the performance of Spring Boot instances.

Data streams:
- `auditevents`: Collects information related to the authentication status, remote address, document ID and principal.
- `gc`: Collects information related to the GC collector name, memory usage before and after collection, thread count, and time metrics.
- `httptrace`: Collects information related to the http requests, status response, principal and session details.
- `memory`: Collects information related to the heap and non-heap memory, buffer pool and manager.
- `threading`: Collects information related to the thread allocations, monitoring and CPU times.

Note:
- Users can monitor and view the logs inside the ingested documents for Spring Boot in the `logs-*` index pattern from `Discover`, while for metrics, the index pattern is `metrics-*`.

## Compatibility

This integration has been tested against Spring Boot 4.0.6 running on JDK 25. It remains compatible with Spring Boot 2.x for the `auditevents`, `gc`, `memory`, and `threading` data streams. For `httptrace`, the actuator endpoint was renamed in Spring Boot 3.0 to `httpexchanges`; the integration defaults to the new endpoint, and the data stream exposes `HTTP Exchanges path` and `Response split target` inputs that can be set back to `/actuator/httptrace` and `body.traces` respectively to continue collecting from Spring Boot 2.x.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended or self-manage the Elastic Stack on your own hardware.

In order to ingest data from Spring Boot:
- You must know the host for Spring Boot application, add that host while configuring the integration package.
- Add the path for jolokia (the default is `/actuator/jolokia`).
- Spring-boot-actuator module provides all Spring Boot's production-ready features. You also need to add the following dependency to the `pom.xml` file:
```
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-actuator</artifactId>
</dependency>
```
- For access of jolokia add the appropriate dependency in the `pom.xml` of the Spring Boot application:
  - Spring Boot 2.x:
    ```
    <dependency>
        <groupId>org.jolokia</groupId>
        <artifactId>jolokia-core</artifactId>
    </dependency>
    ```
  - Spring Boot 3.x / 4.x (Jolokia auto-configuration was removed from Spring Boot 3.0; use the dedicated Jolokia starter from Jolokia 2.5+):
    ```
    <dependency>
        <groupId>org.jolokia</groupId>
        <artifactId>jolokia-support-springboot</artifactId>
    </dependency>
    ```
- To expose HTTP request/response exchanges:
  - Spring Boot 2.x: expose `httptrace` and register an [`InMemoryHttpTraceRepository`](https://docs.spring.io/spring-boot/docs/2.7.x/api/org/springframework/boot/actuate/trace/http/InMemoryHttpTraceRepository.html) bean.
  - Spring Boot 3.x / 4.x: expose `httpexchanges`, set `management.httpexchanges.recording.enabled=true`, and register an [`InMemoryHttpExchangeRepository`](https://docs.spring.io/spring-boot/api/org/springframework/boot/actuate/web/exchanges/InMemoryHttpExchangeRepository.html) bean.
- To expose `Audit Events` metrics the following class can be used: [InMemoryAuditEventRepository](https://docs.spring.io/spring-boot/docs/current/api/org/springframework/boot/actuate/audit/InMemoryAuditEventRepository.html).

## Setup

For step-by-step instructions on how to set up an integration, see the [Getting Started](https://www.elastic.co/guide/en/starting-with-the-elasticsearch-platform-and-its-solutions/current/getting-started-observability.html) guide.

## Validation

After the integration is successfully configured, click on the *Assets* tab of the Spring Boot Integration to display the available dashboards. Select the dashboard for your configured data stream, which should be populated with the required data.

## Troubleshooting

- If **[Spring Boot] Audit Events panel** does not display older documents after upgrading to ``0.9.0`` or later versions, this issue can be resolved by reindexing the ``Audit Events`` data stream.
- If `host.ip` appears conflicted under the ``logs-*`` data view, this issue can be resolved by [reindexing](https://www.elastic.co/guide/en/elasticsearch/reference/current/use-a-data-stream.html#reindex-with-a-data-stream) the ``Audit Events`` data stream. 
- If `host.ip` appears conflicted under the ``metrics-*`` data view, this issue can be resolved by [reindexing](https://www.elastic.co/guide/en/elasticsearch/reference/current/use-a-data-stream.html#reindex-with-a-data-stream) the ``Garbage Collector``, ``Memory`` and ``Threading`` data stream.

## Logs

### Audit Events logs

This is the `audit_events` data stream.

- This data stream exposes audit events information for the current application.

An example event for `audit_events` looks as following:

```json
{
    "@timestamp": "2026-05-28T22:40:25.209Z",
    "agent": {
        "ephemeral_id": "69620662-1ab0-4d61-ad55-5111588db240",
        "id": "c93fa949-a34f-413f-9448-cdc70b43b908",
        "name": "elastic-agent-51266",
        "type": "filebeat",
        "version": "9.3.3"
    },
    "data_stream": {
        "dataset": "spring_boot.audit_events",
        "namespace": "14359",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "c93fa949-a34f-413f-9448-cdc70b43b908",
        "snapshot": false,
        "version": "9.3.3"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "created": "2026-05-28T22:40:25.209Z",
        "dataset": "spring_boot.audit_events",
        "ingested": "2026-05-28T22:40:28Z",
        "kind": "event",
        "module": "spring_boot",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "elastic-agent-51266",
        "ip": [
            "172.19.0.2",
            "172.18.0.7"
        ],
        "mac": [
            "16-64-2B-B6-87-B9",
            "EE-78-1C-6F-5E-D2"
        ],
        "name": "elastic-agent-51266",
        "os": {
            "kernel": "6.8.0-64-generic",
            "name": "Wolfi",
            "platform": "wolfi",
            "type": "linux",
            "version": "20230201"
        }
    },
    "spring_boot": {
        "audit_events": {
            "document_id": "pqq07k9MHdeXOo2Ow4y8zJXnn+o=",
            "principal": "actuator",
            "type": "AUTHENTICATION_SUCCESS"
        }
    },
    "tags": [
        "spring_boot.audit_events.metrics"
    ]
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| spring_boot.audit_events.data.remote_address | Remote Address of the Spring Boot application user. | keyword |
| spring_boot.audit_events.data.session_id | Session ID of the Spring Boot application user. | keyword |
| spring_boot.audit_events.document_id | Unique document id generated by Elasticsearch. | keyword |
| spring_boot.audit_events.principal | Restricts the events to those with the given principal. | keyword |
| spring_boot.audit_events.type | Authentication type. | keyword |


### HTTP Trace logs

This is the `http_trace` data stream.

- This data stream displays HTTP trace information.

An example event for `http_trace` looks as following:

```json
{
    "@timestamp": "2026-05-28T22:47:48.217Z",
    "agent": {
        "ephemeral_id": "1fd9ff5c-9f17-46d1-9d29-e05784e83488",
        "id": "b2d9f05f-871b-4ae0-83d2-f2dc00fa4144",
        "name": "elastic-agent-71463",
        "type": "filebeat",
        "version": "9.3.3"
    },
    "data_stream": {
        "dataset": "spring_boot.http_trace",
        "namespace": "43580",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "b2d9f05f-871b-4ae0-83d2-f2dc00fa4144",
        "snapshot": false,
        "version": "9.3.3"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "created": "2026-05-28T22:47:48.217Z",
        "dataset": "spring_boot.http_trace",
        "duration": 3,
        "ingested": "2026-05-28T22:47:51Z",
        "kind": "event",
        "module": "spring_boot",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "elastic-agent-71463",
        "mac": [
            "06-7C-2B-86-84-E1",
            "26-D1-75-F3-43-20"
        ],
        "name": "elastic-agent-71463",
        "os": {
            "kernel": "6.8.0-64-generic",
            "name": "Wolfi",
            "platform": "wolfi",
            "type": "linux",
            "version": "20230201"
        }
    },
    "http": {
        "request": {
            "method": "GET",
            "referrer": "http://springboot:8090/actuator/health"
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

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| spring_boot.http_trace.principal | Principal of the exchange. | keyword |
| spring_boot.http_trace.session | Session associated with the exchange. | keyword |


## Metrics

### Memory Metrics

This is the `memory` data stream.

- This data stream gives metrics related to heap and non-heap memory, buffer pool and manager.

An example event for `memory` looks as following:

```json
{
    "@timestamp": "2026-05-28T22:45:20.870Z",
    "agent": {
        "ephemeral_id": "7f501985-d7fa-476b-bdc5-376621a93d74",
        "id": "dd183e5b-8a17-47e6-a3ec-863a3fb28156",
        "name": "elastic-agent-57840",
        "type": "metricbeat",
        "version": "9.3.3"
    },
    "data_stream": {
        "dataset": "spring_boot.memory",
        "namespace": "21944",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "dd183e5b-8a17-47e6-a3ec-863a3fb28156",
        "snapshot": false,
        "version": "9.3.3"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "dataset": "spring_boot.memory",
        "duration": 415374946,
        "ingested": "2026-05-28T22:45:22Z",
        "kind": "metric",
        "module": "spring_boot",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "elastic-agent-57840",
        "ip": [
            "172.19.0.2",
            "172.18.0.7"
        ],
        "mac": [
            "3A-FF-3F-8B-5A-BD",
            "56-15-DC-31-9E-CF"
        ],
        "name": "elastic-agent-57840",
        "os": {
            "family": "",
            "kernel": "6.8.0-64-generic",
            "name": "Wolfi",
            "platform": "wolfi",
            "type": "linux",
            "version": "20230201"
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
                "committed": 77594624,
                "init": 262144000,
                "max": 4183818240,
                "used": 59466880
            },
            "non_heap": {
                "committed": 70451200,
                "init": 7667712,
                "max": -1,
                "used": 67580248
            }
        }
    },
    "tags": [
        "spring_boot.memory.metrics"
    ]
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
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
    "@timestamp": "2026-05-28T22:46:09.767Z",
    "agent": {
        "ephemeral_id": "066facbc-aa5d-40be-a04e-8d203df24ca8",
        "id": "6b846525-96ba-41f5-8007-d869506d8722",
        "name": "elastic-agent-12420",
        "type": "metricbeat",
        "version": "9.3.3"
    },
    "data_stream": {
        "dataset": "spring_boot.threading",
        "namespace": "81161",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "6b846525-96ba-41f5-8007-d869506d8722",
        "snapshot": false,
        "version": "9.3.3"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "dataset": "spring_boot.threading",
        "duration": 147974384,
        "ingested": "2026-05-28T22:46:12Z",
        "kind": "metric",
        "module": "spring_boot",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "elastic-agent-12420",
        "ip": [
            "172.19.0.2",
            "172.18.0.7"
        ],
        "mac": [
            "16-51-4B-13-52-E0",
            "FA-65-2E-EA-15-9D"
        ],
        "name": "elastic-agent-12420",
        "os": {
            "family": "",
            "kernel": "6.8.0-64-generic",
            "name": "Wolfi",
            "platform": "wolfi",
            "type": "linux",
            "version": "20230201"
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
                "count": 26,
                "current": {
                    "allocated_bytes": 25032448,
                    "time": {
                        "cpu": 126947117,
                        "user": 110000000
                    }
                },
                "daemon": 22,
                "started": 29
            }
        }
    },
    "tags": [
        "spring_boot.threading.metrics"
    ]
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
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
    "@timestamp": "2026-05-28T22:41:15.857Z",
    "agent": {
        "ephemeral_id": "f45626b7-9309-4973-a16f-1d125baf2b79",
        "id": "d30ad1cc-17f6-48cd-827c-3813edc87d08",
        "name": "elastic-agent-38595",
        "type": "metricbeat",
        "version": "9.3.3"
    },
    "data_stream": {
        "dataset": "spring_boot.gc",
        "namespace": "30691",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "d30ad1cc-17f6-48cd-827c-3813edc87d08",
        "snapshot": false,
        "version": "9.3.3"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "dataset": "spring_boot.gc",
        "duration": 157212383,
        "ingested": "2026-05-28T22:41:17Z",
        "kind": "metric",
        "module": "spring_boot",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "elastic-agent-38595",
        "ip": [
            "172.19.0.2",
            "172.18.0.7"
        ],
        "mac": [
            "5E-87-BB-AF-C5-55",
            "CE-FE-C8-29-78-95"
        ],
        "name": "elastic-agent-38595",
        "os": {
            "family": "",
            "kernel": "6.8.0-64-generic",
            "name": "Wolfi",
            "platform": "wolfi",
            "type": "linux",
            "version": "20230201"
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
                "id": 10,
                "memory_usage": {
                    "after": {
                        "compressed_class_space": {
                            "committed": 6619136,
                            "init": 0,
                            "max": 1073741824,
                            "used": 6361448
                        },
                        "g1_eden_space": {
                            "committed": 41943040,
                            "init": 14680064,
                            "max": -1,
                            "used": 0
                        },
                        "g1_old_gen": {
                            "committed": 31457280,
                            "init": 247463936,
                            "max": 4183818240,
                            "used": 20239776
                        },
                        "g1_survivor_space": {
                            "committed": 4194304,
                            "init": 0,
                            "max": -1,
                            "used": 4151392
                        },
                        "metaspace": {
                            "committed": 47579136,
                            "init": 0,
                            "max": -1,
                            "used": 47018160
                        }
                    },
                    "before": {
                        "compressed_class_space": {
                            "committed": 6619136,
                            "init": 0,
                            "max": 1073741824,
                            "used": 6361448
                        },
                        "g1_eden_space": {
                            "committed": 39845888,
                            "init": 14680064,
                            "max": -1,
                            "used": 37748736
                        },
                        "g1_old_gen": {
                            "committed": 31457280,
                            "init": 247463936,
                            "max": 4183818240,
                            "used": 18147032
                        },
                        "g1_survivor_space": {
                            "committed": 6291456,
                            "init": 0,
                            "max": -1,
                            "used": 5434448
                        },
                        "metaspace": {
                            "committed": 47579136,
                            "init": 0,
                            "max": -1,
                            "used": 47018160
                        }
                    }
                },
                "thread_count": 5,
                "time": {
                    "duration": 6,
                    "end": 4326,
                    "start": 4320
                }
            },
            "name": "G1 Young Generation"
        }
    },
    "tags": [
        "spring_boot.gc.metrics"
    ]
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| spring_boot.gc.last_info.id | ID of the GC. | long |  |
| spring_boot.gc.last_info.memory_usage.after.code_cache.committed | Committed memory of the code cache memory pool after GC started. | long | byte |
| spring_boot.gc.last_info.memory_usage.after.code_cache.init | Init memory of the code cache memory pool after GC started. | long | byte |
| spring_boot.gc.last_info.memory_usage.after.code_cache.max | Max memory of the code cache memory pool after GC started. | long | byte |
| spring_boot.gc.last_info.memory_usage.after.code_cache.used | Used memory of the code cache memory pool after GC started. | long | byte |
| spring_boot.gc.last_info.memory_usage.after.compressed_class_space.committed | Committed memory of the compressed class space memory pool after GC started. | long | byte |
| spring_boot.gc.last_info.memory_usage.after.compressed_class_space.init | Init memory of the compressed class space memory pool after GC started. | long | byte |
| spring_boot.gc.last_info.memory_usage.after.compressed_class_space.max | Max memory of the compressed class space memory pool after GC started. | long | byte |
| spring_boot.gc.last_info.memory_usage.after.compressed_class_space.used | Used memory of the compressed class space memory pool after GC started. | long | byte |
| spring_boot.gc.last_info.memory_usage.after.g1_eden_space.committed | Committed memory of the G1 Eden Space memory pool after GC started. | long | byte |
| spring_boot.gc.last_info.memory_usage.after.g1_eden_space.init | Init memory of the G1 Eden Space memory pool after GC started. | long | byte |
| spring_boot.gc.last_info.memory_usage.after.g1_eden_space.max | Max memory of the G1 Eden Space memory pool after GC started. | long | byte |
| spring_boot.gc.last_info.memory_usage.after.g1_eden_space.used | Used memory of the G1 Eden Space memory pool after GC started. | long | byte |
| spring_boot.gc.last_info.memory_usage.after.g1_old_gen.committed | Committed memory of the G1 Old Gen memory pool after GC started. | long | byte |
| spring_boot.gc.last_info.memory_usage.after.g1_old_gen.init | Init memory of the G1 Old Gen memory pool after GC started. | long | byte |
| spring_boot.gc.last_info.memory_usage.after.g1_old_gen.max | Max memory of the G1 Old Gen memory pool after GC started. | long | byte |
| spring_boot.gc.last_info.memory_usage.after.g1_old_gen.used | Used memory of the G1 Old Gen memory pool after GC started. | long | byte |
| spring_boot.gc.last_info.memory_usage.after.g1_survivor_space.committed | Committed memory of the G1 Survivor Space memory pool after GC started. | long | byte |
| spring_boot.gc.last_info.memory_usage.after.g1_survivor_space.init | Init memory of the G1 Survivor Space memory pool after GC started. | long | byte |
| spring_boot.gc.last_info.memory_usage.after.g1_survivor_space.max | Max memory of the G1 Survivor Space memory pool after GC started. | long | byte |
| spring_boot.gc.last_info.memory_usage.after.g1_survivor_space.used | Used memory of the G1 Survivor Space memory pool after GC started. | long | byte |
| spring_boot.gc.last_info.memory_usage.after.metaspace.committed | Committed memory of the metaspace memory pool after GC started. | long | byte |
| spring_boot.gc.last_info.memory_usage.after.metaspace.init | Init memory of the metaspace memory pool after GC started. | long | byte |
| spring_boot.gc.last_info.memory_usage.after.metaspace.max | Max memory of the metaspace memory pool after GC started. | long | byte |
| spring_boot.gc.last_info.memory_usage.after.metaspace.used | Used memory of the metaspace memory pool after GC started. | long | byte |
| spring_boot.gc.last_info.memory_usage.after.ps_eden_space.committed | Committed memory of the PS Eden Space memory pool after GC started. | long | byte |
| spring_boot.gc.last_info.memory_usage.after.ps_eden_space.init | Init memory of the PS Eden Space memory pool after GC started. | long | byte |
| spring_boot.gc.last_info.memory_usage.after.ps_eden_space.max | Max memory of the PS Eden Space memory pool after GC started. | long | byte |
| spring_boot.gc.last_info.memory_usage.after.ps_eden_space.used | Used memory of the PS Eden Space memory pool after GC started. | long | byte |
| spring_boot.gc.last_info.memory_usage.after.ps_old_gen.committed | Committed memory of the PS Old Gen memory pool after GC started. | long | byte |
| spring_boot.gc.last_info.memory_usage.after.ps_old_gen.init | Init memory of the PS Old Gen memory pool after GC started. | long | byte |
| spring_boot.gc.last_info.memory_usage.after.ps_old_gen.max | Max memory of the PS Old Gen memory pool after GC started. | long | byte |
| spring_boot.gc.last_info.memory_usage.after.ps_old_gen.used | Used memory of the PS Old Gen memory pool after GC started. | long | byte |
| spring_boot.gc.last_info.memory_usage.after.ps_survivor_space.committed | Committed memory of the PS Survivor Space memory pool after GC started. | long | byte |
| spring_boot.gc.last_info.memory_usage.after.ps_survivor_space.init | Init memory of the PS Survivor Space memory pool after GC started. | long | byte |
| spring_boot.gc.last_info.memory_usage.after.ps_survivor_space.max | Max memory of the PS Survivor Space memory pool after GC started. | long | byte |
| spring_boot.gc.last_info.memory_usage.after.ps_survivor_space.used | Used memory of the PS Survivor Space memory pool after GC started. | long | byte |
| spring_boot.gc.last_info.memory_usage.before.code_cache.committed | Committed memory of the code cache memory pool before GC starts. | long | byte |
| spring_boot.gc.last_info.memory_usage.before.code_cache.init | Init memory of the code cache memory pool before GC starts. | long | byte |
| spring_boot.gc.last_info.memory_usage.before.code_cache.max | Max memory of the code cache memory pool before GC starts. | long | byte |
| spring_boot.gc.last_info.memory_usage.before.code_cache.used | Used memory of the code cache memory pool before GC starts. | long | byte |
| spring_boot.gc.last_info.memory_usage.before.compressed_class_space.committed | Committed memory of the compressed class space memory pool before GC starts. | long | byte |
| spring_boot.gc.last_info.memory_usage.before.compressed_class_space.init | Init memory of the compressed class space memory pool before GC starts. | long | byte |
| spring_boot.gc.last_info.memory_usage.before.compressed_class_space.max | Max memory of the compressed class space memory pool before GC starts. | long | byte |
| spring_boot.gc.last_info.memory_usage.before.compressed_class_space.used | Used memory of the compressed class space memory pool before GC starts. | long | byte |
| spring_boot.gc.last_info.memory_usage.before.g1_eden_space.committed | Committed memory of the G1 Eden Space memory pool before GC starts. | long | byte |
| spring_boot.gc.last_info.memory_usage.before.g1_eden_space.init | Init memory of the G1 Eden Space memory pool before GC starts. | long | byte |
| spring_boot.gc.last_info.memory_usage.before.g1_eden_space.max | Max memory of the G1 Eden Space memory pool before GC starts. | long | byte |
| spring_boot.gc.last_info.memory_usage.before.g1_eden_space.used | Used memory of the G1 Eden Space memory pool before GC starts. | long | byte |
| spring_boot.gc.last_info.memory_usage.before.g1_old_gen.committed | Committed memory of the G1 Old Gen memory pool before GC starts. | long | byte |
| spring_boot.gc.last_info.memory_usage.before.g1_old_gen.init | Init memory of the G1 Old Gen memory pool before GC starts. | long | byte |
| spring_boot.gc.last_info.memory_usage.before.g1_old_gen.max | Max memory of the G1 Old Gen memory pool before GC starts. | long | byte |
| spring_boot.gc.last_info.memory_usage.before.g1_old_gen.used | Used memory of the G1 Old Gen memory pool before GC starts. | long | byte |
| spring_boot.gc.last_info.memory_usage.before.g1_survivor_space.committed | Committed memory of the G1 Survivor Space memory pool before GC starts. | long | byte |
| spring_boot.gc.last_info.memory_usage.before.g1_survivor_space.init | Init memory of the G1 Survivor Space memory pool before GC starts. | long | byte |
| spring_boot.gc.last_info.memory_usage.before.g1_survivor_space.max | Max memory of the G1 Survivor Space memory pool before GC starts. | long | byte |
| spring_boot.gc.last_info.memory_usage.before.g1_survivor_space.used | Used memory of the G1 Survivor Space memory pool before GC starts. | long | byte |
| spring_boot.gc.last_info.memory_usage.before.metaspace.committed | Committed memory of the metaspace memory pool before GC starts. | long | byte |
| spring_boot.gc.last_info.memory_usage.before.metaspace.init | Init memory of the metaspace memory pool before GC starts. | long | byte |
| spring_boot.gc.last_info.memory_usage.before.metaspace.max | Max memory of the metaspace memory pool before GC starts. | long | byte |
| spring_boot.gc.last_info.memory_usage.before.metaspace.used | Used memory of the metaspace memory pool before GC starts. | long | byte |
| spring_boot.gc.last_info.memory_usage.before.ps_eden_space.committed | Committed memory of the PS Eden Space memory pool before GC starts. | long | byte |
| spring_boot.gc.last_info.memory_usage.before.ps_eden_space.init | Init memory of the PS Eden Space memory pool before GC starts. | long | byte |
| spring_boot.gc.last_info.memory_usage.before.ps_eden_space.max | Max memory of the PS Eden Space memory pool before GC starts. | long | byte |
| spring_boot.gc.last_info.memory_usage.before.ps_eden_space.used | Used memory of the PS Eden Space memory pool before GC starts. | long | byte |
| spring_boot.gc.last_info.memory_usage.before.ps_old_gen.committed | Committed memory of the PS Old Gen memory pool before GC starts. | long | byte |
| spring_boot.gc.last_info.memory_usage.before.ps_old_gen.init | Init memory of the PS Old Gen memory pool before GC starts. | long | byte |
| spring_boot.gc.last_info.memory_usage.before.ps_old_gen.max | Max memory of the PS Old Gen memory pool before GC starts. | long | byte |
| spring_boot.gc.last_info.memory_usage.before.ps_old_gen.used | Used memory of the PS Old Gen memory pool before GC starts. | long | byte |
| spring_boot.gc.last_info.memory_usage.before.ps_survivor_space.committed | Committed memory of the PS Survivor Space memory pool before GC starts. | long | byte |
| spring_boot.gc.last_info.memory_usage.before.ps_survivor_space.init | Init memory of the PS Survivor Space memory pool before GC starts. | long | byte |
| spring_boot.gc.last_info.memory_usage.before.ps_survivor_space.max | Max memory of the PS Survivor Space memory pool before GC starts. | long | byte |
| spring_boot.gc.last_info.memory_usage.before.ps_survivor_space.used | Used memory of the PS Survivor Space memory pool before GC starts. | long | byte |
| spring_boot.gc.last_info.thread_count | Thread count of the GC. | long |  |
| spring_boot.gc.last_info.time.duration | Elapsed time of the GC in milliseconds. | long | ms |
| spring_boot.gc.last_info.time.end | End time of the GC. | long | ms |
| spring_boot.gc.last_info.time.start | Start time of the GC. | long | ms |
| spring_boot.gc.name | Name of the GC. | keyword |  |

