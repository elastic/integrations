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

This integration has been tested against Spring Boot v2.7.17 with LTS JDK versions 8, 11, 17, and 21.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended or self-manage the Elastic Stack on your own hardware.

In order to ingest data from Spring Boot:
- You must know the host for Spring Boot application, add that host while configuring the integration package.
- Add default path for jolokia.
- Spring-boot-actuator module provides all Spring Boot's production-ready features. You also need to add the following dependency to the `pom.xml` file:
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
- To expose `HTTP Trace` metrics following class can be used [InMemoryHttpTraceRepository](https://docs.spring.io/spring-boot/docs/2.0.6.RELEASE/api/org/springframework/boot/actuate/trace/http/InMemoryHttpTraceRepository.html).
- To expose `Audit Events` metrics following class can be used [InMemoryAuditEventRepository](https://docs.spring.io/spring-boot/docs/current/api/org/springframework/boot/actuate/audit/InMemoryAuditEventRepository.html).

## Setup

For step-by-step instructions on how to set up an integration, see the [Getting Started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

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
    "@timestamp": "2024-06-18T07:15:52.565Z",
    "agent": {
        "ephemeral_id": "5026de47-56bf-4ed7-996b-c574a7c0d140",
        "id": "97400795-188c-4140-a1ee-0002078c785d",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "spring_boot.audit_events",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "97400795-188c-4140-a1ee-0002078c785d",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "created": "2024-06-18T07:15:52.565Z",
        "dataset": "spring_boot.audit_events",
        "ingested": "2024-06-18T07:16:04Z",
        "kind": "event",
        "module": "spring_boot",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "8259e024976a406e8a54cdbffeb84fec",
        "ip": [
            "192.168.245.7"
        ],
        "mac": [
            "02-42-C0-A8-F5-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.102.1.el7.x86_64",
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

## ECS Field Reference

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
    "@timestamp": "2024-06-18T07:17:49.933Z",
    "agent": {
        "ephemeral_id": "f957703f-c55c-49bb-81d4-ec742b088158",
        "id": "97400795-188c-4140-a1ee-0002078c785d",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "spring_boot.http_trace",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "97400795-188c-4140-a1ee-0002078c785d",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "created": "2024-06-18T07:17:49.933Z",
        "dataset": "spring_boot.http_trace",
        "duration": 3,
        "ingested": "2024-06-18T07:18:01Z",
        "kind": "event",
        "module": "spring_boot",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "8259e024976a406e8a54cdbffeb84fec",
        "ip": [
            "{0=192.168.245.7}"
        ],
        "mac": [
            "02-42-C0-A8-F5-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.102.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
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

## ECS Field Reference

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
    "@timestamp": "2024-06-18T07:18:47.122Z",
    "agent": {
        "ephemeral_id": "2972904f-375b-4b83-9de9-e0c36d85d5de",
        "id": "97400795-188c-4140-a1ee-0002078c785d",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "spring_boot.memory",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "97400795-188c-4140-a1ee-0002078c785d",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "dataset": "spring_boot.memory",
        "duration": 672110556,
        "ingested": "2024-06-18T07:18:59Z",
        "kind": "metric",
        "module": "spring_boot",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "8259e024976a406e8a54cdbffeb84fec",
        "ip": [
            "192.168.245.7"
        ],
        "mac": [
            "02-42-C0-A8-F5-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.102.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
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
                "committed": 587202560,
                "init": 260046848,
                "max": 3698851840,
                "used": 158654888
            },
            "non_heap": {
                "committed": 63504384,
                "init": 2555904,
                "max": -1,
                "used": 58973664
            }
        }
    },
    "tags": [
        "spring_boot.memory.metrics"
    ]
}
```

## ECS Field Reference

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
    "@timestamp": "2024-06-18T07:19:44.017Z",
    "agent": {
        "ephemeral_id": "9e0f783a-f02b-4fc0-90c9-2d264b73e4bc",
        "id": "97400795-188c-4140-a1ee-0002078c785d",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "spring_boot.threading",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "97400795-188c-4140-a1ee-0002078c785d",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "dataset": "spring_boot.threading",
        "duration": 301437518,
        "ingested": "2024-06-18T07:19:55Z",
        "kind": "metric",
        "module": "spring_boot",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "8259e024976a406e8a54cdbffeb84fec",
        "ip": [
            "192.168.245.7"
        ],
        "mac": [
            "02-42-C0-A8-F5-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.102.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
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
                    "allocated_bytes": 29755720,
                    "time": {
                        "cpu": 293039690,
                        "user": 280000000
                    }
                },
                "daemon": 16,
                "started": 23
            }
        }
    },
    "tags": [
        "spring_boot.threading.metrics"
    ]
}
```

## ECS Field Reference

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
    "@timestamp": "2024-06-18T07:16:52.674Z",
    "agent": {
        "ephemeral_id": "bfe8ee26-f9e4-4990-8790-7fbc2a8c075e",
        "id": "97400795-188c-4140-a1ee-0002078c785d",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "spring_boot.gc",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "97400795-188c-4140-a1ee-0002078c785d",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "dataset": "spring_boot.gc",
        "duration": 347472291,
        "ingested": "2024-06-18T07:17:04Z",
        "kind": "metric",
        "module": "spring_boot",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "8259e024976a406e8a54cdbffeb84fec",
        "ip": [
            "192.168.245.7"
        ],
        "mac": [
            "02-42-C0-A8-F5-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.102.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
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
                "id": 6,
                "memory_usage": {
                    "after": {
                        "code_cache": {
                            "committed": 14286848,
                            "init": 2555904,
                            "max": 251658240,
                            "used": 14213056
                        },
                        "compressed_class_space": {
                            "committed": 4980736,
                            "init": 0,
                            "max": 1073741824,
                            "used": 4443120
                        },
                        "metaspace": {
                            "committed": 36265984,
                            "init": 0,
                            "max": -1,
                            "used": 33775552
                        },
                        "ps_eden_space": {
                            "committed": 457703424,
                            "init": 65536000,
                            "max": 1354235904,
                            "used": 0
                        },
                        "ps_old_gen": {
                            "committed": 90177536,
                            "init": 173539328,
                            "max": 2774007808,
                            "used": 10597560
                        },
                        "ps_survivor_space": {
                            "committed": 16777216,
                            "init": 10485760,
                            "max": 16777216,
                            "used": 8605776
                        }
                    },
                    "before": {
                        "code_cache": {
                            "committed": 14286848,
                            "init": 2555904,
                            "max": 251658240,
                            "used": 14213056
                        },
                        "compressed_class_space": {
                            "committed": 4980736,
                            "init": 0,
                            "max": 1073741824,
                            "used": 4443120
                        },
                        "metaspace": {
                            "committed": 36265984,
                            "init": 0,
                            "max": -1,
                            "used": 33775552
                        },
                        "ps_eden_space": {
                            "committed": 262144000,
                            "init": 65536000,
                            "max": 1359478784,
                            "used": 10469928
                        },
                        "ps_old_gen": {
                            "committed": 90177536,
                            "init": 173539328,
                            "max": 2774007808,
                            "used": 10589368
                        },
                        "ps_survivor_space": {
                            "committed": 10485760,
                            "init": 10485760,
                            "max": 10485760,
                            "used": 10453056
                        }
                    }
                },
                "thread_count": 10,
                "time": {
                    "duration": 8,
                    "end": 3406,
                    "start": 3398
                }
            },
            "name": "PS Scavenge"
        }
    },
    "tags": [
        "spring_boot.gc.metrics"
    ]
}
```

## ECS Field Reference

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

