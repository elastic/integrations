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

## Metrics

### GC Metrics

This is the `gc` data stream.

- This data stream gives metrics related to Garbage Collector(GC) Memory.

An example event for `gc` looks as following:

```json
{
    "@timestamp": "2022-04-20T17:01:37.492Z",
    "agent": {
        "ephemeral_id": "432d108b-1f7c-4f96-a02d-4225dc1a06df",
        "id": "5a14593f-1e5a-4fe0-81b6-282e92649870",
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
        "version": "8.1.0"
    },
    "elastic_agent": {
        "id": "5a14593f-1e5a-4fe0-81b6-282e92649870",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "database",
        "dataset": "spring_boot.gc",
        "duration": 92851054,
        "ingested": "2022-04-20T17:01:40Z",
        "kind": "metric",
        "module": "spring_boot",
        "type": "info"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "172.23.0.7"
        ],
        "mac": [
            "02:42:ac:17:00:07"
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
        "name": "jmx",
        "period": 60000
    },
    "service": {
        "address": "http://springboot:8090/actuator/jolokia",
        "type": "jolokia"
    },
    "spring_boot": {
        "gc": {
            "last_gc_info": {
                "end_time": 7743,
                "gc_thread_count": 4,
                "memory_usage_after_gc": {
                    "code_cache": {
                        "committed": 11665408,
                        "init": 2555904,
                        "max": 251658240,
                        "used": 11634560
                    },
                    "compressed_class_space": {
                        "committed": 4980736,
                        "init": 0,
                        "max": 1073741824,
                        "used": 4445576
                    },
                    "metaspace": {
                        "committed": 36265984,
                        "init": 0,
                        "max": -1,
                        "used": 33724952
                    },
                    "ps_eden_space": {
                        "committed": 244318208,
                        "init": 24641536,
                        "max": 482344960,
                        "used": 0
                    },
                    "ps_old_gen": {
                        "committed": 55574528,
                        "init": 64487424,
                        "max": 1012400128,
                        "used": 17436616
                    },
                    "ps_survivor_space": {
                        "committed": 12058624,
                        "init": 3670016,
                        "max": 12058624,
                        "used": 0
                    }
                },
                "memory_usage_before_gc": {
                    "code_cache": {
                        "committed": 11665408,
                        "init": 2555904,
                        "max": 251658240,
                        "used": 11634560
                    },
                    "compressed_class_space": {
                        "committed": 4980736,
                        "init": 0,
                        "max": 1073741824,
                        "used": 4445576
                    },
                    "metaspace": {
                        "committed": 36265984,
                        "init": 0,
                        "max": -1,
                        "used": 33724952
                    },
                    "ps_eden_space": {
                        "committed": 244318208,
                        "init": 24641536,
                        "max": 482344960,
                        "used": 0
                    },
                    "ps_old_gen": {
                        "committed": 45088768,
                        "init": 64487424,
                        "max": 1012400128,
                        "used": 16752984
                    },
                    "ps_survivor_space": {
                        "committed": 12058624,
                        "init": 3670016,
                        "max": 12058624,
                        "used": 6586384
                    }
                },
                "start_time": 7630
            },
            "name": "PS MarkSweep",
            "valid": true
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
| spring_boot.gc.collection.count | Total number of collections that have occurred | long |
| spring_boot.gc.collection.time | Approximate accumulated collection elapsed time in milliseconds | long |
| spring_boot.gc.last_gc_info.duration | Elapsed time of the GC in milliseconds | long |
| spring_boot.gc.last_gc_info.end_time | End time of the GC | long |
| spring_boot.gc.last_gc_info.gc_thread_count | Thread count of the GC | long |
| spring_boot.gc.last_gc_info.id | ID of the GC | long |
| spring_boot.gc.last_gc_info.memory_usage_after_gc.code_cache.committed | Committed memory of the code cache memory pool after GC started | long |
| spring_boot.gc.last_gc_info.memory_usage_after_gc.code_cache.init | Init memory of the code cache memory pool after GC started | long |
| spring_boot.gc.last_gc_info.memory_usage_after_gc.code_cache.max | Max memory of the code cache memory pool after GC started | long |
| spring_boot.gc.last_gc_info.memory_usage_after_gc.code_cache.used | Used memory of the code cache memory pool after GC started | long |
| spring_boot.gc.last_gc_info.memory_usage_after_gc.compressed_class_space.committed | Committed memory of the compressed class space memory pool after GC started | long |
| spring_boot.gc.last_gc_info.memory_usage_after_gc.compressed_class_space.init | Init memory of the compressed class space memory pool after GC started | long |
| spring_boot.gc.last_gc_info.memory_usage_after_gc.compressed_class_space.max | Max memory of the compressed class space memory pool after GC started | long |
| spring_boot.gc.last_gc_info.memory_usage_after_gc.compressed_class_space.used | Used memory of the compressed class space memory pool after GC started | long |
| spring_boot.gc.last_gc_info.memory_usage_after_gc.metaspace.committed | Committed memory of the metaspace memory pool after GC started | long |
| spring_boot.gc.last_gc_info.memory_usage_after_gc.metaspace.init | Init memory of the metaspace memory pool after GC started | long |
| spring_boot.gc.last_gc_info.memory_usage_after_gc.metaspace.max | Max memory of the metaspace memory pool after GC started | long |
| spring_boot.gc.last_gc_info.memory_usage_after_gc.metaspace.used | Used memory of the metaspace memory pool after GC started | long |
| spring_boot.gc.last_gc_info.memory_usage_after_gc.ps_eden_space.committed | Committed memory of the PS Eden Space memory pool after GC started | long |
| spring_boot.gc.last_gc_info.memory_usage_after_gc.ps_eden_space.init | Init memory of the PS Eden Space memory pool after GC started | long |
| spring_boot.gc.last_gc_info.memory_usage_after_gc.ps_eden_space.max | Max memory of the PS Eden Space memory pool after GC started | long |
| spring_boot.gc.last_gc_info.memory_usage_after_gc.ps_eden_space.used | Used memory of the PS Eden Space memory pool after GC started | long |
| spring_boot.gc.last_gc_info.memory_usage_after_gc.ps_old_gen.committed | Committed memory of the PS Old Gen memory pool after GC started | long |
| spring_boot.gc.last_gc_info.memory_usage_after_gc.ps_old_gen.init | Init memory of the PS Old Gen memory pool after GC started | long |
| spring_boot.gc.last_gc_info.memory_usage_after_gc.ps_old_gen.max | Max memory of the PS Old Gen memory pool after GC started | long |
| spring_boot.gc.last_gc_info.memory_usage_after_gc.ps_old_gen.used | Used memory of the PS Old Gen memory pool after GC started | long |
| spring_boot.gc.last_gc_info.memory_usage_after_gc.ps_survivor_space.committed | Committed memory of the PS Survivor Space memory pool after GC started | long |
| spring_boot.gc.last_gc_info.memory_usage_after_gc.ps_survivor_space.init | Init memory of the PS Survivor Space memory pool after GC started | long |
| spring_boot.gc.last_gc_info.memory_usage_after_gc.ps_survivor_space.max | Max memory of the PS Survivor Space memory pool after GC started | long |
| spring_boot.gc.last_gc_info.memory_usage_after_gc.ps_survivor_space.used | Used memory of the PS Survivor Space memory pool after GC started | long |
| spring_boot.gc.last_gc_info.memory_usage_before_gc.code_cache.committed | Committed memory of the code cache memory pool before GC starts | long |
| spring_boot.gc.last_gc_info.memory_usage_before_gc.code_cache.init | Init memory of the code cache memory pool before GC starts | long |
| spring_boot.gc.last_gc_info.memory_usage_before_gc.code_cache.max | Max memory of the code cache memory pool before GC starts | long |
| spring_boot.gc.last_gc_info.memory_usage_before_gc.code_cache.used | Used memory of the code cache memory pool before GC starts | long |
| spring_boot.gc.last_gc_info.memory_usage_before_gc.compressed_class_space.committed | Committed memory of the compressed class space memory pool before GC starts | long |
| spring_boot.gc.last_gc_info.memory_usage_before_gc.compressed_class_space.init | Init memory of the compressed class space memory pool before GC starts | long |
| spring_boot.gc.last_gc_info.memory_usage_before_gc.compressed_class_space.max | Max memory of the compressed class space memory pool before GC starts | long |
| spring_boot.gc.last_gc_info.memory_usage_before_gc.compressed_class_space.used | Used memory of the compressed class space memory pool before GC starts | long |
| spring_boot.gc.last_gc_info.memory_usage_before_gc.metaspace.committed | Committed memory of the metaspace memory pool before GC starts | long |
| spring_boot.gc.last_gc_info.memory_usage_before_gc.metaspace.init | Init memory of the metaspace memory pool before GC starts | long |
| spring_boot.gc.last_gc_info.memory_usage_before_gc.metaspace.max | Max memory of the metaspace memory pool before GC starts | long |
| spring_boot.gc.last_gc_info.memory_usage_before_gc.metaspace.used | Used memory of the metaspace memory pool before GC starts | long |
| spring_boot.gc.last_gc_info.memory_usage_before_gc.ps_eden_space.committed | Committed memory of the PS Eden Space memory pool before GC starts | long |
| spring_boot.gc.last_gc_info.memory_usage_before_gc.ps_eden_space.init | Init memory of the PS Eden Space memory pool before GC starts | long |
| spring_boot.gc.last_gc_info.memory_usage_before_gc.ps_eden_space.max | Max memory of the PS Eden Space memory pool before GC starts | long |
| spring_boot.gc.last_gc_info.memory_usage_before_gc.ps_eden_space.used | Used memory of the PS Eden Space memory pool before GC starts | long |
| spring_boot.gc.last_gc_info.memory_usage_before_gc.ps_old_gen.committed | Committed memory of the PS Old Gen memory pool before GC starts | long |
| spring_boot.gc.last_gc_info.memory_usage_before_gc.ps_old_gen.init | Init memory of the PS Old Gen memory pool before GC starts | long |
| spring_boot.gc.last_gc_info.memory_usage_before_gc.ps_old_gen.max | Max memory of the PS Old Gen memory pool before GC starts | long |
| spring_boot.gc.last_gc_info.memory_usage_before_gc.ps_old_gen.used | Used memory of the PS Old Gen memory pool before GC starts | long |
| spring_boot.gc.last_gc_info.memory_usage_before_gc.ps_survivor_space.committed | Committed memory of the PS Survivor Space memory pool before GC starts | long |
| spring_boot.gc.last_gc_info.memory_usage_before_gc.ps_survivor_space.init | Init memory of the PS Survivor Space memory pool before GC starts | long |
| spring_boot.gc.last_gc_info.memory_usage_before_gc.ps_survivor_space.max | Max memory of the PS Survivor Space memory pool before GC starts | long |
| spring_boot.gc.last_gc_info.memory_usage_before_gc.ps_survivor_space.used | Used memory of the PS Survivor Space memory pool before GC starts | long |
| spring_boot.gc.last_gc_info.start_time | Start time of the GC | long |
| spring_boot.gc.name | Name of the GC | keyword |
| spring_boot.gc.valid | Validation of the GC | boolean |

