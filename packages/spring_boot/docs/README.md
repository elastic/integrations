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

### Threading Metrics

This is the `threading` data stream.

- This data stream gives metrics related to thread allocations, monitoring and CPU times.

An example event for `threading` looks as following:

```json
{
    "@timestamp": "2022-04-20T11:42:11.404Z",
    "agent": {
        "ephemeral_id": "14adc5b5-698c-41a2-a988-cac42457c181",
        "id": "874f5030-4e15-4b08-9934-fd1df85257f8",
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
        "version": "8.1.0"
    },
    "elastic_agent": {
        "id": "874f5030-4e15-4b08-9934-fd1df85257f8",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "database",
        "dataset": "spring_boot.threading",
        "duration": 93470677,
        "ingested": "2022-04-20T11:42:14Z",
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
            "allocated_memory": {
                "enabled": true,
                "supported": true
            },
            "contention_monitoring": {
                "enabled": false,
                "supported": true
            },
            "count": 20,
            "cpu_time": {
                "enabled": true,
                "supported": true
            },
            "current_thread": {
                "allocated_bytes": 1044528,
                "cpu_time": 463388970,
                "cpu_time_supported": true,
                "user_time": 460000000
            },
            "daemon_thread_count": 16,
            "object_monitor_usage_supported": true,
            "peak_thread_count": 20,
            "synchronizer_usage_supported": true,
            "total_started_thread_count": 23
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
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| spring_boot.threading.allocated_memory.enabled | Allocated memory for threads | boolean |
| spring_boot.threading.allocated_memory.supported | Allocated memory support for threads | boolean |
| spring_boot.threading.contention_monitoring.enabled | Shows thread contention monitoring is enabled | boolean |
| spring_boot.threading.contention_monitoring.supported | Shows the Java virtual machine supports thread contention monitoring | boolean |
| spring_boot.threading.count | Current number of live threads including both daemon and non-daemon threads | long |
| spring_boot.threading.cpu_time.enabled | Shows thread CPU time measurement is enabled | boolean |
| spring_boot.threading.cpu_time.supported | Shows the Java virtual machine implementation supports CPU time measurement for any thread | boolean |
| spring_boot.threading.current_thread.allocated_bytes | Allocated bytes for the current thread | double |
| spring_boot.threading.current_thread.cpu_time | CPU time for the current thread in nanoseconds | long |
| spring_boot.threading.current_thread.cpu_time_supported | Shows the Java virtual machine supports CPU time measurement for the current thread | boolean |
| spring_boot.threading.current_thread.user_time | User time for the current thread | long |
| spring_boot.threading.daemon_thread_count | Current number of live daemon threads | long |
| spring_boot.threading.object_monitor_usage_supported | Object monitor usage support | boolean |
| spring_boot.threading.peak_thread_count | Peak thread count to the current number of live threads | long |
| spring_boot.threading.synchronizer_usage_supported | Show the synchronizer usage support | boolean |
| spring_boot.threading.total_started_thread_count | Total number of threads created and also started since the Java virtual machine started | long |

