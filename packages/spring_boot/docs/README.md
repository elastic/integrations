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

## Metrics

### JVM Metrics

This is the `jvm` dataset.

- This dataset gives data of JVM Memory.

An example event for `jvm` looks as following:

```json
{
    "@timestamp": "2022-04-03T06:03:02.784Z",
    "agent": {
        "ephemeral_id": "dfaab7ac-8ab2-4885-b53b-4cc9ee47350c",
        "id": "44c552b2-d11d-4119-a198-95a9c6503b11",
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
        "id": "44c552b2-d11d-4119-a198-95a9c6503b11",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "spring_boot.jvm",
        "duration": 104861772,
        "ingested": "2022-04-03T06:03:06Z",
        "kind": "metric",
        "module": "prometheus"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "172.21.0.7"
        ],
        "mac": [
            "02:42:ac:15:00:07"
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
                "state": "blocked"
            },
            "metrics": {
                "jvm": {
                    "threads": {
                        "states_threads": 0
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

