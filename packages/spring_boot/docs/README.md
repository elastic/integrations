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

