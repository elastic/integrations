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

### Server Metrics

This is the `server` dataset.

- This dataset gives information of Server.

An example event for `server` looks as following:

```json
{
    "@timestamp": "2022-04-03T06:17:31.235Z",
    "agent": {
        "ephemeral_id": "03c8469a-e01a-4104-b480-d09f5c704737",
        "id": "a795adfc-cb74-46e5-817e-ebf58bcc0848",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.1.0"
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
        "id": "a795adfc-cb74-46e5-817e-ebf58bcc0848",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "spring_boot.server",
        "duration": 103393992,
        "ingested": "2022-04-03T06:17:34Z",
        "kind": "metric",
        "module": "prometheus"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "192.168.32.7"
        ],
        "mac": [
            "02:42:c0:a8:20:07"
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
        "server": {
            "labels": {
                "instance": "springboot:8090",
                "job": "prometheus",
                "level": "info"
            },
            "metrics": {
                "logback_events_total": 9
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

