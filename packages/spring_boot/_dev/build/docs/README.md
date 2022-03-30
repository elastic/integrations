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

{{event "audit_events"}}

{{fields "audit_events"}}

## Metrics

### Memory Metrics

This is the `memory` dataset.

- This dataset gives Memory information.

{{event "memory"}}

{{fields "memory"}}


### GC Metrics

This is the `gc` dataset.

- This dataset gives data of GC Memory.

{{event "gc"}}

{{fields "gc"}}
