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

{{event "info"}}

{{fields "info"}}

### Audit Events logs

This is the `audit_events` dataset.

- This dataset exposes audit events information for the current application.

{{event "audit_events"}}

{{fields "audit_events"}}

### HTTP Trace logs

This is the `http_trace` dataset.

- This dataset displays HTTP trace information.

{{event "http_trace"}}

{{fields "http_trace"}}

## Metrics

### Memory Metrics

This is the `memory` dataset.

- This dataset gives Memory information.

{{event "memory"}}

{{fields "memory"}}

### OS Metrics

This is the `os` dataset.

- This dataset gives OS related information.

{{event "os"}}

{{fields "os"}}

### Threads Metrics

This is the `threads` dataset.

- This dataset gives details of threads.

{{event "threads"}}

{{fields "threads"}}

### JVM Metrics

This is the `jvm` dataset.

- This dataset gives data of JVM Memory.

{{event "jvm"}}

{{fields "jvm"}}

### Server Metrics

This is the `server` dataset.

- This dataset gives information of Server.

{{event "server"}}

{{fields "server"}}
