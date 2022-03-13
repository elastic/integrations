# Spring Boot Endpoints

The Spring Boot Endpoints integration is used to fetch observability data from [Spring Boot Actuators web endpoints](https://docs.spring.io/spring-boot/docs/2.6.3/actuator-api/htmlsingle/) and ingest it into Elasticsearch.

## Compatibility

This module has been tested against `Spring Boot Version: 2.3.12`

## Requirements

In order to ingest data from Spring Boot :
- You must know the host for Spring Boot application, add that host while configuring the integration package.
- Add default path for jolokia.
- Spring-boot-actuator module provides all Spring Boot’s production-ready features. So add below dependency in `pom.xml` file.
```
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-actuator</artifactId>
</dependency>
```
- For access of jolokia add below dependency in `pom.xml` of Spring Boot Endpoints application.
```sh
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

### Jolokia Metrics

This is the `jolokia` dataset.

- This dataset exposes JMX beans over HTTP when Jolokia is on the classpath.

{{event "jolokia"}}

{{fields "jolokia"}}

### Prometheus Metrics

This is the `prometheus` dataset.

- This dataset exposes metrics in a format that can be scraped by a Prometheus server.

{{event "prometheus"}}

{{fields "prometheus"}}
