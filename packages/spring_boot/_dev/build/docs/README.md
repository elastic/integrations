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

{{event "audit_events"}}

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "audit_events"}}

### HTTP Trace logs

This is the `http_trace` data stream.

- This data stream displays HTTP trace information.

{{event "http_trace"}}

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "http_trace"}}

## Metrics

### Memory Metrics

This is the `memory` data stream.

- This data stream gives metrics related to heap and non-heap memory, buffer pool and manager.

{{event "memory"}}

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "memory"}}

### Threading Metrics

This is the `threading` data stream.

- This data stream gives metrics related to thread allocations, monitoring and CPU times.

{{event "threading"}}

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "threading"}}

### GC Metrics

This is the `gc` data stream.

- This data stream gives metrics related to Garbage Collector (GC) Memory.

{{event "gc"}}

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "gc"}}
