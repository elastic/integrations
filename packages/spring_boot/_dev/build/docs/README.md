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

### Troubleshooting

If **[Spring Boot] Audit Events panel** does not display older documents after upgrading to ``0.9.0`` or later versions, then this issue can be solved by reindexing the ``audit_events`` data stream's indices.

To reindex the data, the following steps must be performed.

1. Stop the data stream by going to `Integrations -> Spring Boot -> Integration policies` open the configuration of Spring Boot and disable the `Spring Boot Audit Events metrics` toggle to reindex ``audit_events`` data stream and save the integration.

2. Copy data into the temporary index and delete the existing data stream and index template by performing the following steps in the Dev tools.

```
POST _reindex
{
  "source": {
    "index": "<index_name>"
  },
  "dest": {
    "index": "temp_index"
  }
}
```
Example:
```
POST _reindex
{
  "source": {
    "index": "logs-spring_boot.audit_events-default"
  },
  "dest": {
    "index": "temp_index"
  }
}
```

```
DELETE /_data_stream/<data_stream>
```
Example:
```
DELETE /_data_stream/logs-spring_boot.audit_events-default
```

```
DELETE _index_template/<index_template>
```
Example:
```
DELETE _index_template/logs-spring_boot.audit_events
```
3. Go to `Integrations ->  Spring Boot  -> Settings` and click on `Reinstall Spring Boot`.

4. Copy data from temporary index to new index by performing the following steps in the Dev tools.

```
POST _reindex
{
  "source": {
    "index": "temp_index"
  },
  "dest": {
    "index": "<index_name>",
    "op_type": "create"

  }
}
```
Example:
```
POST _reindex
{
  "source": {
    "index": "temp_index"
  },
  "dest": {
    "index": "logs-spring_boot.audit_events-default",
    "op_type": "create"

  }
}
```

5. Verify data is reindexed completely.

6. Start the data stream by going to the `Integrations -> Spring Boot -> Integration policies` and open configuration of integration and enable the `Spring Boot Audit Events metrics` toggle.

7. Delete temporary index by performing the following step in the Dev tools.

```
DELETE temp_index
```

More details about reindexing can be found [here](https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-reindex.html).

## Logs

### Audit Events logs

This is the `audit_events` data stream.

- This data stream exposes audit events information for the current application.

{{event "audit_events"}}

{{fields "audit_events"}}

### HTTP Trace logs

This is the `http_trace` data stream.

- This data stream displays HTTP trace information.

{{event "http_trace"}}

{{fields "http_trace"}}

## Metrics

### Memory Metrics

This is the `memory` data stream.

- This data stream gives metrics related to heap and non-heap memory, buffer pool and manager.

{{event "memory"}}

{{fields "memory"}}

### Threading Metrics

This is the `threading` data stream.

- This data stream gives metrics related to thread allocations, monitoring and CPU times.

{{event "threading"}}

{{fields "threading"}}

### GC Metrics

This is the `gc` data stream.

- This data stream gives metrics related to Garbage Collector (GC) Memory.

{{event "gc"}}

{{fields "gc"}}
