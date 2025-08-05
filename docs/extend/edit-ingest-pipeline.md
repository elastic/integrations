---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/edit-ingest-pipeline.html
---

# Edit ingest pipelines [edit-ingest-pipeline]

In most instances, before you ingest data into the {{stack}}, the data needs to be manipulated. For example, you should parse your logs into structured data before ingestion. To do so, integrations use **ingest pipelines**.

::::{admonition}
**Ingest pipelines** let you perform common transformations on your data before indexing. For example, you can use pipelines to remove fields, extract values from text, and enrich your data.

A pipeline consists of a series of configurable tasks called processors. Each processor runs sequentially, making specific changes to incoming documents. After the processors have run, {{es}} adds the transformed documents to your data stream or index.

Learn more in the [ingest pipeline reference](docs-content://manage-data/ingest/transform-enrich/ingest-pipelines.md).

::::


Ingest pipelines are defined in the `elasticsearch/ingest_pipeline` directory. They only apply to the parent data stream within which they live. For our example, this would be the `apache.access` dataset.

For example, the [Apache integration](https://github.com/elastic/integrations/tree/main/packages/apache):

```text
apache
└───data_stream
│   └───access
│   │   └───elasticsearch/ingest_pipeline
│   │          default.yml <1>
│   └───error
│   └───status
```

1. The ingest pipeline definition for the access logs data stream of the Apache integration


An ingest pipeline definition requires a description and an array of processors. Here’s a snippet of the access logs ingest pipeline:

```yaml
description: "Pipeline for parsing Apache HTTP Server access logs."
processors:
- set:
    field: event.ingested
    value: '{{_ingest.timestamp}}'
- rename:
    field: message
    target_field: event.original
- remove:
    field: apache.access.time
    ignore_failure: true
```

Open each `elasticsearch/ingest_pipeline/default.yml` file created for each data stream. Edit each ingest pipeline to match your needs.

The [processor reference](elasticsearch://reference/enrich-processor/index.md) provides a list of all available processors and their configurations.


## Pipeline organization and chaining

Integrations can use multiple pipelines to organize complex processing logic:

* **default.yml** - The main pipeline that runs for all documents in the data stream
* **Custom pipelines** - Additional pipelines for specific processing needs (e.g., `parser.yml`, `enrichment.yml`)
* **@custom pipeline** - A user-defined pipeline that runs after the integration's pipelines

Pipelines can call other pipelines using the `pipeline` processor:

```yaml
processors:
- pipeline:
    name: logs-apache.access-1.0.0-parser
    if: ctx.event?.original != null
```

Best practices for organizing pipelines:
* Keep the default pipeline focused on core transformations
* Split complex parsing logic into separate pipelines
* Use conditional pipelines for format-specific processing
* Document the purpose of each pipeline clearly


## Common processor patterns

Here are frequently used processor patterns for data transformation:

### Parsing timestamps
Use the `date` processor to parse timestamps with multiple possible formats:

```yaml
- date:
    field: apache.access.time
    target_field: "@timestamp"
    formats:
      - dd/MMM/yyyy:HH:mm:ss Z
      - ISO8601
      - UNIX_MS
    timezone: "{{ event.timezone }}"
```

### Extracting JSON fields
Parse JSON strings into structured fields:

```yaml
- json:
    field: message
    target_field: parsed
    add_to_root: true
    on_failure:
      - append:
          field: error.message
          value: "Failed to parse JSON: {{{ _ingest.on_failure_message }}}"
```

### Parsing structured logs
Use [`grok`](elasticsearch://reference/ingest/processors/grok.md) for complex patterns or [`dissect`](elasticsearch://reference/ingest/processors/dissect.md) for fixed delimiters:

```yaml
# Grok for flexible patterns
- grok:
    field: message
    patterns:
      - '%{IPORHOST:source.ip} %{USER:user.name} \[%{HTTPDATE:timestamp}\] "%{WORD:http.request.method} %{DATA:url.path}"'
    pattern_definitions:
      CUSTOM_PATTERN: "your-regex-here"

# Dissect for better performance with fixed formats
- dissect:
    field: message
    pattern: "%{source.ip} - %{user.name} [%{timestamp}] \"%{http.request.method} %{url.path}\""
```

### Conditional processing
Apply processors only when conditions are met:

```yaml
- lowercase:
    field: http.request.method
    if: ctx.http?.request?.method != null
- remove:
    field: temp_field
    if: ctx.tags?.contains('processed')
```


## Error handling

Proper error handling ensures pipeline resilience:

### Using ignore_failure
For non-critical processors that may fail:

```yaml
- convert:
    field: http.response.status_code
    type: long
    ignore_failure: true  # Continue if conversion fails
```

### Using on_failure blocks
For handling specific failure scenarios:

```yaml
- json:
    field: message
    on_failure:
      - set:
          field: error.type
          value: "json_parse_error"
      - set:
          field: error.message
          value: "{{{ _ingest.on_failure_message }}}"
```

### Pipeline-level error handling
Define fallback behavior for the entire pipeline:

```yaml
description: Pipeline with error handling
processors:
  - json:
      field: message
on_failure:
  - set:
      field: error.pipeline
      value: "default"
  - set:
      field: event.kind
      value: "pipeline_error"
```

Common error handling patterns:
* Use `ignore_failure` for optional fields
* Add error details to dedicated error fields
* Log errors for debugging but don't block ingestion


## Testing pipelines

Testing ensures your pipelines work correctly before deployment. See the [pipeline testing documentation](./pipeline-testing.md) for comprehensive testing strategies.


## Performance considerations

Pipeline performance impacts ingestion throughput:

### Processor ordering
* Place `drop` processors early to filter unwanted documents
* Run field existence checks before complex operations
* Group related processors together

### Expensive operations
Use these processors sparingly:
* **script** - Painless scripts have overhead
* **enrich** - Requires lookups against Elasticsearch
* **geoip/user_agent** - Database lookups
* **grok** with complex patterns - Consider `dissect` for fixed formats

### Optimization techniques
```yaml
# Drop unwanted documents early
- drop:
    if: ctx.event?.dataset != "apache.access"

# Check field existence before processing
- lowercase:
    field: user.name
    if: ctx.user?.name != null

# Use dissect instead of grok when possible
- dissect:
    field: message
    pattern: "%{} - %{} [%{}] \"%{method} %{path} %{}\" %{status} %{}"
```

### Monitoring pipeline performance
* Check pipeline stats: `GET _nodes/stats/ingest`
* Monitor ingestion rates in Stack Monitoring
* Set up alerts for pipeline failures
