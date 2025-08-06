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
