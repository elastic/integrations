# Custom Kafka Log input package

This package is an **input** type integration: it exposes the Filebeat Kafka input in Fleet so you can read from topics in a Kafka cluster and choose a dataset name for routing.

Configure bootstrap **hosts**, **topics**, and a consumer **group_id** (and optional SASL, TLS, parsers, and related settings) in the policy.

## Compatibility
This package works with Kafka versions in between 0.11 and 2.8.0. Older versions might work as well, but are not supported.

## Ingest Pipelines
Custom ingest pipelines may be added by setting the pipeline option; you can create pipelines via the API or the [Ingest Node Pipeline UI](/app/management/ingest/ingest_pipelines/).

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.