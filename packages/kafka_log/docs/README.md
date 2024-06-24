# Custom Kafka Log integration

The custom Kafka log integration is used to read from topics in a Kafka cluster.

To configure this integration, specify a list of one or more hosts in the cluster to bootstrap the connection with, a list of topics to track, and a group_id for the connection.


## Compatibility
This Integration works with all Kafka versions in between 0.11 and 2.8.0. Older versions might work as well, but are not supported.


## Ingest Pipelines
Custom ingest pipelines may be added by adding the name to the pipeline configuration option, creating custom ingest pipelines can be done either through the API or the [Ingest Node Pipeline UI](/app/management/ingest/ingest_pipelines/).

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.