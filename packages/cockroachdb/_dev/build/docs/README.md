# CockroachDB Integration

This integration collects metrics from [CockroachDB](https://www.cockroachlabs.com/docs/stable/developer-guide-overview.html). It includes the following datasets for receiving logs:

- `status` datastream: consists of status metrics

## Compatibility

The CockroachDB integration is compatible with any CockroachDB version
exposing metrics in Prometheus format.

### status

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "status"}}

{{event "status"}}

