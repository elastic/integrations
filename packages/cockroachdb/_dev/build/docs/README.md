# CockroachDB Integration

This integration collects metrics from [CockroachDB](https://www.cockroachlabs.com/docs/stable/developer-guide-overview.html). It includes the following datasets for receiving logs:

- `status` datastream: consists of status metrics

## Compatibility

The CockroachDB integration is compatible with any CockroachDB version
exposing metrics in Prometheus format.

### status

{{fields "status"}}

{{event "status"}}

