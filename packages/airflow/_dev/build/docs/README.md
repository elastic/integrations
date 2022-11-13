# Airflow Integration

This integration collects metrics from [Airflow](https://airflow.apache.org/docs/apache-airflow/stable/logging-monitoring/metrics.html) running a
statsd server where airflow will send metrics to. The default metricset is `statsd`.

## Compatibility

The Airflow module is tested with Airflow 2.4.0. It should work with version
2.0.0 and later.

### statsd

{{fields "statsd"}}

