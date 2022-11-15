# Airflow Integration

This integration collects metrics from [Airflow](https://airflow.apache.org/docs/apache-airflow/stable/logging-monitoring/metrics.html) running a
statsd server where airflow will send metrics to. The default metricset is `statsd`.

## Compatibility

The Airflow module is tested with Airflow 2.4.0. It should work with version
2.0.0 and later.

### statsd
statsd datastream retrieves the Airflow metrics using Statsd.
The Airflow integration requires [Statsd](https://www.elastic.co/guide/en/beats/metricbeat/master/metricbeat-module-airflow.html) to receive Statsd metrics. Refer to the link for instructions about how to use Statsd.

Add the following lines to your Airflow configuration file e.g. `airflow.cfg` ensuring `statsd_prefix` is left empty and replace `%HOST%` with the address agent is running:

```
[metrics]
statsd_on = True
statsd_host = %HOST%
statsd_port = 8125
statsd_prefix =
```
{{fields "statsd"}}

