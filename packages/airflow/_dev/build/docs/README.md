# Airflow Integration

Airflow is a platform to programmatically author, schedule and monitor workflows.
Airflow is used to author workflows Directed Acyclic Graphs (DAGs) of tasks. The airflow scheduler executes your tasks on an array of workers while following the specified dependencies.
This integration collects metrics from [Airflow](https://airflow.apache.org/docs/apache-airflow/stable/logging-monitoring/metrics.html) running a
StatsD server where airflow will send metrics to. The default datastream is `StatsD`.

## Compatibility

The Airflow module is tested with Airflow 2.4.0. It should work with version
2.0.0 and later.

### StatsD
StatsD datastream retrieves the Airflow metrics using StatsD server.
The Airflow integration requires [StatsD](https://github.com/statsd/statsd) to receive StatsD metrics. Refer to the link for more details about StatsD.

Add the following lines to your Airflow configuration file e.g. `airflow.cfg` ensuring `statsd_prefix` is left empty and replace `%HOST%` with the address agent is running:

```
[metrics]
statsd_on = True
statsd_host = %HOST%
statsd_port = 8125
statsd_prefix =
```
{{fields "statsd"}}

