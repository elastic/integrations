# Airflow Integration

## Overview

[Airflow](https://airflow.apache.org/docs/apache-airflow/stable/logging-monitoring/metrics.html) is a platform to programmatically author, schedule and monitor workflows. Airflow is used to author workflows Directed Acyclic Graphs (DAGs) of tasks. The Airflow scheduler executes user's tasks on an array of workers while following the specified dependencies.

Use the Airflow integration to:

- Collect detailed metrics from Airflow using statsd to gain a deeper understanding of system performance.
- Create informative visualizations to track usage trends, measure key logs, and derive actionable business insights.
- Keep track of your workflows performance and status with real-time monitoring capabilities.

## Data streams

The Airflow integration collects metrics data.

Metrics give you insight into the statistics of the Airflow. The `Metric` data stream collected by the Airflow integration is `statsd` so that the user can monitor and troubleshoot the performance of the Airflow instance.

Data stream:

- `statsd`: Collects metrics related to scheduler activities, pool usage, task execution details, executor performance, and worker states in Airflow.

Note:
- Users can monitor and view metrics within the ingested documents for Airflow in the `metrics-*` index pattern from `Discover`.

## Compatibility

The Airflow module is tested with Airflow `2.4.0`. It should work with versions `2.0.0` and later.

## Prerequisites

User need Elasticsearch for storing and searching user's data and Kibana for visualizing and managing it. User can use hosted Elasticsearch Service on Elastic Cloud, which is recommended or self-manage the Elastic Stack on user's own hardware.

In order to ingest data from the Airflow, user must have [statsd](https://github.com/statsd/statsd) to receive statsd metrics.

## Setup

For step-by-step instructions on how to set up an integration, see the [Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Steps to Setup Airflow

To ensure a proper installation of Airflow, please refer to the official [Airflow Installation Guide](https://airflow.apache.org/docs/apache-airflow/stable/installation/index.html).

Add the following lines to user's Airflow configuration file e.g. `airflow.cfg` ensuring `statsd_prefix` is left empty and replace `%HOST%` with the address agent is running:

```
[metrics]
statsd_on = True
statsd_host = %HOST%
statsd_port = 8125
statsd_prefix =
```

## Validation

After the integration is successfully configured, clicking on the Assets tab of the Airflow integration should display a list of available dashboards. Click on the dashboard available for user's configured data stream. It should be populated with the required data.

## Troubleshooting

- To troubleshoot issues with missing metrics on the monitoring dashboard, verify that the `StatsD` server is properly receiving data from Airflow by examining the logs for potential errors.
- Verify that the `%HOST%` placeholder in the Airflow configuration file is replaced with the correct address of the machine where the `StatsD` server is running.
- In case Airflow metrics are not being emitted, confirm that the `[metrics]` section in the `airflow.cfg` file is properly configured as per the instructions above.

## Metrics reference

### Statsd
This is the `statsd` data stream. This data stream collects metrics related to scheduler activities, pool usage, task execution details, executor performance, and worker states in Airflow.

{{event "statsd"}}

{{fields "statsd"}}
