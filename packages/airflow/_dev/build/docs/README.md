# Airflow Integration

## Overview

[Airflow](https://airflow.apache.org/docs/apache-airflow/stable/logging-monitoring/metrics.html) is an open-source platform for programmatically authoring, scheduling, and monitoring workflows. It allows users to define workflows as Directed Acyclic Graphs (DAGs) of tasks, which are then executed by the Airflow scheduler on an array of workers while following the specified dependencies.

Use the Airflow integration to:

- Collect detailed metrics from Airflow using StatsD to gain insights into system performance.
- Create informative visualizations to track usage trends, measure key metrics, and derive actionable business insights.
- Monitor your workflows' performance and status in real-time.

## Data streams

The Airflow integration gathers metric data.

Metrics provide insight into the statistics of Airflow. The `Metric` data stream collected by the Airflow integration is `statsd`, enabling users to monitor and troubleshoot the performance of the Airflow instance.

Data stream:

- `statsd`: Collects metrics related to scheduler activities, pool usage, task execution details, executor performance, and worker states in Airflow.

Note:
- Users can monitor and view metrics within the ingested documents for Airflow in the `metrics-*` index pattern from `Discover`.

## Compatibility

The Airflow module is tested with Airflow `2.4.0`. It should work with versions `2.0.0` and later.

## Prerequisites

Users require Elasticsearch to store and search user data, and Kibana to visualize and manage it. They can utilize the hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on their own hardware.

To ingest data from Airflow, users must have [StatsD](https://github.com/statsd/statsd) to receive the same.

## Setup

For step-by-step instructions on how to set up an integration, see the [Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Steps to Setup Airflow

Be sure to follow the official [Airflow Installation Guide](https://airflow.apache.org/docs/apache-airflow/stable/installation/index.html) for the correct installation of Airflow.

Include the following lines in the user's Airflow configuration file (e.g. `airflow.cfg`). Leave `statsd_prefix` empty and replace `%HOST%` with the address where the Agent is running:

```
[metrics]
statsd_on = True
statsd_host = %HOST%
statsd_port = 8125
statsd_prefix =
```

## Validation

Once the integration is set up, you can click on the Assets tab in the Airflow integration to see a list of available dashboards. Choose the dashboard that corresponds to your configured data stream. The dashboard should be populated with the required data.

## Troubleshooting

- Check if the StatsD server is receiving data from Airflow by examining the logs for potential errors.
- Make sure the `%HOST%` placeholder in the Airflow configuration file is replaced with the correct address of the machine where the StatsD server is running.
- If Airflow metrics are not being emitted, confirm that the `[metrics]` section in the `airflow.cfg` file is properly configured as per the instructions above.

## Metrics reference

### Statsd
This is the `statsd` data stream, which collects metrics related to scheduler activities, pool usage, task execution details, executor performance, and worker states in Airflow.

{{event "statsd"}}

{{fields "statsd"}}
