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

An example event for `statsd` looks as following:

```json
{
    "@timestamp": "2023-11-28T06:26:54.238Z",
    "agent": {
        "ephemeral_id": "283d2103-181e-4e55-990c-d463765d591a",
        "id": "208488b1-ba3d-4035-b968-4202e1fadc05",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.11.0"
    },
    "airflow": {
        "task_executable": {
            "value": 0
        }
    },
    "data_stream": {
        "dataset": "airflow.statsd",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "208488b1-ba3d-4035-b968-4202e1fadc05",
        "snapshot": false,
        "version": "8.11.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "airflow.statsd",
        "ingested": "2023-11-28T06:26:55Z",
        "module": "statsd"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "d7fd92f5e61644938d48518adcee73ad",
        "ip": "172.20.0.7",
        "mac": "02-42-AC-14-00-07",
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.90.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "server"
    },
    "service": {
        "type": "statsd"
    }
}
```

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| agent.id |  | keyword |  |
| airflow.\*.count | Airflow counters | object | counter |
| airflow.\*.max | Airflow max timers metric | object |  |
| airflow.\*.mean | Airflow mean timers metric | object |  |
| airflow.\*.mean_rate | Airflow mean rate timers metric | object |  |
| airflow.\*.median | Airflow median timers metric | object |  |
| airflow.\*.min | Airflow min timers metric | object |  |
| airflow.\*.stddev | Airflow standard deviation timers metric | object |  |
| airflow.\*.value | Airflow gauges | object | gauge |
| airflow.dag_file | Airflow dag file metadata | keyword |  |
| airflow.dag_id | Airflow dag id metadata | keyword |  |
| airflow.job_name | Airflow job name metadata | keyword |  |
| airflow.operator_name | Airflow operator name metadata | keyword |  |
| airflow.pool_name | Airflow pool name metadata | keyword |  |
| airflow.scheduler_heartbeat.count | Airflow scheduler heartbeat | double |  |
| airflow.status | Airflow status metadata | keyword |  |
| airflow.task_id | Airflow task id metadata | keyword |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |
| cloud.region | Region in which this host is running. | keyword |  |
| container.id | Unique container id. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| event.dataset | Event dataset | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| host | A host is defined as a general computing instance. ECS host.\* fields should be populated with details about the host on which the event happened, or from which the measurement was taken. Host types include hardware, virtual machines, Docker containers, and Kubernetes nodes. | group |  |
| host.containerized | If the host is a container. | boolean |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| service.address | Service address | keyword |  |

