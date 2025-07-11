# Docker OpenTelemetry Assets

The Docker OpenTelemetry Assets integration collects metrics from Docker containers using OpenTelemetry Collector. This integration enables monitoring of Docker containers using the OpenTelemetry protocol for metrics collection, providing insights into container performance and resource utilization.

Use the Docker OpenTelemetry Assets integration to monitor container metrics such as CPU usage, memory consumption, disk I/O, and network traffic through the OpenTelemetry Collector. 

For example, if you wanted to monitor container CPU spikes, you could track CPU usage metrics across all containers. Then you can visualize these metrics in dashboards or create alerts when CPU usage exceeds defined thresholds.

## Data streams

The Docker OpenTelemetry Assets integration collects metrics data streams using the OpenTelemetry protocol.

**Metrics** give you insight into the state of Docker containers through OpenTelemetry collection.
Metric data streams collected by the Docker OpenTelemetry Assets integration include `cpu`, `memory`, `disk_io`, and `network` metrics. See more details in the [Metrics](#metrics-reference).

## Setup

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.
