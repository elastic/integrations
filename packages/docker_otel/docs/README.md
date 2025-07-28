# Docker OpenTelemetry Assets

The Docker OpenTelemetry Assets content package provides out-of-the-box dashboards for visualizing container performance and resource utilization metrics such as CPU usage, memory consumption, disk I/O, and network traffic from Docker hosts running OpenTelemetry Collector with the Docker Stats Receiver.

For example, if you wanted to monitor container CPU spikes, you could track CPU usage metrics across all containers. Then you can visualize these metrics in dashboards or create alerts when CPU usage exceeds defined thresholds.

## Setup

The minimal required configuration for the Docker Stats Receiver is:

```yaml
receivers:
  docker_stats:
```

Additional configuration options are available in the [OpenTelemetry Docker Stats Receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/dockerstatsreceiver/README.md) documentation. The configuration options available will depend on the version of the OpenTelemetry Collector you are using.