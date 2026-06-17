# AWS EC2 OpenTelemetry Assets

Amazon EC2 (Elastic Compute Cloud) provides resizable virtual machine instances that form the compute layer for most AWS workloads.

These assets include alert rules and SLO templates for EC2 infrastructure metrics collected by the OpenTelemetry `awscloudwatchreceiver`. They cover instance availability (status checks), CPU saturation and burstable credit exhaustion, and network and disk throughput health.

## Compatibility

The AWS EC2 OpenTelemetry assets have been tested with OpenTelemetry AWS CloudWatch receiver from [opentelemetry-collector-contrib](https://github.com/open-telemetry/opentelemetry-collector-contrib).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage
the Elastic Stack on your own hardware.

## Setup

### Prerequisites

EC2 publishes infrastructure metrics to CloudWatch automatically for every running instance; no in-guest agent is required for the metrics used by these assets. Before deploying the collector, ensure the credentials used by the receiver can call CloudWatch `GetMetricData` and `ListMetrics` (for metric discovery) in the target AWS account and region. Optionally enable detailed monitoring on instances if you need 1-minute metric resolution instead of the default 5-minute resolution.

### Configuration

Configure the OpenTelemetry Collector or Elastic Distribution of OpenTelemetry (EDOT) Collector with the `awscloudwatchreceiver` to discover EC2 metrics from the `AWS/EC2` namespace and export them to Elasticsearch.

- `<AWS_REGION>` — AWS region where EC2 instances run (for example, `us-east-1`).
- `<ES_ENDPOINT>` — Elasticsearch endpoint URL (for example, `https://my-deployment.es.us-central1.gcp.cloud.es.io:443`).
- `${env:ES_API_KEY}` — API key for Elasticsearch authentication, supplied via the `ES_API_KEY` environment variable.

```yaml
receivers:
  awscloudwatch:
    region: <AWS_REGION>
    metrics:
      collection_interval: 5m
      period: 5m
      delay: 10m
      discovery:
        filters:
          namespace: AWS/EC2
        limit: 500
        stats:
          - Average
          - Sum
          - Maximum

exporters:
  elasticsearch/otel:
    endpoints:
      - <ES_ENDPOINT>
    api_key: ${env:ES_API_KEY}
    mapping:
      mode: otel

service:
  pipelines:
    metrics:
      receivers:
        - awscloudwatch
      exporters:
        - elasticsearch/otel
```

> **Note**: Tune `discovery.limit` if your account has more EC2 metrics than the receiver can scrape per cycle. The `Average`, `Sum`, and `Maximum` statistics are required by the generated alert rules and SLO templates. If you use explicit `queries` instead of `discovery`, include every EC2 metric referenced by the assets (`CPUUtilization`, `StatusCheckFailed`, `StatusCheckFailed_System`, `StatusCheckFailed_Instance`, `CPUCreditBalance`, `CPUSurplusCreditsCharged`, `NetworkIn`, `NetworkOut`, `DiskReadBytes`, `DiskWriteBytes`) with the matching statistics.

## Reference

### Metrics

Refer to the [metadata.yaml](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/awscloudwatchreceiver/metadata.yaml)
of the OpenTelemetry AWS CloudWatch receiver for details on available metrics.

EC2 metrics appear in the `metrics-awscloudwatchreceiver.otel-*` data stream with `attributes.Namespace` set to `AWS/EC2`. Each document carries one metric value in a field named `metrics.amazonaws.com/AWS/EC2/<MetricName>` and is distinguished by `attributes.MetricName`, `attributes.stat` (`Average`, `Sum`, or `Maximum`), and `attributes.InstanceId`.

## Alert rules

| Alert | Trigger | Severity |
|-------|---------|----------|
| **[AWS EC2 OTel] Status check failed** | Combined status check reports a failure (Maximum ≥ 1) within a 10-minute window | Critical |
| **[AWS EC2 OTel] System status check failed** | System status check fails (Maximum ≥ 1) within a 10-minute window | Critical |
| **[AWS EC2 OTel] Instance status check failed** | Instance status check fails (Maximum ≥ 1) within a 10-minute window | Critical |
| **[AWS EC2 OTel] High CPU utilization** | Average CPU utilization exceeds 90% over a 15-minute window | High |
| **[AWS EC2 OTel] Low CPU credit balance** | CPU credit balance drops below 10 over a 15-minute window | High |
| **[AWS EC2 OTel] CPU utilization spike** | Peak CPU utilization exceeds 95% over a 15-minute window | Medium |
| **[AWS EC2 OTel] CPU surplus credits charged** | Surplus CPU credits charged exceed zero over a 15-minute window | Medium |
| **[AWS EC2 OTel] High network ingress** | Inbound network bytes exceed 1 GB over a 15-minute window | Medium |
| **[AWS EC2 OTel] High network egress** | Outbound network bytes exceed 1 GB over a 15-minute window | Medium |
| **[AWS EC2 OTel] High disk read throughput** | Disk read bytes exceed 512 MB over a 15-minute window | Medium |
| **[AWS EC2 OTel] High disk write throughput** | Disk write bytes exceed 512 MB over a 15-minute window | Medium |
| **[AWS EC2 OTel] Network traffic drop** | Both inbound and outbound network bytes fall below 1 KB over a 15-minute window | Medium |

## SLO templates

{{ sloTemplates }}
