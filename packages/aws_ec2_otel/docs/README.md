# AWS EC2 Metrics OpenTelemetry Assets

This package contains Kibana assets for monitoring EC2 instances with AWS CloudWatch metrics collected by the OpenTelemetry Collector.

The package is **content only**. It provides a curated metrics dashboard, but it does not configure data collection. Configure the OpenTelemetry Collector CloudWatch receiver to collect the required AWS service metrics and export them to Elasticsearch.

## Data requirements

- CloudWatch metrics collected by the OpenTelemetry Collector AWS CloudWatch receiver.
- Documents indexed into the `metrics-aws.ec2.otel-*` data stream.
- The relevant AWS dimensions for this service, such as resource name, region, and service-specific identifiers.

## Compatibility

Requires Kibana `^9.5.0`.

## Dashboards

This package includes one pre-built Kibana dashboard:

| Name | Description |
|---|---|
| [AWS OTel] EC2 | AWS EC2 dashboard for CloudWatch metrics collected by the OpenTelemetry Collector. |

## Alerting Rule Template
Alert rule templates provide pre-defined configurations for creating alert rules in Kibana.

For more information, refer to the [Elastic documentation](https://www.elastic.co/docs/reference/fleet/alerting-rule-templates).

Alert rule templates require Elastic Stack version 9.2.0 or later.

**The following alert rule templates are available:**

<details>
<summary>View the alert rule templates</summary>

| Name | Description |
|---|---|
| [AWS EC2 OTel] CPU surplus credits charged | Alerts when burstable unlimited-mode instances are charged for surplus CPU credits, indicating credit balance exhaustion and overage billing. |
| [AWS EC2 OTel] High CPU utilization | Alerts when sustained average CPU utilization exceeds a threshold, indicating compute saturation and potential scheduling latency. |
| [AWS EC2 OTel] High disk read throughput | Alerts when local disk read throughput exceeds a threshold over the lookback window. Important: the DiskReadBytes metric only measures temporary local disks (instance store) that are physically attached to the host. It does NOT measure EBS volumes, which is how most EC2 instances store their data. If your instances use EBS (the common case), this alert will stay silent — track EBS disk activity using the EBS metrics (AWS/EBS namespace) instead. |
| [AWS EC2 OTel] High disk write throughput | Alerts when local disk write throughput exceeds a threshold over the lookback window. Important: the DiskWriteBytes metric only measures temporary local disks (instance store) that are physically attached to the host. It does NOT measure EBS volumes, which is how most EC2 instances store their data. If your instances use EBS (the common case), this alert will stay silent — track EBS disk activity using the EBS metrics (AWS/EBS namespace) instead. |
| [AWS EC2 OTel] Instance status check failed | Alerts when the EC2 instance status check fails, indicating a guest OS or instance-level problem (exhausted memory, corrupt network config, failed boot). Remediation is typically reboot. |
| [AWS EC2 OTel] Low CPU credit balance | Alerts when CPU credit balance on burstable (T-family) instances drops below a threshold, indicating imminent throttling and application slowdown. |
| [AWS EC2 OTel] System status check failed | Alerts when the EC2 system status check fails, indicating underlying AWS host, hardware, or network impairment. Remediation is typically recover (stop/start on new hardware). |

</details>



## SLO Templates
SLO templates provide pre-defined configurations for creating SLOs in Kibana.

For more information, refer to the [Elastic documentation](https://www.elastic.co/docs/solutions/observability/incident-management/service-level-objectives-slos).

SLO templates require Elastic Stack version 9.4.0 or later.

**The following SLO templates are available:**

<details>
<summary>View the SLO templates</summary>

| Name | Description |
|---|---|
| [AWS EC2 OTel] Status check availability 99.5% rolling 30 days | Per-instance SLO that treats each 5-minute window as healthy when the CloudWatch StatusCheckFailed metric (Maximum statistic) is below 1, meaning neither the system nor instance status check reported a failure. Targets 99.5% of rolling 30-day windows as healthy. This is the primary EC2 platform-availability signal: a failed check indicates AWS-detected impairment requiring recover or reboot. Application-only failures while checks remain at 0 are outside this data source and should be monitored separately. |

</details>


