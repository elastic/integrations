# AWS RDS Metrics OpenTelemetry Assets

This package contains Kibana assets for monitoring RDS database instances with AWS CloudWatch metrics collected by the OpenTelemetry Collector.

The package is **content only**. It provides a curated metrics dashboard, but it does not configure data collection. Use the **AWS CloudWatch OpenTelemetry Input Package** (`aws_cloudwatch_input_otel`) to configure the OpenTelemetry Collector CloudWatch receiver and collect the required AWS service metrics into Elasticsearch.

## Data requirements

- CloudWatch metrics collected by the OpenTelemetry Collector AWS CloudWatch receiver.
- Documents indexed into the `metrics-aws.rds.otel-*` data stream.
- The relevant AWS dimensions for this service, such as resource name, region, and service-specific identifiers.

## Compatibility

Requires Kibana `^9.5.0`.

## Dashboards

This package includes one pre-built Kibana dashboard:

| Name | Description |
|---|---|
| [AWS RDS OTel] Metrics | AWS RDS dashboard for CloudWatch metrics collected by the OpenTelemetry Collector. |

## Alerting Rule Templates
Alert rule templates provide pre-defined configurations for creating alert rules in Kibana.

For more information, refer to the [Elastic documentation](https://www.elastic.co/docs/reference/fleet/alerting-rule-templates).

Alert rule templates require Elastic Stack version 9.2.0 or later.

**The following alert rule templates are available:**

<details>
<summary>View the alert rule templates</summary>

| Name | Description |
|---|---|
| [AWS RDS OTel] Burst balance low | Alerts when gp2 burst balance falls below a percentage floor. Depleted burst credits throttle IOPS and typically precede disk queue depth and latency spikes. |
| [AWS RDS OTel] Checkpoint lag high | Alerts when checkpoint lag exceeds a threshold. Uses the Maximum statistic for worst-case lag. Rising checkpoint lag indicates the instance cannot keep up with write/redo volume. |
| [AWS RDS OTel] CPU utilization high | Alerts when average CPU utilization is sustained above a threshold. Latency rises sharply above ~80% CPU; correlate with SwapUsage for memory-related CPU pressure. |
| [AWS RDS OTel] Database connections high | Alerts when average database connections exceed a threshold. Uses the Average statistic per AWS recommended alarms. CloudWatch does not publish max_connections — set the threshold against your engine limit and normal baseline. |
| [AWS RDS OTel] Disk queue depth high | Alerts when average disk queue depth is sustained above a threshold. High queue depth with plateauing IOPS is the canonical storage I/O saturation signature. |
| [AWS RDS OTel] Free storage space low | Alerts when free storage space on an RDS instance falls below an absolute byte floor. Storage exhaustion is an outage-class risk; total volume size is not published by CloudWatch so percentage thresholds cannot be derived from this source. |
| [AWS RDS OTel] Freeable memory low | Alerts when freeable memory on an RDS instance falls below an absolute byte floor. Persistent low memory leads to swapping and latency; correlate with DatabaseConnections and SwapUsage. |
| [AWS RDS OTel] Read latency high | Alerts when peak read I/O latency exceeds a threshold. Uses the Maximum statistic for worst-case tail latency. Correlate with DiskQueueDepth and ReadIOPS for storage bottlenecks. |
| [AWS RDS OTel] Replica lag high | Alerts when read replica lag exceeds a threshold. Uses the Maximum statistic for worst-case lag. Rising lag means stale read traffic and failover targets behind the primary. |
| [AWS RDS OTel] Swap usage high | Alerts when swap usage exceeds an absolute byte threshold. Non-zero or rising swap indicates memory pressure spilling to disk and degrading performance. |
| [AWS RDS OTel] Write latency high | Alerts when peak write I/O latency exceeds a threshold. Uses the Maximum statistic for worst-case tail latency. Correlate with DiskQueueDepth and WriteIOPS for storage bottlenecks. |

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
| [AWS RDS OTel] Average read latency 99.5% rolling 30 days | Tracks per-I/O read storage latency from CloudWatch RDS metrics. At least 99.5% of 1-minute intervals per DB instance should show average read latency below 10 milliseconds, protecting read-heavy application workloads from storage bottlenecks. |

</details>


