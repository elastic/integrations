# AWS OpenTelemetry Assets

This package contains Kibana assets for monitoring [AWS](https://aws.amazon.com/) services with data collected by the OpenTelemetry Collector. It ships a family of curated dashboards built on top of Amazon CloudWatch metrics and AWS service logs, giving SREs a consistent, golden-signals view across the most common AWS services.

The package is **content only** — it provides dashboards but does not configure data collection. Use the corresponding input package to set up collection of the required CloudWatch metrics and AWS service logs.

## What's included

The package provides one landing dashboard and a per-service dashboard for each supported AWS service:

| Dashboard | What it covers |
|-----------|----------------|
| **AWS Overview** | Landing page for the AWS dashboard family. One section per service (EC2, Lambda, RDS, ELB, SQS, Fargate) with health KPIs and top-N tables. Click any widget to drill into the corresponding service dashboard. |
| **AWS EC2** | Per-instance compute health: instance status counts, CPU utilization, network in/out, disk read/write and EBS activity, plus top-N instances by CPU, network and disk. |
| **AWS Lambda** | Per-function health: invocations, errors, throttles and dead-letter errors, average duration and concurrent executions, plus top-N functions by invocations, errors and duration. |
| **AWS RDS** | Per-database health: CPU utilization, read/write IOPS, network throughput, freeable memory and connections, plus top-N databases by CPU, connections and IOPS. |
| **AWS ELB** | Per-load-balancer health: request volume, processed bytes, HTTP 4xx/5xx, backend errors, latency, active and rejected connections, plus top-N load balancers by requests, errors and latency. Supports Application (ALB), Network (NLB) and Classic load balancers. |
| **AWS SQS** | Per-queue health: messages sent/deleted, visible vs. not-visible messages, queue depth and oldest message age, plus detection of backlogged, stale and idle queues. |
| **AWS Fargate / ECS** | Per-service container health: CPU and memory utilization, Service Connect bytes, network throughput and running task counts, plus top-N services by CPU, memory and network. |

Each service dashboard classifies entities into health states (for example healthy / hot / saturated / idle) and includes a recent-logs panel that surfaces the relevant service logs alongside the metrics.

## Data requirements

The dashboards read from two complementary data sources, both collected via the OpenTelemetry Collector and routed to Elasticsearch:

- **CloudWatch metrics** — the metric-driven panels query the `metrics-awscloudwatchreceiver.otel-default` data stream, which holds AWS CloudWatch metrics in the CloudWatch Metric Streams OpenTelemetry format.
- **AWS service logs** — the recent-logs panels (and the ELB dashboard's access-log view) read from the `logs-*` data streams.

Configure collection of these data sources using the corresponding input package; this content package only provides the dashboards that visualize the data.

## Compatibility

Requires Kibana `^9.4.0`.