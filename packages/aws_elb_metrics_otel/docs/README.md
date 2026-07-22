# AWS ELB Metrics OpenTelemetry Assets

This package contains Kibana assets for monitoring ELB load balancers with AWS CloudWatch metrics collected by the OpenTelemetry Collector.

The package is **content only**. It provides a curated metrics dashboard, but it does not configure data collection. Use the **AWS CloudWatch OpenTelemetry Input Package** (`aws_cloudwatch_input_otel`) to configure the OpenTelemetry Collector CloudWatch receiver and collect the required AWS service metrics into Elasticsearch.

## Data requirements

- CloudWatch metrics collected by the OpenTelemetry Collector AWS CloudWatch receiver.
- Documents indexed into the `metrics-aws.elb.otel-*` data stream.
- The relevant AWS dimensions for this service, such as resource name, region, and service-specific identifiers.

## Compatibility

Requires Kibana `^9.5.0`.

## Dashboards

This package includes one pre-built Kibana dashboard:

| Name | Description |
|---|---|
| [AWS ELB OTel] Metrics | AWS ELB metrics dashboard for CloudWatch metrics collected by the OpenTelemetry Collector. |

## Alerting Rule Templates
Alert rule templates provide pre-defined configurations for creating alert rules in Kibana.

For more information, refer to the [Elastic documentation](https://www.elastic.co/docs/reference/fleet/alerting-rule-templates).

Alert rule templates require Elastic Stack version 9.2.0 or later.

**The following alert rule templates are available:**

<details>
<summary>View the alert rule templates</summary>

| Name | Description |
|---|---|
| [AWS ELB OTel] High Application Load Balancer 5XX error rate | Alerts when load-balancer-generated 5XX error rate exceeds a tunable threshold. Indicates edge/infrastructure failures such as no healthy targets, connection timeouts, or LB capacity issues. |
| [AWS ELB OTel] Application Load Balancer rejected connections detected | Alerts when the ALB rejects connections because it reached its connection ceiling. A hard capacity-class failure requiring immediate attention. |
| [AWS ELB OTel] High Application Load Balancer target 5XX error rate | Alerts when target-generated 5XX error rate exceeds a tunable threshold for any load balancer target group. Indicates application or backend failures behind the ALB. |
| [AWS ELB OTel] High Application Load Balancer target response time (average) | Alerts when average target response time exceeds a tunable threshold. Indicates typical backend latency degradation even when error rates remain low. |
| [AWS ELB OTel] High Application Load Balancer target response time (tail) | Alerts when peak (maximum) target response time exceeds a tunable threshold. Serves as a tail-latency proxy where CloudWatch percentiles are unavailable. |
| [AWS ELB OTel] Application Load Balancer unhealthy targets detected | Alerts when any target in a target group is failing health checks (UnHealthyHostCount \> 0). Early warning before healthy capacity collapses to zero. |

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
| [AWS ELB OTel] Application Load Balancer request availability 99.5% rolling 30 days | Tracks Application Load Balancer request availability by keeping the combined ELB-generated and target-generated 5XX error rate below 0.5% in each 1-minute interval. Scoped per load balancer and region; aggregates all target groups behind the load balancer. A rolling 30-day target of 99.5% ensures users receive successful responses at the edge. |
| [AWS ELB OTel] Application Load Balancer target response time average 99.5% rolling 30 days | Tracks typical backend latency for Application Load Balancer target groups by keeping average TargetResponseTime below 1 second in each 1-minute interval. Scoped per target group, load balancer, and region. A rolling 30-day target of 99.5% ensures users experience responsive service even when errors are absent. |

</details>


