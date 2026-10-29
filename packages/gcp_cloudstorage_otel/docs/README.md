# GCP Cloud Storage OpenTelemetry Assets

This package contains Kibana assets for monitoring [Cloud Storage](https://cloud.google.com/storage) buckets with Google Cloud Monitoring metrics collected by the OpenTelemetry Collector.

The package is **content only**. It does not configure data collection. Use the **[Google Cloud Monitoring OpenTelemetry Input](https://www.elastic.co/docs/reference/integrations/googlecloudmonitor_input_otel)** package (`googlecloudmonitor_input_otel`) to collect Cloud Storage metrics into Elasticsearch.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage
the Elastic Stack on your own hardware.

## Setup

Install the **[Google Cloud Monitoring OpenTelemetry Input](https://www.elastic.co/docs/reference/integrations/googlecloudmonitor_input_otel)** package (`googlecloudmonitor_input_otel`) and configure it to collect Cloud Storage Cloud Monitoring metrics. This content package provides assets that visualize data collected by that input.

When configuring the input package, set the dataset name to `gcp.cloudstorage.otel` so that data is written to the `metrics-gcp.cloudstorage.otel-default` data stream, which these dashboards query.

The assets in this package use the following Cloud Monitoring metric types:

| Metric type | Used for |
|-------------|----------|
| `storage.googleapis.com/api/request_count` | Request volume, error rate, and fault attribution by method and response code. |
| `storage.googleapis.com/network/sent_bytes_count` | Outbound bytes, used for egress volume and cost attribution. |
| `storage.googleapis.com/storage/v2/total_bytes` | Stored bytes by bucket, location, and storage class. |
| `storage.googleapis.com/storage/v2/total_count` | Stored object count by bucket and storage class. |
| `storage.googleapis.com/storage/total_byte_seconds` | Storage consumption over time, used for cost attribution. |
| `storage.googleapis.com/storage/total_bytes` | Stored bytes reported by the earlier metric, kept for buckets that still emit it. |
| `storage.googleapis.com/storage/object_count` | Object count reported by the earlier metric, kept for buckets that still emit it. |
| `storage.googleapis.com/authz/acl_based_object_access_count` | Object reads authorized by ACLs rather than IAM. |
| `storage.googleapis.com/authz/acl_operations_count` | ACL operations, which indicate buckets not yet using uniform bucket-level access. |

## Dashboards

| Dashboard | Description |
|-----------|-------------|
| **[GCP OTel] Cloud Storage Overview** | Estate-wide health for Cloud Storage: request volume and error rate, whether failures are client-side or Google-side, a bucket hex map for spotting the worst offenders, and stored bytes, object counts, and storage consumption broken down by storage class and object type. |
| **[GCP OTel] Cloud Storage Bucket Detail** | Per-bucket deep-dive into request volume by fault class, method, and response code, availability, stored bytes and object counts by storage class, storage consumption, and ACL-based access that indicates buckets not yet using uniform bucket-level access. |

Open **[GCP OTel] Cloud Storage Overview** and click a bucket in the bucket hex map or the bucket ranking table to drill into **[GCP OTel] Cloud Storage Bucket Detail** for that bucket.

## Alerting Rule Templates

The rule templates are published for the v2 alerting engine, which must be enabled in Kibana. Rules created from them detect conditions only; notifications are configured separately, through alerting v2 action policies.

The rule templates query the same `metrics-gcp.cloudstorage.otel-default` data stream as the dashboards, reading it as time series with the ES|QL `TS` command. They are deliberately non-overlapping: authorization failures, other client faults, service faults, and throttling each have their own rule, so one incident pages once and arrives with the runbook that matches its cause.

The rules run on two different clocks, because Cloud Monitoring publishes Cloud Storage metrics on two. Request, error, and byte metrics are roughly 60-second delta counters, so the reliability and traffic rules add up every sample, counting each once even when the collector splits a bucket's metric across several time series, and compare minute-scale slices over windows of 30 minutes to 24 hours. The storage-size and object-count metrics are point-in-time snapshots that Cloud Monitoring recomputes only about once a day, so the capacity rules necessarily use a 14-day window and compare multi-day slices. Expect those two to confirm a trend over days rather than react within hours. Both capacity rules add up a bucket's storage classes hour by hour before comparing, so data that moves between classes under a lifecycle rule or Autoclass is not counted twice. They read the `storage/v2` metrics for live and noncurrent objects, which is the same scope as the earlier metrics, and fall back to the earlier metrics when only those are collected. Either generation can be collected on its own, collecting both does not double the totals, and soft-deleted objects and incomplete multipart uploads are not counted.

Alert rule templates provide pre-defined configurations for creating alert rules in Kibana.

For more information, refer to the [Elastic documentation](https://www.elastic.co/docs/reference/fleet/alerting-rule-templates).

Alert rule templates require Elastic Stack version 9.6.0 or later.

**The following alert rule templates are available:**

<details>
<summary>View the alert rule templates</summary>

| Name | Description |
|---|---|
| [GCP Cloud Storage OTel] Authorization failures rising on a bucket | Fires when the share of PERMISSION_DENIED and UNAUTHENTICATED responses on a bucket steps up sharply against its own recent baseline. Compares the last hour with the preceding three hours, so the signal is change rather than absolute level. This is the characteristic shape of an IAM policy change, a key rotation, or an expired service-account credential. |
| [GCP Cloud Storage OTel] Previously active bucket has stopped serving requests | Fires when a bucket that was consistently busy over the preceding 21 hours has served zero requests for the last three. Buckets with no traffic emit no documents at all rather than zeros, so absence is a real signal: it means a client outage, a collector outage, or a credentials failure at the collector. |
| [GCP Cloud Storage OTel] Client-fault response code surge on a bucket | Fires when any non-authorization client-fault code (NOT_FOUND, FAILED_PRECONDITION, INVALID_ARGUMENT, OUT_OF_RANGE, ALREADY_EXISTS, CANCELLED) steps up at least three-fold against its own 22-hour baseline on a bucket. One alert per bucket and code, because the remediation for each code is completely different. |
| [GCP Cloud Storage OTel] Unexpected egress growth on a bucket | Fires when a bucket's outbound byte rate steps up at least three-fold against its own 18-hour baseline and exceeds an absolute floor. Egress is normally the most expensive axis of a Cloud Storage bill and the one that moves without warning, so this rule covers both the cost-incident and the data-exfiltration case. Reports bytes per request so the responder can immediately tell more requests from bigger objects. |
| [GCP Cloud Storage OTel] Object count outpacing stored bytes on a bucket | Fires when a bucket's object count grows substantially while its average object size falls by more than a quarter over 14 days. This is small-object sprawl: cost shifts from storage to per-operation charges and list performance degrades, and neither is visible on a capacity view that only tracks bytes. |
| [GCP Cloud Storage OTel] Bucket requests throttled by rate limits | Fires when a bucket receives rate-limit or resource-exhaustion responses. This is the definitive saturation signal for Cloud Storage: the bucket is shedding load because demand has grown faster than it can redistribute IO capacity. Reports approximate read and write request rates alongside so the ramp can be judged against Google's ramp-up guidance. |
| [GCP Cloud Storage OTel] Service-fault errors on bucket requests | Fires when a bucket returns service-side, retryable status codes (UNAVAILABLE, INTERNAL, DEADLINE_EXCEEDED, ABORTED and any code the rule does not recognise as a client fault) above 1% of its requests. These codes have a near-zero baseline, so absolute level is the signal. Client-fault codes and rate limiting are deliberately excluded and covered by separate rules. |
| [GCP Cloud Storage OTel] Bucket storage growing faster than expected | Fires when a bucket's stored bytes grow more than 50% over 14 days. Storage metrics are daily snapshots, so this runs on a slow clock and is a capacity and cost-trajectory signal rather than an operational one. Reports the share of bytes sitting in a hot storage class so the lifecycle-policy opportunity is visible from the alert. |

</details>

Cloud Storage reports canonical status strings such as `OK`, `NOT_FOUND`, `PERMISSION_DENIED`, and `UNAVAILABLE` rather than numeric HTTP codes, and the rules split them into caller-attributable faults and service faults so the two classes reach different runbooks. The classification is exclusion-based: anything that is not `OK`, not a listed client fault, and not a throttle is treated as a service fault, so a status code that is new or absent from your estate surfaces for investigation instead of being silently dropped.

Every threshold is a starting point, not a recommendation. Each rule carries a runbook with a triage walkthrough and a tuning section that names the specific condition to adjust for your estate, whether that is the step-change multiplier, a volume floor, or the comparison window.

> **Note**: Google does not publish per-request latency for the `gcs_bucket` monitored resource, so none of this content measures latency. Rate-limit and retryable service-fault responses are the only observable edge of latency degradation, so treat a sustained rise in either as evidence that response times have degraded.

## SLO Templates

The SLO templates track object availability, split by path because a refused read and a refused write have different consequences: a failed read is user-facing, while a failed write risks data loss and upstream backpressure.

SLO templates provide pre-defined configurations for creating SLOs in Kibana.

For more information, refer to the [Elastic documentation](https://www.elastic.co/docs/solutions/observability/incident-management/service-level-objectives-slos).

SLO templates require Elastic Stack version 9.4.0 or later.

**The following SLO templates are available:**

<details>
<summary>View the SLO templates</summary>

| Name | Description |
|---|---|
| [GCP Cloud Storage OTel] Object read availability 99.5% rolling 30 days | Tracks Cloud Storage object-read availability as the share of valid ReadObject requests that complete with an OK status, over a rolling 30 days, per GCP project. Requests rejected for caller-attributable reasons (NOT_FOUND, PERMISSION_DENIED, UNAUTHENTICATED, INVALID_ARGUMENT, FAILED_PRECONDITION, OUT_OF_RANGE, ALREADY_EXISTS, CANCELLED) are excluded from both the numerator and the denominator, mirroring the Valid Requests definition in the Cloud Storage SLA, so the objective reflects storage-side read reliability rather than benign object-existence probing or client misconfiguration. Every other non-OK status consumes error budget, including transient service faults and rate-limit rejections, so status codes not present today still fail safe. A breach means applications could not read object data they were entitled to read. |
| [GCP Cloud Storage OTel] Object write availability 99.5% rolling 30 days | Tracks Cloud Storage object-write availability as the share of valid WriteObject requests that complete with an OK status, over a rolling 30 days, per GCP project. Requests rejected for caller-attributable reasons (NOT_FOUND, PERMISSION_DENIED, UNAUTHENTICATED, INVALID_ARGUMENT, FAILED_PRECONDITION, OUT_OF_RANGE, ALREADY_EXISTS, CANCELLED) are excluded from both the numerator and the denominator, mirroring the Valid Requests definition in the Cloud Storage SLA, so the objective reflects storage-side write reliability rather than optimistic-concurrency contention or client misconfiguration. Every other non-OK status consumes error budget, including transient service faults and rate-limit rejections, so status codes not present today still fail safe. A breach means durable writes were refused, which risks data loss and upstream backpressure. |

</details>



"Valid" follows the Valid Requests definition in the Cloud Storage SLA. Requests rejected for caller-attributable reasons (`NOT_FOUND`, `PERMISSION_DENIED`, `UNAUTHENTICATED`, `INVALID_ARGUMENT`, `FAILED_PRECONDITION`, `OUT_OF_RANGE`, `ALREADY_EXISTS`, `CANCELLED`) are excluded from both the numerator and the denominator. Without that exclusion a blended error rate is dominated by benign object-existence probing, and the objective ends up measuring how often callers ask for objects that are not there rather than how reliably Cloud Storage served them. Every other non-`OK` status consumes error budget, including transient service faults and rate-limit rejections, so codes that are absent today still fail safe.

Both SLOs group by `resource.attributes.project_id` rather than by bucket. Request volume across buckets is extremely skewed, and in the long tail of buckets that see only a handful of requests a single failure reads as a catastrophic percentage. Per-bucket detection is the alerting rules' job; the project is the ownership and billing boundary and carries enough volume for a 99.5% objective to mean something.

There is no latency SLO, and there cannot be one. With no duration metric published for the `gcs_bucket` resource there is nothing for a latency objective to measure.
