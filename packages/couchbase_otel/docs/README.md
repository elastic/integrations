# Couchbase integration assets

Couchbase Server is a distributed, multi-model document database that combines a memory-first key-value and JSON document store with query, index, replication, and optional Sync Gateway for mobile and edge workloads.

These assets help you run Couchbase in production with Elasticsearch and Kibana: four SRE-focused dashboards, seventeen alert rules, and three SLO templates built on the Elastic [Couchbase integration](https://www.elastic.co/docs/reference/integrations/couchbase) (Metricbeat, Filebeat, and related collectors), spanning ten data streams—one node log data set and nine metric data sets for buckets, cluster, query and index, XDCR, and Sync Gateway telemetry.

## Compatibility

These assets are designed for data collected by the Elastic Agent **Couchbase** integration package into the `logs-couchbase.*` and `metrics-couchbase.*` data streams. Use the integration version that matches your Elastic Stack release; see the integration documentation for supported Couchbase Server, Sync Gateway, and Elastic Stack combinations.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage
the Elastic Stack on your own hardware.

## Setup

### Prerequisites

Before data appears in Elasticsearch, configure Couchbase and Sync Gateway so the integration can reach their APIs and metric endpoints:

- Allow outbound network access from Elastic Agent hosts to Couchbase REST endpoints (for example the cluster management port), with credentials that can read cluster and bucket statistics.
- For Sync Gateway, enable the Prometheus-style metrics that the integration scrapes (for example the HTTP `/metrics` exporter), and ensure TLS and authentication match your security policy.
- Confirm the **Node** data stream: the integration collects node-level statistics (CPU, memory, swap, and related fields) into `logs-couchbase.node-default` via the configured input; verify node hostnames or URLs and any HTTP proxy requirements.

Validate connectivity using the Couchbase UI or `curl` against your cluster and Sync Gateway admin and metrics URLs from the same network path the agents use.

### Configuration

Install and enroll Elastic Agent with Fleet (recommended) or use a standalone Agent policy, then add the **Couchbase** integration and assign it to your hosts. Wire outputs to your Elasticsearch cluster using the default shipper settings for your deployment.

**Placeholders**

- `<COUCHBASE_HOST>` — Hostname or IP of a Couchbase node that can serve the REST API (example: `couchbase.internal`).
- `<COUCHBASE_REST_PORT>` — Couchbase REST port (commonly `8091` for non-TLS, or your TLS port).
- `<COUCHBASE_USERNAME>` — Credentials user for Couchbase stats (principle of least privilege).
- `<COUCHBASE_PASSWORD>` — Password or secret reference for that user.
- `<SYNC_GATEWAY_METRICS_URL>` — Base URL for Sync Gateway Prometheus metrics if you collect Sync Gateway data (example: `https://sync-gateway.internal:4986/_metrics`).
- `<AGENT_POLICY_NAME>` — Fleet policy name that receives the Couchbase integration.

Apply equivalent settings in the Fleet UI (**Integrations → Couchbase → Add Couchbase**), or reflect them in exported policy YAML. Tune data stream namespace, collection period, and SSL options to match your environment; see the [Couchbase integration](https://www.elastic.co/docs/reference/integrations/couchbase) reference for all variables and advanced options.

> **Note**: Generated dashboards, alerts, and SLOs assume default dataset names such as `metrics-couchbase.bucket-default` and `logs-couchbase.node-default`. If you change the integration’s `namespace`, update index patterns or saved object references accordingly.

## Reference

### Metrics

Refer to the [Couchbase integration](https://www.elastic.co/docs/reference/integrations/couchbase) documentation and package `fields` definitions for metric field descriptions across datasets including `couchbase.bucket`, `couchbase.cluster`, `couchbase.query_index`, `couchbase.xdcr`, `couchbase.resource`, `couchbase.database_stats`, `couchbase.cache`, `couchbase.cbl_replication`, and `couchbase.miscellaneous`.

### Logs

The `couchbase.node` log data stream carries node-level operational measurements (for example CPU, memory, swap, operations) ingested for this integration configuration. Treat it as structured operational telemetry indexed under `logs-couchbase.node-default` when building queries, alerts, and SLOs that target node statistics.

## Dashboards

| Dashboard | Description |
|-----------|-------------|
| **[Couchbase] SRE Cluster overview** | Cluster health, query service, node utilization, bucket throughput, and XDCR backlog in one operational view. |
| **[Couchbase] SRE Capacity planning** | Headroom for RAM, disk, and buckets — disk fetches, quotas, and index service memory. |
| **[Couchbase] SRE Replication health** | XDCR backlog, throttling, and Couchbase Lite replication posture (catch-up, conflicts, sync cost). |
| **[Couchbase] SRE Sync Gateway operations** | Sync Gateway process health, DCP lag gauge, document throughput, channel cache, and security counters. |

## Alert rules

| Alert | Trigger | Severity |
|-------|---------|----------|
| **[Couchbase] Bucket disk fetches (working set pressure)** | Disk fetch count indicates the working set does not fit in RAM (threshold filters noise). | High |
| **[Couchbase] CBL push conflict rate high** | Couchbase Lite push write conflict rate per database exceeds the threshold. | High |
| **[Couchbase] Cluster HDD free space low** | Cluster free disk space falls below the configured floor. | High |
| **[Couchbase] Cluster RAM quota critically high** | Cluster-wide RAM quota utilization exceeds a critical percentage. | Critical |
| **[Couchbase] High bucket RAM quota usage** | Any bucket’s RAM quota usage in the lookback window exceeds the threshold. | High |
| **[Couchbase] Index service RAM saturation** | Index service RAM usage percentage exceeds the threshold. | High |
| **[Couchbase] N1QL query latency high** | Average N1QL request time is above the configured threshold (seconds). | High |
| **[Couchbase] Node CPU utilization high** | Average node CPU utilization over the window exceeds the threshold (node logs stream). | High |
| **[Couchbase] Node swap usage detected** | Non-zero swap on nodes (memory pressure signal). | High |
| **[Couchbase] Shared bucket import error rate** | Shared bucket document import error rate is elevated on Sync Gateway. | High |
| **[Couchbase] Sync Gateway authentication failure rate** | Failed authentication rate per database exceeds the threshold. | High |
| **[Couchbase] Sync Gateway error and warning rate high** | Combined Sync Gateway error and warning counter rate exceeds the threshold. | High |
| **[Couchbase] Sync Gateway process CPU high** | Sync Gateway process CPU percentage is sustained above the threshold. | High |
| **[Couchbase] Sync Gateway security access error rate** | Security access error rate per database exceeds the threshold. | High |
| **[Couchbase] XDCR destination backoff** | XDCR backoff indicates destination-side throttling. | High |
| **[Couchbase] XDCR out-of-memory errors** | XDCR out-of-memory error counter is non-zero in the evaluation window. | Critical |
| **[Couchbase] XDCR replication backlog high** | XDCR items remaining (backlog) is above the threshold. | High |

## SLO templates

| SLO | Target | Window | Description |
|-----|--------|--------|-------------|
| **[Couchbase OTel] Bucket RAM quota usage 99.5% rolling 30 days** | 99.5% | 30-day rolling | Goal that nearly all evaluation windows keep per-bucket RAM quota usage below 85% to limit ejections and disk fetches. |
| **[Couchbase OTel] N1QL query latency 99.5% rolling 30 days** | 99.5% | 30-day rolling | Goal that average N1QL execution time stays below one second per collecting host through most short windows. |
| **[Couchbase OTel] XDCR items backlog 99.5% rolling 30 days** | 99.5% | 30-day rolling | Goal that XDCR items remaining stays below five hundred per collecting host through most short windows. |
