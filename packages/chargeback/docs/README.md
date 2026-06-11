# Chargeback

_Technical preview: This integration is being developed by Elastic's Customer Engineering team. Please report any issues to the Elastician who shared this integration with you._

The Chargeback integration provides FinOps visibility into Elastic usage across tenants. By integrating data from the [**Elasticsearch Service Billing**](https://www.elastic.co/docs/reference/integrations/ess_billing/) and [**Elasticsearch**](https://www.elastic.co/docs/reference/integrations/elasticsearch/) integrations, it enables the determination of value provided by each deployment, data stream, and tier across the organisation. This allows Centre of Excellence (CoE) teams to accurately allocate costs back to the appropriate tenant.

## What is FinOps?

FinOps is an operational framework and cultural practice aimed at maximizing the business value of cloud usage. It facilitates timely, data-driven decision-making and promotes financial accountability through collaboration among engineering, finance, and business teams.

## Purpose

The Chargeback integration assists organisations in addressing a crucial question:

> **"How is my organisation consuming the Elastic solution, and to which tenants can I allocate these costs?"**

The integration provides a breakdown of chargeable units (ECU/ERU) per deployment, data tier, data stream, and day.

Chargeback costs are presented based on a configured rate and unit, used to convert raw consumption (ECU or ERU) into your preferred currency (for example `EUR` at a rate of `0.85` per chargeable unit).

## Requirements

**Monitoring cluster:**
- Must be on Elasticsearch version **9.2.0+** due to the use of smart [ES|QL LOOKUP JOIN](https://www.elastic.co/docs/reference/query-languages/esql/esql-lookup-join) (conditional joins) in transforms and dashboard queries.
- Kibana version **9.4.0+** is required for package **0.5.0** and later. **Kibana 9.3 is not supported** — Billing and Usage dashboards fail to render (`No embeddable factory found for type: vis`) and lack GA support for ES|QL multi-select variable controls (`MV_CONTAINS` filtering).
- This is where the Chargeback integration should be installed.

**Required integrations:**
- [**Elasticsearch Service Billing**](https://www.elastic.co/docs/reference/integrations/ess_billing/) integration (v1.4.1+) must be installed and collecting billing data from your Elastic Cloud organisation (ESS / Elastic Cloud only).
- **[On-Premises Billing](https://github.com/elastic/integrations/tree/main/packages/onprem_billing)** integration (v0.3.3+) as a replacement for ESS Billing when running on-premises (ECE, ECK, self-managed). See that integration's README for ERU/mERU configuration.
- [**Elasticsearch**](https://www.elastic.co/docs/reference/integrations/elasticsearch/) integration (v1.16.0+) must be **installed and actively running** on all monitored deployments, with the following datasets enabled:
  - **Index stats** (`elasticsearch.index` / `elasticsearch.stack_monitoring.index`) — required for tier and data stream cost allocation. The `logs-elasticsearch.index_pivot` transform must be running to aggregate these into `monitoring-indices`.
  - **Node stats** from data nodes — required for the realized cost utilization score (`cluster_capacity_utilization` transform). Node stats are read from `metrics-elasticsearch.stack_monitoring.node_stats-*` (Elasticsearch integration), `.monitoring-es-*` (cloud/on-prem monitoring), or `metricbeat-*` (Metricbeat) depending on your deployment type. They are **not** available in `monitoring-indices`. Without node stats, utilization defaults to 100% and no utilization discount is applied.

**Required transforms:**
- The transform `logs-elasticsearch.index_pivot-default-{VERSION}` (from the Elasticsearch integration) must be running to aggregate usage metrics per index into `monitoring-indices`.

**Data flow:**
1. ESS Billing data is collected into `metrics-ess_billing.billing-*`.
2. Elasticsearch index usage data is aggregated into `monitoring-indices*` by the Elasticsearch integration index pivot transform.
3. Elasticsearch node stats flow into `metrics-elasticsearch.stack_monitoring.node_stats-*` via the Elasticsearch integration's node stats dataset.
4. Chargeback transforms process and correlate this data.
5. Dashboard queries the resulting lookup indices using ES|QL.

## Configuration

Configuration values are stored in the `chargeback_conf_lookup` index. The dashboard automatically applies the correct configuration based on the billing date falling within the `conf_start_date` and `conf_end_date` range.

### Update the default configuration

Using `_update/config` updates the document with ID `config`:

```
POST chargeback_conf_lookup/_update/config
{
  "doc": {
    "conf_chargeable_unit_rate": 0.85,
    "conf_chargeable_unit_rate_unit": "EUR",
    "conf_indexing_weight": 20,
    "conf_query_weight": 20,
    "conf_storage_weight": 40,
    "conf_utilization_memory_weight": 70,
    "conf_utilization_storage_weight": 30,
    "conf_utilization_floor": 0.10,
    "conf_memory_cost_weight": 50,
    "conf_storage_cost_weight": 50,
    "conf_start_date": "2024-01-01T00:00:00.000Z",
    "conf_end_date": "2024-12-31T23:59:59.999Z"
  }
}
```

### Add a new configuration period

Using `_doc` creates a new document with an auto-generated ID, allowing different rates or weights for different time periods (for example Q1 vs Q2 rates):

```
POST chargeback_conf_lookup/_doc
{
  "conf_chargeable_unit_rate": 0.95,
  "conf_chargeable_unit_rate_unit": "EUR",
  "conf_indexing_weight": 20,
  "conf_query_weight": 20,
  "conf_storage_weight": 40,
  "conf_start_date": "2025-01-01T00:00:00.000Z",
  "conf_end_date": "2025-12-31T23:59:59.999Z"
}
```

### Configuration reference

**Rate and currency:**
- `conf_chargeable_unit_rate`: monetary value per chargeable unit (ECU/ERU), for example `0.85`
- `conf_chargeable_unit_rate_unit`: currency code, for example `"EUR"`, `"USD"`, `"GBP"`

**Blended cost weights** (determine how indexing, querying, and storage activity are combined into a single cost figure):
- `conf_indexing_weight`: weight for indexing operations (default: `20`, applies to hot tier only)
- `conf_query_weight`: weight for query operations (default: `20`)
- `conf_storage_weight`: weight for storage (default: `40`)

**Utilization score weights** (determine how heap and disk metrics are combined into the utilization score):
- `conf_utilization_memory_weight`: weight for heap p95 in utilization score (default: `70`)
- `conf_utilization_storage_weight`: weight for disk p95 in utilization score (default: `30`)
- `conf_utilization_floor`: minimum utilization score applied to all deployments (default: `0.10`). Prevents realized cost from reaching zero for idle or unmonitored clusters.

**Memory/storage cost split** (illustrative decomposition of the chargeable pool shown in the Usage and Cost Allocation dashboard):
- `conf_memory_cost_weight`: weight for memory contribution display (default: `50`)
- `conf_storage_cost_weight`: weight for storage contribution display (default: `50`)

**Date window:**
- `conf_start_date`: start date/time for the configuration period (ISO 8601 format)
- `conf_end_date`: end date/time for the configuration period (ISO 8601 format)

## Realized Cost

Realized cost answers: *of the capacity I purchased, how much am I actually using, and what does that cost?*

### Formula

```
util_score    = GREATEST((mem_w x heap_p95 + disk_w x disk_p95) / (mem_w + disk_w), floor)
chargeable_pool = provisioned_ecu x util_score
realized_cost   = chargeable_pool x conf_chargeable_unit_rate
```

Where:
- `heap_p95` = p95 heap usage across data nodes (0.0 to 1.0), sourced from `cluster_capacity_utilization_lookup`. Defaults to 1.0 (100%) when monitoring data is absent.
- `disk_p95` = p95 disk usage across data nodes (0.0 to 1.0), same source.
- `mem_w` / `disk_w` = `conf_utilization_memory_weight` / `conf_utilization_storage_weight` (default 70 / 30)
- `floor` = `conf_utilization_floor` (default 0.10)

**Why 70% memory / 30% storage?** Elasticsearch is a memory-bound workload; heap exhaustion is the primary failure mode and directly impacts query performance. Disk is more manageable via ILM, compression, and tier movement. The 70/30 default reflects this operational reality.

**Why p95?** p95 captures the "reliably busy" signal: it accounts for peak hours without being distorted by brief maintenance spikes (which p99+ would amplify) or being washed out like daily averages.

**Why a utilization floor?** Without a floor, idle or unmonitored deployments produce zero realized cost; they appear to consume nothing even though they hold provisioned capacity. A floor of 10% (default) ensures every deployment contributes proportionally to the shared cost pool, even during quiet periods.

## Data and Transforms

The integration creates eight transforms to aggregate cost and usage data:

**Billing transforms:**
1. **`billing_cluster_cost`**: aggregates daily chargeable units (ECU/ERU) per deployment and SKU from ESS Billing, adding `cost_type`, `cost_category`, and `is_allocatable` classification.
2. **`billing_realized_pool`**: aggregates daily allocatable data-tier capacity per deployment (the provisioned ECU ceiling for data nodes only).
3. **`chargeback_conf_lookup`**: configuration bootstrap; creates the `chargeback_conf_lookup` index with default values on install.

**Utilization transforms:**
4. **`cluster_capacity_utilization`**: computes p95 heap and disk utilization across data-role nodes per deployment/day from `node_stats`.

**Usage transforms** (from monitoring indices):
5. **`cluster_deployment_contribution`**: indexing, querying, and storage metrics per deployment/day.
6. **`cluster_datastream_contribution`**: same metrics split by data stream.
7. **`cluster_tier_contribution`**: same metrics split by data tier.
8. **`cluster_tier_and_ds_contribution`**: same metrics split by both tier and data stream.

These transforms produce lookup indices queried by the dashboards using ES|QL LOOKUP JOINs.

### Transform auto-start

All Chargeback transforms start automatically when the integration is installed.

The `cluster_capacity_utilization` transform reads from broad monitoring source indices covering all deployment types. To avoid a heavy historical backfill that could impact cluster performance on first run, it is configured to process only the last 26 hours of data — building utilization from the current day forward rather than historically. Utilization data from before installation is not backfilled; the 100% default applies until the transform has run for its first full day.

You can verify the transforms are running by navigating to **Stack Management > Transforms** and filtering for `chargeback`.

### Transform health monitoring

The integration includes a **Transform Health Monitoring** alert rule template that can be installed from the integration page. This rule monitors all Chargeback transforms and alerts when they encounter issues or failures.

## Dashboards

Chargeback ships three focused dashboards with a navigation bar linking between them.

### [Chargeback] Billing Components Overview

Answers: *what did we spend and where did it go?*

**Source:** `billing_cluster_cost_lookup` (full invoice, all SKUs). Totals in this dashboard equal the full Elastic invoice.

Sections:
- **Deployment group statistics**: total billing spend and trend per chargeback group. Use this for internal chargeback allocation by team or cost centre.
- **Component statistics**: cost broken down by billing component (`cost_type`: datahot/datacontent, datawarm, ml, kibana, snapshots, data-transfer, etc.) and FinOps category (`cost_category`: data_tier, platform, transfer, snapshot, onprem, other).

![Billing Components Overview](../img/chargeback-billing-overview.png)

### [Chargeback] Usage and Cost Allocation

Answers: *which data streams and tiers drive cost, and how efficiently are we using capacity?*

**Source:** `cluster_tier_contribution_lookup` and related usage lookups. Totals reflect the chargeable pool (allocatable data-tier ECU discounted by utilization) and will not equal the full invoice. ML, Kibana, snapshots, and data transfer are excluded.

Sections:
- **Deployment cost allocation (usage-based)**: normalized cost per deployment split by data tier (usage-weighted). Shows which deployments consume the most of their chargeable pool across tiers.
- **Datatiers / utilization**: provisioned capacity vs chargeable pool, utilization p95 per deployment.
- **Data tier and data stream overview**: top-20 data streams by indexing / query / storage cost, blended cost totals, workload breakdown by tier.
- **Data tier and data stream per day**: time-series panels (indexing, querying, storage, blended) broken out by data stream and data tier (usage-based), including absolute cost and percentage share.

![Usage and Cost Allocation](../img/chargeback-usage-allocation.png)

### [Chargeback] Configuration

Reference dashboard showing all active configuration values: conversion rate, date windows, blended cost weights, utilization score weights, and memory/storage cost split.

![Configuration](../img/chargeback-configuration.png)

### Cost reconciliation

Two distinct totals appear across the dashboards; both are valid and intentionally different:

| Total | Source | Dashboard |
|---|---|---|
| **Full deployment bill** | `SUM(total_chargeable_units)` over all SKUs in `billing_cluster_cost_lookup` | Billing Components Overview |
| **Chargeable pool** | `billing_realized_pool_lookup` capacity x utilization score | Usage and Cost Allocation |

Do not expect the chargeable pool to equal the full deployment bill. Non-allocatable SKUs (ML, Kibana, transfer, snapshots) appear in the Billing Components Overview only. The utilization discount is not spread to tiers or data streams by design.

When `node_stats` is missing for a deployment/day, utilization defaults to 100%.

## Deployment Groups

The integration supports organising deployments into logical groups using the `chargeback_group` tag on ESS Billing deployments. This enables cost allocation and filtering by team, project, or any organisational structure.

To assign a deployment to a chargeback group, add a tag in the Elastic Cloud console in the format:

```
chargeback_group:<group-name>
```

For example: `chargeback_group:team-search` or `chargeback_group:project-analytics`.

The `billing_cluster_cost` transform automatically extracts these tags from the `deployment_tags` field in ESS Billing data. Each deployment should have only one `chargeback_group` tag; multiple tags can produce unpredictable cost allocation.

## Observability Alerting

Three alert rule templates are included and can be installed from the integration page. Alert rule templates require Elastic Stack version 9.2.0 or later.

**[Chargeback] Deployment with chargeback group missing usage data:** alerts when a deployment that has a chargeback group assigned is not sending usage data to the monitoring cluster. This prevents silent gaps in cost allocation.

**[Chargeback] New chargeback group detected:** notifies when a new `chargeback_group` tag appears on a deployment. Use this to ensure new teams or projects are accounted for in your chargeback model.

**[Chargeback] Transform health monitoring:** monitors all Chargeback transforms and alerts when they encounter failures or fall behind on processing. Requires all transforms to be running before activation.

For more information, refer to the [Elastic documentation](https://www.elastic.co/docs/reference/fleet/alerting-rule-templates).

## Upgrade Notes

### Upgrading to 0.5.0

1. Upgrade the Fleet package to **0.5.0**.
2. Upgrade Kibana to **9.4.0+** before installing 0.5.0. Kibana 9.3 cannot render the updated Billing and Usage dashboards.
3. Transforms are reinstalled with `fleet_transform_version: 0.5.0` (pipeline logic unchanged). No lookup index recreation is required.
4. The Billing and Usage dashboards are replaced with versions that use chained ES|QL variable controls instead of legacy options-list controls. Delete stale dashboard saved objects from **Stack Management > Saved Objects** if duplicates appear after upgrade.

### Upgrading to 0.4.0

1. Upgrade the Fleet package to **0.4.0**.
2. The two new transforms (`billing_realized_pool`, `cluster_capacity_utilization`) are created and auto-started.
3. Reset the `billing_cluster_cost` transform to backfill `cost_type`, `cost_category`, and `is_allocatable` into existing lookup documents. Until backfill completes, the Component statistics panels will show no data.
4. Ensure the Elasticsearch integration collects **`node_stats`** from data nodes. Without this, utilization defaults to 100%.
5. The old `[Chargeback] Cost and Consumption breakdown` dashboard is replaced by three new dashboards. Delete the old dashboard from **Stack Management > Saved Objects** if it is not removed automatically.

### Upgrading from 0.3.1 to 0.3.2

Lookup mappings were updated to include legacy ECU field aliases (`total_ecu`, `conf_ecu_rate`, `conf_ecu_rate_unit`) pointing to chargeable-unit fields. Existing 0.3.1 lookup indices retain old mappings. After upgrading:

1. Delete each affected lookup index (`billing_cluster_cost_lookup`, `chargeback_conf_lookup`) and reset the corresponding transform so the index is recreated with 0.3.2 mappings.
2. Start or schedule the `billing_cluster_cost` and `chargeback_conf_lookup` transforms.

If the dashboard was not replaced on upgrade, re-import the Chargeback dashboard saved objects.

### Upgrading from 0.2.x to 0.3.0

Field names changed from ECU to chargeable units: `total_ecu` to `total_chargeable_units`, `conf_ecu_rate` to `conf_chargeable_unit_rate`, `conf_ecu_rate_unit` to `conf_chargeable_unit_rate_unit`. Dashboard ES|QL uses `COALESCE` across both names; both columns must exist in the lookup index mapping or panels fail at query time.
