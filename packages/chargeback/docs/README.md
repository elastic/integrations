# Chargeback

_Technical preview: This integration is being developed by Elastic's Customer Engineering team. Please report any issues to the Elastician who shared this integration with you._

The Chargeback integration provides FinOps visibility into Elastic usage across tenants. By integrating data from the [**Elasticsearch Service Billing**](https://www.elastic.co/docs/reference/integrations/ess_billing/) and [**Elasticsearch**](https://www.elastic.co/docs/reference/integrations/elasticsearch/) integrations, it enables the determination of value provided by each deployment, data stream, and tier across the organisation. This allows Centre of Excellence (CoE) teams to accurately allocate costs back to the appropriate tenant.

The integration creates several transforms that aggregate billing and usage data into lookup indices optimized for cost analysis and chargeback reporting.

## What is FinOps?

FinOps is an operational framework and cultural practice aimed at maximizing the business value of cloud usage. It facilitates timely, data-driven decision-making and promotes financial accountability through collaboration among engineering, finance, and business teams.

## Purpose

The Chargeback integration assists organisations in addressing a crucial question:

> **"How is my organisation consuming the Elastic solution, and to which tenants can I allocate these costs?"**

The integration provides a breakdown of chargeable units (ECU/ERU) per:

- Deployment
- Data tier
- Data stream
- Day

Currently, Chargeback calculations consider only Elasticsearch data nodes. Contributions from other assets, like Kibana or ML nodes, are assumed to be shared proportionally among tenants. To incorporate indexing, querying, and storage in a weighted manner, a blended value is created using the following default weights (modifiable):
- Indexing: `20` (applicable only to the hot tier)
- Querying: `20`
- Storage: `40`

This default weighting means storage contributes most to the blended cost calculation, with indexing considered only on the hot tier. Adjust these weights based on your organisation's needs and best judgment.

Chargeback costs are presented based on a configured rate and unit. These are used to display cost in your local currency, for instance `EUR`, with a rate of `0.85` per chargeable unit (ECU/ERU).

## Configuration

Configuration values are stored in the `chargeback_conf_lookup` index. The dashboard automatically applies the correct configuration based on the billing date falling within the `conf_start_date` and `conf_end_date` range.

### Update the default configuration:

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

### Add a new configuration period (for time-based rate changes):

Using `_doc` creates a new document with an auto-generated ID:

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

This allows you to have different rates for different time periods (e.g., quarterly or annual rate changes).

**Configuration Options:**
- `conf_chargeable_unit_rate`: The monetary value per chargeable unit (ECU/ERU) (e.g., 0.85)
- `conf_chargeable_unit_rate_unit`: The currency code (e.g., "EUR", "USD", "GBP")
- `conf_indexing_weight`: Weight for indexing operations in **blended tier** mix (default: 20, only applies to hot tier)
- `conf_query_weight`: Weight for query operations in **blended tier** mix (default: 20)
- `conf_storage_weight`: Weight for storage in **blended tier** mix (default: 40)
- `conf_utilization_memory_weight`: Weight for heap p95 in utilization score (default: 70)
- `conf_utilization_storage_weight`: Weight for disk p95 in utilization score (default: 30)
- `conf_utilization_floor`: Minimum utilization score (0.0–1.0) applied to all deployments regardless of actual usage (default: 0.10). Prevents realized cost from reaching zero for idle or unmonitored clusters.
- `conf_memory_cost_weight`: Weight for illustrative memory split of `chargeable_pool` in datatiers panels (default: 50)
- `conf_storage_cost_weight`: Weight for illustrative storage split of `chargeable_pool` in datatiers panels (default: 50)
- `conf_start_date`: Start date/time for the configuration period (ISO 8601 format)
- `conf_end_date`: End date/time for the configuration period (ISO 8601 format)

## Realized Cost

Realized cost answers: *of the capacity I purchased, how much am I actually using, and what does that cost?*

### Formula

```
util_score        = GREATEST((mem_w × heap_p95 + disk_w × disk_p95) / (mem_w + disk_w), floor)
realized_ecu      = provisioned_ecu × util_score
realized_cost     = realized_ecu × conf_chargeable_unit_rate
```

Where:
- `heap_p95` = p95 heap usage across data nodes (0.0–1.0), sourced from `cluster_capacity_utilization_lookup`. Defaults to 1.0 (100%) when monitoring data is absent.
- `disk_p95` = p95 disk usage across data nodes (0.0–1.0), same source.
- `mem_w` / `disk_w` = `conf_utilization_memory_weight` / `conf_utilization_storage_weight` (default 70 / 30)
- `floor` = `conf_utilization_floor` (default 0.10)

### Why 70 % memory / 30 % storage?

Elasticsearch is a memory-bound workload — heap exhaustion is the primary failure mode and directly impacts query performance. Disk is more manageable via ILM, compression, and tier movement. The 70/30 default reflects this operational reality.

### Why p95?

p95 captures the "reliably busy" signal — it accounts for peak hours without being distorted by brief maintenance spikes (which p99+ would amplify) or washed out like daily averages.

### Why a utilization floor?

Without a floor, idle or unmonitored deployments produce zero realized cost — they appear to consume nothing even though they hold provisioned capacity. A floor of 10 % (default) ensures every deployment contributes proportionally to the shared cost pool, even during quiet periods.

### Decomposition

The `billing_realized_cost_lookup` index stores:
- `memory_contribution_ecu = realized_ecu × mem_w / (mem_w + disk_w)`
- `storage_contribution_ecu = realized_ecu × disk_w / (mem_w + disk_w)`

These always sum to `realized_ecu` and let the trellis visualization show which resource type is driving cost for each deployment.

## Data and Transforms

The integration creates the following transforms to aggregate cost and usage data:

1. **billing_cluster_cost** - Aggregates daily chargeable units (ECU/ERU) per deployment **and SKU** from ESS Billing (`cost_type`, `cost_category`, `is_allocatable`)
2. **billing_realized_pool** - Aggregates daily **allocatable data-tier capacity** per deployment (one row per deployment/day for realized-cost allocation)
3. **billing_realized_cost** - Pre-computes daily **realized cost** per deployment: joins provisioned capacity with utilization metrics and applies the weight-based scoring formula and monetary rate. Output fields: `provisioned_ecu`, `realized_ecu`, `memory_contribution_ecu`, `storage_contribution_ecu`, `util_score`, `realized_cost_amount`. Powers the Realized Cost trellis visualization.
4. **cluster_capacity_utilization** - P95 heap and disk utilization across **data-role nodes** per deployment/day (from `node_stats`)
5. **cluster_deployment_contribution** - Per-deployment usage metrics (indexing, query, storage) from monitoring indices
6. **cluster_datastream_contribution** - Usage per data stream
7. **cluster_tier_contribution** - Usage per data tier
8. **cluster_tier_and_ds_contribution** - Combined tier and data stream usage

These transforms produce lookup indices that are queried by the dashboard using ES|QL LOOKUP JOINs to correlate billing costs with actual usage patterns.

### Transform Auto-Start

All Chargeback transforms start automatically when the integration is installed. No manual intervention is required to start the transforms.

**Performance Note:** On clusters with months of historical monitoring data for multiple deployments, the initial transform execution may process a large volume of data. This can cause temporary performance impact during the first run. The transforms will then run incrementally on their configured schedules (15-60 minute intervals), processing only new data with minimal overhead.

You can verify the transforms are running by navigating to **Stack Management → Transforms** and filtering for `chargeback`.

### Transform Health Monitoring

The integration includes a **Transform Health Monitoring** alert rule template that can be installed from the integration page. This rule monitors all Chargeback transforms and alerts when they encounter issues or failures, providing proactive notification of any problems with data processing.

## Dashboard

Chargeback data can be viewed in the `[Chargeback] Cost and Consumption breakdown` dashboard, which provides collapsible sections:

- **Cost by component (SKU)** — all billable SKUs via `billing_cluster_cost_lookup` (`cost_type` / `cost_category`)
- **Datatiers / utilization** — provisioned capacity vs realized pool, utilization p95, and allocated memory/storage **estimates** (not Cloud invoice lines)
- **Realized Cost** — three Lens panels: (1) stacked area showing aggregate memory vs storage ECU contribution against the provisioned ceiling over time; (2) line chart showing realized monetary cost per deployment over time; (3) summary table with provisioned ECU, realized ECU, utilization %, and cost per deployment.
- **Deployment / tier / data stream** — allocation from `chargeable_pool` × workload shares (not per-SKU ECU)
- **Configuration** — rates and weights

![Cost and Consumption breakdown](../img/chargeback.png)

### Cost reconciliation (FinOps)

Three totals appear on the dashboard; all are valid:

| Total | Source | Use |
|-------|--------|-----|
| **Deployment bill** | `SUM(COALESCE(total_chargeable_units, total_ecu))` over **all** SKUs in `billing_cluster_cost_lookup` | Overview, deployment totals |
| **Provisioned data-tier capacity** | `data_tier_capacity_ecu` in `billing_realized_pool_lookup` | Datatiers “provisioned” |
| **Realized pool** | `chargeable_pool` = capacity × utilization score (ES\|QL) | Tier and data-stream allocation only |

**Do not expect** tier or data-stream allocated units to equal the full deployment bill. Non-allocatable SKUs (ML, Kibana, transfer, snapshots, …) appear in the SKU overview only. The utilization discount is not spread to tiers/streams by design.

When `node_stats` is missing for a deployment/day, utilization defaults to **100%** (`utilization_data_missing` on datatiers panels).

### Upgrading from 0.3.0

From **0.3.1** onward, configuration and billing fields use chargeable-unit names (for example `conf_chargeable_unit_rate` and `total_chargeable_units` instead of `conf_ecu_rate` and `total_ecu`). Dashboard ES|QL uses `COALESCE` across both names; **both columns must exist in the lookup index mapping** or panels fail at query time. From **0.3.2** onward, lookup mappings include legacy ECU names as **field aliases** that point to chargeable-unit fields.

**Upgrading from 0.3.1 to 0.3.2:** The package already defines these aliases in its transform field mappings. For **new installs** (or newly recreated lookup indices), no manual alias creation is required. Existing 0.3.1 lookup indices keep their old mappings, so after upgrading to **0.3.2**:

1. Delete each affected lookup index (`billing_cluster_cost_lookup`, `chargeback_conf_lookup`) and **reset** the corresponding transform so the index is recreated with 0.3.2 mappings (reprocesses historical data; plan for load and sync delay).
2. Start or schedule the `billing_cluster_cost` and `chargeback_conf_lookup` transforms.

If the dashboard was not replaced on upgrade, re-import the Chargeback dashboard saved objects.

If you built your own ES|QL, dashboards, or automation against the lookup indices, prefer the chargeable-unit field names when convenient.

### Upgrading to 0.5.0 (realized cost trellis)

1. Upgrade the Fleet package to **0.5.0**.
2. The new **`billing_realized_cost`** transform starts automatically and creates `billing_realized_cost_lookup`. No action required unless you want to backfill historical data, in which case reset the transform.
3. The **`chargeback_conf_lookup`** transform is bumped to force a reinstall that adds the new `conf_utilization_floor` field (default `0.10`). Reset the transform if the field is missing after upgrade.
4. To customize the utilization floor, update the configuration document (see _Configuration_ section above).

New lookup index: `billing_realized_cost_lookup`.

### Upgrading to 0.4.0 (realized cost)

1. Upgrade the Fleet package to **0.4.0**.
2. **Reset** new transforms: `billing_realized_pool`, `cluster_capacity_utilization`.
3. **Reset** all Chargeback transforms (pipeline **0.4.0**).
4. Ensure the Elasticsearch integration collects **`node_stats`** on monitored clusters (data nodes).
5. Update `chargeback_conf_lookup` if you override utilization or allocated-split weights.

New lookup indices: `billing_realized_pool_lookup`, `cluster_capacity_utilization_lookup`.

## Deployment Groups

The integration supports organizing deployments into logical groups using the `chargeback_group` tag on ESS Billing deployments. This enables cost allocation and filtering by teams, projects, or any organizational structure.

To assign a deployment to a chargeback group, add a tag to your deployment in the Elastic Cloud console in the format:
```
chargeback_group:<group-name>
```

For example: `chargeback_group:team-search` or `chargeback_group:project-analytics`

The `billing_cluster_cost` transform automatically extracts these tags from the `deployment_tags` field in ESS Billing data using runtime mappings. The dashboard includes a deployment group filter to view costs by specific groups, making it easy to track expenses per team or project.

**Note:** Each deployment should have only one `chargeback_group` tag. Having multiple tags can cause issues and lead to unpredictable cost allocation.

## Observability Alerting

Alert rule templates provide pre-defined configurations for creating alert rules in Kibana.

For more information, refer to the [Elastic documentation](https://www.elastic.co/docs/reference/fleet/alerting-rule-templates).

Alert rule templates require Elastic Stack version 9.2.0 or later.

The following alert rule templates are available:

**[Chargeback] Deployment with chargeback group missing usage data**



**[Chargeback] New chargeback group detected**



**[Chargeback] Transform health monitoring**





## Requirements

To use this integration, the following prerequisites must be met:

**Monitoring Cluster:**
- Must be on Elasticsearch version **9.2.0+** due to the use of smart [ES|QL LOOKUP JOIN](https://www.elastic.co/docs/reference/query-languages/esql/esql-lookup-join) (conditional joins) in transforms and dashboard queries
- This is where the Chargeback integration should be installed

**Required Integrations:**
- [**Elasticsearch Service Billing**](https://www.elastic.co/docs/reference/integrations/ess_billing/) integration (v1.4.1+) must be installed and collecting billing data from your Elastic Cloud organization _(ESS / Elastic Cloud only)_
- **[On-Premises Billing](https://github.com/elastic/integrations/tree/main/packages/onprem_billing)** integration (v0.3.3+) as a replacement for ESS Billing when running on-premises (ECE, ECK, self-managed). See that integration's README for ERU/mERU configuration.
- [**Elasticsearch**](https://www.elastic.co/docs/reference/integrations/elasticsearch/) integration (v1.16.0+) must be installed and collecting [usage data](https://www.elastic.co/docs/reference/integrations/elasticsearch/#indices-and-data-streams-usage-analysis) and **`node_stats`** from data nodes on all deployments you want in chargeback calculations

**Required Transforms:**
- The transform `logs-elasticsearch.index_pivot-default-{VERSION}` (from the Elasticsearch integration) must be running to aggregate usage metrics per index

**Data Flow:**
1. ESS Billing data is collected into `metrics-ess_billing.billing-*`
2. Elasticsearch usage data is collected into `metrics-elasticsearch.stack_monitoring.*`, or—when using the Elasticsearch integration index pivot—into indices whose names match `monitoring-indices*` (the default destination is `monitoring-indices`).
3. Chargeback transforms process and correlate this data
4. Dashboard queries the resulting lookup indices using ES|QL

**Note:** This integration must be installed on a centralized monitoring cluster that has visibility to both billing and usage data from your deployments.