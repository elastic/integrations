# Chargeback

_Technical preview: This integration is being developed by Elastic's Customer Engineering team. Report any issues to the Elastician who shared this integration with you._

The Chargeback integration provides FinOps visibility into Elastic usage across tenants. Using built-in Elastic Agent CEL collection alongside optional data from the [**Elasticsearch Service Billing**](https://www.elastic.co/docs/reference/integrations/ess_billing/), On-Premises Billing, and [**Elasticsearch**](https://www.elastic.co/docs/reference/integrations/elasticsearch/) integrations, it determines the cost and workload share of each deployment, data tier, and data stream across an organization so Center of Excellence (CoE) teams can allocate costs back to the appropriate tenant.

## What is FinOps?

FinOps is an operational framework and cultural practice aimed at maximizing the business value of cloud usage. It facilitates timely, data-driven decision-making and promotes financial accountability through collaboration among engineering, finance, and business teams.

## Purpose

The Chargeback integration assists organizations in addressing a crucial question:

> **"How is your organization consuming the Elastic solution, and to which tenants can you allocate these costs?"**

The integration provides a breakdown of chargeable units (ECU/ERU) per deployment, data tier, data stream, and day.

Chargeback costs are presented based on a configured rate and unit, used to convert raw consumption (ECU or ERU) into your preferred currency (for example `EUR` at a rate of `0.85` per chargeable unit).

## Requirements

**Monitoring cluster:**
- Must be on Elasticsearch version **9.2.0+** due to the use of smart [ES|QL LOOKUP JOIN](https://www.elastic.co/docs/reference/query-languages/esql/esql-lookup-join) (conditional joins) in transforms and dashboard queries.
- Run a single Fleet-managed **Elastic Agent** on an agent policy with the **Chargeback** integration enabled (or install assets alongside existing billing and monitoring producers).

**Self-contained data collection, On-Premises billing prerequisite, and legacy coexistence:**
- Chargeback collects Elastic Cloud billing, index/tier usage, and node utilization telemetry directly via Elastic Agent CEL inputs:
  - `metrics-chargeback.billing-*`: Elastic Cloud Hosted (ECH) and Serverless billing line items across all project types, deployment tags (`chargeback_group:*`), regions, configuration snapshots, and optional organization credit commitments (`collect_ess_credits`).
  - `metrics-chargeback.usage-*`: 10-minute reset-aware per-index usage metrics harvested via `/_stats` and `/_settings` (`_tier_preference`, `creation_date`, computed `age`) on ECH and self-managed clusters (`primaries.store.total_data_set_size_in_bytes`) and `/_cat/indices` on Cloud Serverless projects, attributing timestamped counter intervals across UTC days and reporting observation gaps.
  - `metrics-chargeback.node_stats-*`: 15-minute `/_nodes/_all/stats/jvm,fs` samples across data-role nodes for realized capacity utilization scoring.
- **Self-managed / On-Premises billing prerequisite**: Because the native `chargeback.billing` stream queries Elastic Cloud Billing APIs, **self-managed / On-Premises** deployments (including Hub-only policies where `organization_id` and `cloud_api_key` are left empty) **require On-Premises Billing** (`metrics-ess_billing.billing-onprem*`) or a compatible billing producer writing `ess.billing.*` (`onprem_node`) records into `metrics-ess_billing.billing-*` so deployment cost and realized-pool dashboards have billing inputs to allocate.
- **Existing collector coexistence**: **On-Premises Billing** (`metrics-ess_billing.billing-onprem*`), **ESS Billing** (`metrics-ess_billing.billing-*`), **Elasticsearch** (`monitoring-indices*`, `metrics-elasticsearch.stack_monitoring.node_stats*`, `.monitoring-es-*`, and `metricbeat-*`), and Cross-Cluster Search (`*:monitoring-indices*`) are supported side by side. When both native `chargeback.*` and legacy streams report the same deployment and UTC day, Chargeback transforms retain legacy rows until native samples cover the full day across contributing nodes and indices so totals are neither double-counted nor truncated during mid-day cutover.

**Opt-in compatibility aliases for stock ESS Billing and Elasticsearch Consumption dashboards:**
- Chargeback populates compatibility fields on `chargeback_lookup.dest_billing_cluster_cost-1` (aliased as `chargeback_lookup.billing_cluster_cost`), `chargeback_lookup.dest_billing_credits-1` (aliased as `chargeback_lookup.billing_credits`), and `metrics-chargeback.usage-*` (`doc_type: index_usage`, 10-minute per-index samples) without automatically attaching index names owned by `ess_billing` or `elasticsearch` (`index_pivot`).
- On standalone clusters that do not run separate `ess_billing` or `elasticsearch` (`index_pivot`) policies, install the dashboard assets only under **Management -> Integrations -> ESS Billing / Elasticsearch -> Assets -> Install assets**, enable **Collect ESS Credit Commitment Data (for stock ESS Billing Credits dashboard)** (`collect_ess_credits`) if using the Credits dashboard, and attach the opt-in lookup and filtered data-stream aliases in Dev Tools:

```json
POST /_aliases
{
  "actions": [
    { "add": { "index": "chargeback_lookup.dest_billing_cluster_cost-*", "alias": "metrics-ess_billing.billing-chargeback" } },
    { "add": { "index": "chargeback_lookup.dest_billing_credits-*", "alias": "metrics-ess_billing.credits-chargeback" } },
    { "add": { "index": "metrics-chargeback.usage-*", "alias": "monitoring-indices", "filter": { "term": { "doc_type": "index_usage" } } } }
  ]
}
```

**Data flow:**
1. Elastic Agent collects billing into `metrics-chargeback.billing-*`, index/tier usage into `metrics-chargeback.usage-*`, and node stats into `metrics-chargeback.node_stats-*` (alongside On-Premises Billing or any existing monitoring streams).
2. Chargeback continuous transforms (`5m` configuration sync and `60m` billing, credit commitment, usage, and utilization rollups) aggregate and enrich this telemetry into eight `lookup`-mode indices and one credit-commitment compatibility index.
3. Chargeback dashboards (and optional stock dashboards) query the lookup indices via ES|QL and Lens.

## Configuration

Credentials, currency settings, optional credit commitments, and cost/utilization weights are configured in Kibana under **Management -> Fleet -> Agent Policies -> Chargeback** and synced into `chargeback_conf_lookup` (`_id: config`) by the `chargeback_conf_lookup` continuous transform when `sync_fleet_config` is enabled.

### Shared Connection Settings (`Elastic Cloud & Cluster Access`)
- **Organization ID (`organization_id`)**: Optional Elastic Cloud organization ID. Leave empty for On-Premises or local Hub-only collection (requires On-Premises Billing or a compatible billing producer for cost dashboards).
- **Elastic Cloud API Key (`cloud_api_key`)**: Optional API key with **Billing Admin** role and Cloud deployment or Serverless project read access. Leave empty for On-Premises or local Hub-only collection (requires On-Premises Billing or a compatible billing producer for cost dashboards).
- **Local / Hub Elasticsearch URL (`hub_es_url`)** and **Local / Hub Elasticsearch API Key (`hub_es_api_key`)**: Optional direct endpoint and API key for harvesting the local or self-managed Hub cluster.
- **Target Deployment Elasticsearch API Keys (`deployment_api_keys`)**: Optional comma-separated `<deployment_id_or_name>:<encoded_api_key>` entries for direct harvesting of remote ECH deployments or Serverless projects.
- **Sync Fleet Rate & Weight Settings to Configuration Lookup (`sync_fleet_config`)**: Emits daily `config_snapshot` events into `chargeback_conf_lookup` across whichever streams are enabled (default: `true`). Set to `false` to preserve manual edits or custom multi-period rows in `chargeback_conf_lookup`. On assets-only installations without a Chargeback Agent policy, `chargeback_conf_lookup` is created automatically as an empty lookup index once any billing or monitoring source index exists so dashboards apply default rates and weights automatically. To create or update `_id: config` manually via `POST chargeback_conf_lookup/_update/config` with `"doc_as_upsert": true`, place `config_join_key: "chargeback_config"`, `conf_start_date`, and `conf_end_date` directly inside `"doc"` (or run `PUT chargeback_conf_lookup` first on an empty cluster before source indices arrive):

```json
POST chargeback_conf_lookup/_update/config
{
  "doc": {
    "config_join_key": "chargeback_config",
    "conf_chargeable_unit_rate": 0.85,
    "conf_chargeable_unit_rate_unit": "EUR",
    "conf_indexing_weight": 20,
    "conf_query_weight": 20,
    "conf_storage_weight": 40,
    "conf_utilization_memory_weight": 70,
    "conf_utilization_storage_weight": 30,
    "conf_utilization_floor": 0.10,
    "conf_start_date": 1262304000000,
    "conf_end_date": 2430518399999
  },
  "doc_as_upsert": true
}
```

### Per-Data-Stream UI Settings

**Elastic Cloud Daily Billing & Rate Settings (`chargeback.billing`):**
- **Billing Lookbehind Days (`lookbehind`)**: Historical days backfilled on initial install (default: `60`).
- **Currency Unit (`currency_unit`)**: Target display currency code, for example `"EUR"`, `"USD"`, `"GBP"`, `"ZAR"` (default: `"EUR"`).
- **Chargeable Unit Rate (`unit_rate`)**: Monetary value per chargeable unit (ECU/ERU), for example `0.85`.
- **Configuration Effective Start Date (Optional) (`config_effective_from`)**: Optional ISO-8601 UTC start timestamp (for example `2026-01-01T00:00:00Z`) applied to `_id: config` when preserving earlier non-overlapping historical rate windows in `chargeback_conf_lookup`.
- **Collect ESS Credit Commitment Data (for stock ESS Billing Credits dashboard) (`collect_ess_credits`)**: Pulls daily organization credit commitment snapshots into `metrics-chargeback.billing-*` for the opt-in stock **[Metrics ESS Billing] Credits dashboard** alias (default: `false`).

**Index & Tier Usage (`chargeback.usage`):**
- **Blended Indexing Weight (`indexing_weight`)**: Non-negative weight for indexing operations in blended cost calculation (default: `20`, applies to hot/content tier only).
- **Blended Query Weight (`query_weight`)**: Non-negative weight for query operations in blended cost calculation (default: `20`). The sum of `query_weight` and `storage_weight` must be greater than zero.
- **Blended Storage Weight (`storage_weight`)**: Non-negative weight for storage in blended cost calculation (default: `40`). The sum of `query_weight` and `storage_weight` must be greater than zero.

**Elastic Cloud Data Node Utilization (15m) (`chargeback.node_stats`):**
- **Utilization Memory (Heap p95) Weight (`utilization_memory_weight`)**: Non-negative weight for JVM heap p95 in capacity utilization score (default: `70`). The sum of `utilization_memory_weight` and `utilization_storage_weight` must be greater than zero.
- **Utilization Storage (Disk p95) Weight (`utilization_storage_weight`)**: Non-negative weight for disk p95 in capacity utilization score (default: `30`). The sum of `utilization_memory_weight` and `utilization_storage_weight` must be greater than zero.
- **Utilization Floor (`utilization_floor`)**: Minimum utilization score (`0.0` to `1.0`) applied across realized-cost dashboard calculations (default: `0.10`). Prevents realized cost from reaching zero for idle clusters.

## Realized Cost

Realized cost answers: *of the capacity I purchased, how much am I actually using, and what does that cost?*

### Formula

```
util_score      = GREATEST((mem_w x heap_p95 + disk_w x disk_p95) / (mem_w + disk_w), floor)
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

The integration creates nine transforms to aggregate cost and usage data:

**Billing transforms:**
1. **`billing_cluster_cost`**: aggregates daily chargeable units (ECU/ERU) per deployment and SKU into `chargeback_lookup.dest_billing_cluster_cost-1` (aliased as `chargeback_lookup.billing_cluster_cost`), adding `cost_type`, `cost_category`, `is_allocatable`, and ESS Billing compatibility fields.
2. **`billing_realized_pool`**: aggregates daily allocatable data-tier capacity per deployment across ECH data tiers, Serverless workload and retained storage SKUs, and On-Premises nodes into `chargeback_lookup.dest_billing_realized_pool-1` (aliased as `chargeback_lookup.billing_realized_pool`).
3. **`billing_credits`**: aggregates daily organization credit commitment snapshots into `chargeback_lookup.dest_billing_credits-1` (aliased as `chargeback_lookup.billing_credits`) for the opt-in stock **[Metrics ESS Billing] Credits dashboard** compatibility alias.
4. **`chargeback_conf_lookup`**: syncs `config_snapshot` events into `chargeback_conf_lookup` (`_id: config`) while preserving manual configuration rows when Fleet sync is inactive.

**Utilization transforms:**
5. **`cluster_capacity_utilization`**: computes p95 heap and disk utilization across data-role nodes per deployment/day from `node_stats`.

**Usage transforms** (from `metrics-chargeback.usage-*` and `monitoring-indices*`):
6. **`cluster_deployment_contribution`**: indexing, querying, and storage metrics per deployment/day into `chargeback_lookup.dest_cluster_deployment_contribution-1` (aliased as `chargeback_lookup.cluster_deployment_contribution`).
7. **`cluster_datastream_contribution`**: same metrics split by data stream into `chargeback_lookup.dest_cluster_datastream_contribution-1` (aliased as `chargeback_lookup.cluster_datastream_contribution`). The usage ingest pipeline also sets `ds_type` (first `-` segment) and `ds_namespace` (last `-` segment) from the data stream name, or `other` when the name is non-conforming.
8. **`cluster_tier_contribution`**: same metrics split by data tier into `chargeback_lookup.dest_cluster_tier_contribution-1` (aliased as `chargeback_lookup.cluster_tier_contribution`).
9. **`cluster_tier_and_ds_contribution`**: same metrics split by both tier and data stream into `chargeback_lookup.dest_cluster_tier_and_datastream_contribution-1` (aliased as `chargeback_lookup.cluster_tier_and_datastream_contribution`), including `ds_type` and `ds_namespace`.

All transform destination documents include ECS `event.ingested` (when the lookup row was written).

These transforms produce lookup indices queried by the dashboards using ES|QL LOOKUP JOINs.

### Transform auto-start

All Chargeback transforms start automatically when the integration is installed.

The `cluster_capacity_utilization` transform reads from broad monitoring source indices covering all deployment types. To avoid a heavy historical backfill that could impact cluster performance on first run, it is configured to process only the last 26 hours of data — building utilization from the current day forward rather than historically. Utilization data from before installation is not backfilled. The 100% default applies until the transform has run for its first full day.

You can verify the transforms are running by navigating to **Stack Management → Transforms** and filtering for `chargeback`.

### Transform health monitoring

The integration includes a **Transform Health Monitoring** alert rule template that can be installed from the integration page. This rule monitors all Chargeback transforms and alerts when they encounter issues or failures.

## Dashboards

Chargeback ships three focused dashboards with a navigation bar linking between them.

### [Chargeback] Billing Components Overview

Answers: *what did we spend and where did it go?*

**Source:** `chargeback_lookup.billing_cluster_cost` (full invoice, all SKUs). Totals in this dashboard equal the full Elastic invoice.

Sections:
- **Deployment group statistics**: total billing spend and trend per chargeback group. Use this for internal chargeback allocation by team or cost center.
- **Component statistics**: cost broken down by billing component (`cost_type`: datahot/datacontent, datawarm, ml, kibana, snapshots, data-transfer, and others) and FinOps category (`cost_category`: data_tier, platform, transfer, snapshot, support, onprem, other).

![Billing Components Overview](../img/chargeback-billing-overview.png)

### [Chargeback] Usage and Cost Allocation

Answers: *which data streams and tiers drive cost, and how efficiently are we using capacity?*

**Source:** `chargeback_lookup.cluster_tier_contribution`, `chargeback_lookup.cluster_tier_and_datastream_contribution`, and related usage lookups. Totals reflect the chargeable pool (allocatable data-tier capacity weighted by utilization and clamped to `conf_utilization_floor`) and do not equal the full invoice. ML, Kibana, snapshots, support, and data transfer are excluded.

Sections:
- **Deployment cost allocation (usage-based)**: normalized cost per deployment split by data tier (usage-weighted). Shows which deployments consume the most of their chargeable pool across tiers.
- **Datatiers / utilization**: provisioned capacity vs chargeable pool, utilization p95 per deployment.
- **Data tier and data stream overview**: top-20 data streams by indexing / query / storage cost, blended cost totals, and the **Workload Breakdown by Data Tier** table with columns **Data stream type**, **Namespace**, **Data stream**, **Data tier**, then indexing / querying / storage / blended cost.
- **Data tier and data stream per day**: time-series panels (indexing, querying, storage, blended) broken out by data stream and data tier (usage-based), including absolute cost and percentage share.

#### Namespace-based ownership on shared deployments

When several teams share one deployment, assign each team a unique Fleet **namespace** so their data lands in distinct data streams (`<type>-<dataset>-<namespace>`). Chargeback parses `ds_namespace` and `ds_type` from the full data stream name and shows them on the Workload Breakdown table. Interactive control-bar filters on those fields are not part of this release line. Use the table columns (or a KQL/ES|QL query) until a later package that ships ES|QL variable controls.

![Usage and Cost Allocation](../img/chargeback-usage-allocation.png)

### [Chargeback] Configuration

Fleet Data Stream health and deployment harvest registry showing freshness-based status (`Active` when telemetry arrived within the last 72 hours versus `Stale` or `Missing`) alongside separate historical coverage counts across `chargeback.billing`, `chargeback.usage`, and `chargeback.node_stats`, per-deployment ECH, Serverless, and On-Premises telemetry status, and a quick-reference Fleet UI setup guide.

![Configuration](../img/chargeback-configuration.png)

### Cost reconciliation

Two distinct totals appear across the dashboards. Both are valid and intentionally different:

| Total | Source | Dashboard |
|---|---|---|
| **Full deployment bill** | `SUM(total_chargeable_units)` over all SKUs in `chargeback_lookup.billing_cluster_cost` | Billing Components Overview |
| **Chargeable pool** | `chargeback_lookup.billing_realized_pool` capacity x utilization score | Usage and Cost Allocation |

Do not expect the chargeable pool to equal the full deployment bill. Non-allocatable SKUs (ML, Kibana, transfer, snapshots) appear in the Billing Components Overview only. The utilization discount is not spread to tiers or data streams by design.

When `node_stats` is missing for a deployment/day, utilization defaults to 100%.

#### Small differences versus the ESS Billing dashboard

Chargeback billing and usage transforms aggregate on a **calendar day** (`calendar_interval: 1d`) with a sync delay (typically about one hour) and a periodic frequency. The ESS Billing dashboard can show near-real-time or partial-day totals for the current UTC day. Small differences for "today" or windows that cross midnight are expected. When you compare Chargeback to ESS Billing, use **completed UTC days** (or extend the billing time range across the day boundary) rather than an incomplete current day.

## Deployment Groups

The integration supports organizing deployments into logical groups using the `chargeback_group` tag on ESS Billing deployments. This enables cost allocation and filtering by team, project, or any organizational structure.

To assign a deployment to a chargeback group, add a tag in the Elastic Cloud console in the format:

```
chargeback_group:<group-name>
```

For example: `chargeback_group:team-search` or `chargeback_group:project-analytics`.

The `billing_cluster_cost` transform automatically extracts these tags from the `deployment_tags` field in ESS Billing data. Each deployment should have only one `chargeback_group` tag. Multiple tags can produce unpredictable cost allocation.

## Observability Alerting

Three alert rule templates are included and can be installed from the integration page. Alert rule templates require Elastic Stack version 9.2.0 or later.

**[Chargeback] Deployment with chargeback group missing usage data:** alerts when a deployment that has a chargeback group assigned is not sending usage data to the monitoring cluster. This prevents silent gaps in cost allocation.

**[Chargeback] New chargeback group detected:** notifies when a new `chargeback_group` tag appears on a deployment. Use this to ensure new teams or projects are accounted for in your chargeback model.

**[Chargeback] Transform health monitoring:** monitors all Chargeback transforms and alerts when they encounter failures or fall behind on processing. Requires all transforms to be running before activation.

For more information, refer to the [Elastic documentation](https://www.elastic.co/docs/reference/fleet/alerting-rule-templates).

## Upgrade Notes

### Upgrading to 0.6.0

1. Upgrade the Fleet package to **0.6.0**. Kibana requirement remains `^9.2.0`.
2. `billing_cluster_cost`, `billing_realized_pool`, `billing_credits`, `cluster_deployment_contribution`, `cluster_tier_contribution`, `cluster_datastream_contribution`, and `cluster_tier_and_ds_contribution` now write to versioned lookup indices (`chargeback_lookup.dest_*-1` aliased as `chargeback_lookup.billing_cluster_cost`, `chargeback_lookup.billing_realized_pool`, `chargeback_lookup.billing_credits`, `chargeback_lookup.cluster_deployment_contribution`, `chargeback_lookup.cluster_tier_contribution`, `chargeback_lookup.cluster_datastream_contribution`, and `chargeback_lookup.cluster_tier_and_datastream_contribution`) so in-place upgrades do not collide with concrete `0.5.0` lookup mappings or retain stale `group_by` document IDs. All seven transforms backfill retained history from `metrics-ess_billing.billing-*`, `metrics-ess_billing.credits-*`, `monitoring-indices*`, and `metrics-chargeback.*` automatically. If raw billing or monitoring streams use shorter ILM retention than your `0.5.0` `*_lookup` indices, reindex older daily rows (before the earliest retained source timestamp) from the `0.5.0` lookup indices into `chargeback_lookup.dest_*-1` (setting `usage_source` to `"legacy"` on migrated usage rows).
3. Existing manual rates and historical effective-date windows in `chargeback_conf_lookup` remain untouched on package upgrade until a **Chargeback** Fleet policy with `sync_fleet_config: true` emits `config_snapshot` events. Before enabling `sync_fleet_config: true` on an installation with customized rates or historical rate periods, copy your active rate and weights into the Fleet policy UI and set **Configuration Effective Start Date** (`config_effective_from`) to the start timestamp of your current open-ended period so earlier closed historical rows do not overlap, or set `sync_fleet_config: false` to continue managing `chargeback_conf_lookup` manually.
4. Existing **ESS Billing**, **On-Premises Billing**, and **Elasticsearch** monitoring inputs continue to work alongside native `chargeback.*` CEL streams. When both native and legacy sources exist for the same deployment and UTC day, usage and capacity utilization transforms merge non-overlapping observations per index, node, and interval so totals and p95 utilization are neither double-counted nor truncated during mid-day cutover.
5. Lookup destination ingest pipelines now call dedicated `@custom` hooks (`logs-chargeback.lookup@custom` for all lookup rows, plus `logs-chargeback.lookup-billing@custom`, `logs-chargeback.lookup-usage@custom`, `logs-chargeback.lookup-realized_pool@custom`, `logs-chargeback.lookup-credits@custom`, and `logs-chargeback.lookup-capacity_utilization@custom`) because Fleet attaches `global@custom`, `metrics@custom`, `metrics-chargeback.integration@custom`, `metrics-chargeback.billing@custom`, `metrics-chargeback.usage@custom`, and `metrics-chargeback.node_stats@custom` to the raw self-collected `metrics-chargeback.*` CEL data streams. If you defined custom lookup processors on `metrics-chargeback.integration@custom`, `metrics-chargeback.billing@custom`, or `metrics-chargeback.usage@custom` in `0.5.0` or earlier, migrate them to `logs-chargeback.lookup@custom`, `logs-chargeback.lookup-billing@custom`, or `logs-chargeback.lookup-usage@custom` and remove lookup-only logic from `metrics-chargeback.*@custom` before enabling native CEL streams.

### Upgrading to 0.4.5

1. Upgrade the Fleet package to **0.4.5**. Kibana requirement remains `^9.2.0`.
2. This release bumps the affected transform asset versions so package upgrade deletes, reinstalls, and restarts the lookup transforms whose `composite_key` mapping changed from `text` to `keyword`.
3. No manual lookup-index deletion or transform reset is required for that mapping fix on upgrade to 0.4.5.

### Upgrading to 0.4.4

1. Upgrade the Fleet package to **0.4.4**. Kibana requirement remains `^9.2.0`.
2. The bootstrap transform now writes the default configuration document with `_id` `config`, so `POST chargeback_conf_lookup/_update/config` works as documented.
3. **If you upgraded from 0.2.10-0.4.3** and already have a hashed-ID bootstrap row: after the package upgrade creates the new `_id` `config` document, copy any customized field values onto it with `POST chargeback_conf_lookup/_update/config`, then delete the hashed-ID document so LOOKUP JOIN does not match two overlapping date windows. Do not index a partial document to ID `config` with the index API (`_doc`); that replaces the whole document and can drop required bootstrap fields such as `config_join_key`. Fresh 0.4.4 installs need no cleanup.

### Upgrading to 0.4.3

1. Upgrade the Fleet package to **0.4.3**. Kibana requirement remains `^9.2.0`.
2. Re-import or replace Chargeback dashboard saved objects if Kibana did not refresh them on upgrade.
3. Delete Chargeback `*_lookup` destination indices, then reset and start the Chargeback transforms so `composite_key` is remapped with a keyword multifield. In-place upgrades that leave dynamically mapped `text` `composite_key` fields cause LOOKUP JOIN errors (`JOIN with right field [composite_key] of type [TEXT] is not supported`).
4. If `chargeback_conf_lookup` documents still contain `@timestamp`, delete that index and reset the conf transform as well. LOOKUP JOIN would otherwise overwrite billing `@timestamp` and create null time buckets on Billing Components Overview.

### Upgrading to 0.4.2

1. Upgrade the Fleet package to **0.4.2**. Kibana requirement remains `^9.2.0`.
2. This release updates managed dashboard ES|QL only. Re-import or replace Chargeback dashboard saved objects if Kibana did not refresh them on upgrade.
3. No transform reset is required for these dashboard fixes.

### Upgrading to 0.4.1

1. Upgrade the Fleet package to **0.4.1**. Kibana requirement remains `^9.2.0`.
2. Usage transforms rewrite lookup documents through the updated `usage` pipeline so new rows include `ds_type`, `ds_namespace`, and `event.ingested`. Reset usage transforms (or wait for incremental runs) if you need historical rows enriched.
3. Confirm ESS Billing (or On-Premises Billing) has produced backing indices before relying on `chargeback_conf_lookup` after a fresh install.

### Upgrading to 0.4.0

1. Upgrade the Fleet package to **0.4.0**.
2. The two new transforms (`billing_realized_pool`, `cluster_capacity_utilization`) are created and auto-started.
3. Reset the `billing_cluster_cost` transform to backfill `cost_type`, `cost_category`, and `is_allocatable` into existing lookup documents. Until backfill completes, the Component statistics panels will show no data.
4. Ensure the Elasticsearch integration collects **`node_stats`** from data nodes. Without this, utilization defaults to 100%.
5. The old `[Chargeback] Cost and Consumption breakdown` dashboard is replaced by three new dashboards. Delete the old dashboard from **Stack Management -> Saved Objects** if it is not removed automatically.

### Upgrading from 0.3.1 to 0.3.2

Lookup mappings were updated to include legacy ECU field aliases (`total_ecu`, `conf_ecu_rate`, `conf_ecu_rate_unit`) pointing to chargeable-unit fields. Existing 0.3.1 lookup indices retain old mappings. After upgrading:

1. Delete each affected lookup index (`billing_cluster_cost_lookup`, `chargeback_conf_lookup`) and reset the corresponding transform so the index is recreated with 0.3.2 mappings.
2. Start or schedule the `billing_cluster_cost` and `chargeback_conf_lookup` transforms.

If the dashboard was not replaced on upgrade, re-import the Chargeback dashboard saved objects.

### Upgrading from 0.2.x to 0.3.0

Field names changed from ECU to chargeable units: `total_ecu` to `total_chargeable_units`, `conf_ecu_rate` to `conf_chargeable_unit_rate`, `conf_ecu_rate_unit` to `conf_chargeable_unit_rate_unit`. Dashboard ES|QL uses the chargeable-unit field names (`total_chargeable_units`, `conf_chargeable_unit_rate`). ES|QL does not resolve mapping aliases, so panels must not reference the legacy names even inside `COALESCE`.
