# Chargeback Serverless

Allocate Elastic Cloud Serverless billing to **projects** and **data streams** on a Serverless hub project.

This package is designed for **Serverless-only** organizations. For Hosted monitoring clusters (or combined Hosted and Serverless environments), use the `chargeback` integration with ESS Billing.

## Overview

- **Billing classification pipeline** (`chargeback-serverless-billing`): classifies Serverless SKUs into `allocation_driver` (`indexing`, `query`, `storage`, or `none`) and `cost_category` (`data_tier`, `platform`, `transfer`, `snapshot`, `support`, or `other`).
- **Dashboards**: five linked dashboards for organization billing reconciliation, workload & data stream cost attribution, AI & Machine Learning FinOps, Synthetics FinOps, and policy/registry configuration.
- **Local currency normalization**: spend visuals convert chargeable units (ECU) to your configured currency using policy rates stamped into billing data (`conf_chargeable_unit_rate` × `conf_chargeable_unit_rate_unit`).
- **Alert rule templates**: prebuilt ES|QL rule templates for FinOps spend budgets, workload/project/namespace/model/monitor spend thresholds, 7-day project spend spikes, and consolidated Data Trust & Harvest Health.
- **Automated Serverless data retention (`365d`)**: built-in Data Stream Lifecycle (`data_retention: "365d"`) on `metrics-chargeback_serverless.billing-*` and `metrics-chargeback_serverless.usage-*`, paired with transform `retention_policy` (`time.field: "@timestamp"`, `max_age: 365d`) across all 7 `serverless_*_lookup` destination indices.

![Billing Components Overview](../img/chargeback-serverless-billing-overview.png)

![Usage and Cost Allocation](../img/chargeback-serverless-usage-allocation.png)

![Configuration](../img/chargeback-serverless-configuration.png)

## Dashboards

| Dashboard | Purpose |
| --- | --- |
| **[Chargeback Serverless] Billing Components Overview** | Organization spend KPIs, daily cost by project and cost category, spend flow (`cost_category → cost_type → project_type`), unallocatable & pass-through charges, and invoice reconciliation detail |
| **[Chargeback Serverless] Usage & Cost Allocation** | Workload pool KPIs (Indexing, Search & Query, Storage), daily allocatable cost by workload driver, cost allocation by project, data stream cost attribution by namespace (`ds_namespace`) and data stream type (`ds_type`), and harvested `_cat/indices` usage metrics |
| **[Chargeback Serverless] AI & Machine Learning** | AI & ML FinOps KPIs (AI pool spend, inference volume, active models, avg latency, unit cost per 1k inferences), daily attributed AI cost by model, attributed AI cost by project, AI model compute & spend breakdown, and dedicated AI/Inference/Agent Builder billing line items |
| **[Chargeback Serverless] Synthetics** | Synthetics FinOps KPIs (direct Synthetics SKU spend, lightweight ping vs. browser execution spend, billed check quantity, unit cost per 1k checks), Synthetics data stream attribution KPIs (`synthetics-*` indexing, search, storage), daily attributed Synthetics cost by synthetic type (`http`, `browser`, `icmp`, `tcp`, `dns`), attributed cost by monitor, per-monitor usage & cost attribution table with synthetic type filter tabs, Synthetics data stream cost by synthetic type & namespace, SKU line items, and Synthetics data stream attribution table |
| **[Chargeback Serverless] Configuration** | Fleet policy settings guide, active currency settings, discovered Serverless projects registry, and daily usage harvest status |

Open **Analytics → Dashboards** and filter by the **Chargeback** tag. Use the top Links bar to navigate between the five dashboards, and use the filter controls (`Project type`, `Project name`, `Cost category`, `Cost type`, `Allocation driver`) to slice spend.

## Configuration

### Fleet Integration Policy Settings

Organization ID, Cloud API Key, Currency Rates, and Remote Project API Keys are configured directly in **Integrations → Chargeback Serverless → Settings**. All credentials are encrypted and stored inside Fleet policies; zero credentials or plaintext secret indices exist in Elasticsearch.

| Setting | Secret | Purpose |
| --- | --- | --- |
| **Organization ID** | No | Elastic Cloud organization ID |
| **Cloud API Key** | Yes | Elastic Cloud API key with billing read access |
| **Hub Project Elasticsearch API Key** | Yes | Optional Elasticsearch API key for the local Hub project when harvesting local data streams |
| **Remote Project Elasticsearch API Keys** | Yes | Optional project-specific keys (`<project_id>:<encoded_key>`) with index `monitor` privilege |
| **Billing Lookbehind Days** | No | Historical days of billing data to backfill on initial install (default `60`) |
| **Currency Unit** | No | Currency label (e.g. `USD`, `EUR`, `ZAR`) |
| **Currency Symbol** | No | Currency symbol (e.g. `$`, `€`, `R`) |
| **Chargeable Unit Rate** | No | Multiplier from chargeable units (ECU) to configured currency |

#### Registering Remote Project API Keys

To monitor index and data stream usage on remote Serverless projects, generate a least-privileged key on each remote project (`cluster: ["monitor"]`, `indices: ["*"] ["monitor"]`).

In **Integrations → Chargeback Serverless → Settings**:
- **Adding multiple projects:** Click **Add item** (or **+**) to add an input row for each remote project in `<project_id>:<encoded_key>` format.
- **Updating existing keys:** Because this field is stored as an encrypted Fleet Policy Secret, Kibana masks saved keys. Click **↺ Replace remote project elasticsearch api keys** and re-enter **all** keys you want to retain (both existing and new) before saving.


### Alerts

Create rules from the packaged templates under **Stack Management → Rules**:

- **[Chargeback Serverless] Unallocated cost present**
- **[Chargeback Serverless] Stale project usage harvest**
- **[Chargeback Serverless] Billed project missing from registry**

## Supported project types

| Type | Ingest driver | Search driver | Storage driver |
| --- | --- | --- | --- |
| Elasticsearch | indexing time (`ingest-vcu`) | query time (`search-vcu`) | `dataset.size` (`retained`) |
| Elasticsearch Vector Database (`optimized_for: vector`) | indexing time (`ingest-vcu`) | query time (`search-vcu`) | `dataset.size` (`retained`) |
| Observability | indexing time (`ingest`) | — | `dataset.size` (`retained`) |
| Security | indexing time (`ingest`) | — | `dataset.size` (`retained`) |

Unallocatable / pass-through charges (shown per project on **Billing Components Overview**): inference, managed LLM, ML VCU (`ml-vcu`), synthetics, egress/data transfer, snapshots, cross-project search (CPS), Workflows and Agent Builder executions, and Serverless support uplift.
