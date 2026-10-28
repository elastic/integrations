# Chargeback Serverless

Allocate Elastic Cloud Serverless billing to **projects** and **data streams** on a Serverless hub project.

This package is designed for **Serverless-only** organizations. For Hosted monitoring clusters (or combined Hosted and Serverless environments), use the `chargeback` integration with ESS Billing.

## Overview

- **Billing classification pipeline** (`chargeback-serverless-billing`): classifies Serverless SKUs into `allocation_driver` (`indexing`, `query`, `storage`, or `none`) and `cost_category` (`data_tier`, `platform`, `transfer`, `snapshot`, `support`, or `other`).
- **Dashboards**: three linked dashboards for organization billing reconciliation, workload & data stream cost attribution, and rate/registry configuration.
- **Local currency normalization**: spend visuals convert chargeable units (ECU) to your configured currency via `LOOKUP JOIN chargeback_conf_lookup` (`conf_chargeable_unit_rate` × `conf_chargeable_unit_rate_unit`).
- **Alert rule templates**: prebuilt ES|QL rule templates for unallocated cost, stale usage harvest, and billed projects missing from the project registry.

![Billing Components Overview](../img/chargeback-serverless-billing-overview.png)

![Usage and Cost Allocation](../img/chargeback-serverless-usage-allocation.png)

![Configuration](../img/chargeback-serverless-configuration.png)

## Dashboards

| Dashboard | Purpose |
| --- | --- |
| **[Chargeback Serverless] Billing Components Overview** | Organization spend KPIs, daily cost by project and cost category, spend flow (`cost_category → cost_type → project_type`), unallocatable & pass-through charges, and invoice reconciliation detail |
| **[Chargeback Serverless] Usage & Cost Allocation** | Workload pool KPIs (Indexing, Search & Query, Storage), daily allocatable cost by workload driver, cost allocation by project, data stream cost attribution, and harvested `_cat/indices` usage metrics |
| **[Chargeback Serverless] Configuration** | Dev Tools DSL snippets for rate windows and workflow configuration, configured currency rates (`chargeback_conf_lookup`), discovered Serverless projects registry, and hourly usage harvest status |

Open **Analytics → Dashboards** and filter by the **Chargeback** tag. Use the top Links bar to navigate between the three dashboards, and use the filter controls (`Project type`, `Project name`, `Cost category`, `Cost type`, `Allocation driver`) to slice spend.

## Configuration

### Credentials

Organization ID, Billing API key, and Usage API key are configured in **Integrations → Chargeback Serverless → Settings** and stored in `chargeback-serverless-config` for the **Chargeback Serverless - Billing** (daily) and **Chargeback Serverless - Usage** (hourly) Kibana Workflows. API keys never appear on dashboards.

| Field | Secret | Purpose |
| --- | --- | --- |
| **Organization ID** | No | Elastic Cloud organization ID |
| **Billing API key** | Yes | Cloud API key with billing read access |
| **Usage API key** | Yes | Cloud API key that can list Serverless projects |

### Rates and local currency

Maintain `chargeback_conf_lookup` (using the Dev Tools DSL snippet shown on **[Chargeback Serverless] Configuration**):

- `conf_chargeable_unit_rate` — multiplier from chargeable units (ECU) to your local currency
- `conf_chargeable_unit_rate_unit` — currency label (for example `USD`, `EUR`)
- `conf_start_date` / `conf_end_date` — effective date window

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
