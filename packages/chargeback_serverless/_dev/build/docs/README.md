# Chargeback Serverless

Allocate Elastic Cloud Serverless billing to **projects**, **data streams**, **AI models**, and **Synthetics monitors** on a Serverless hub project.

This package is designed for **Serverless-only** organizations. For Hosted monitoring clusters (or combined Hosted and Serverless environments), use the `chargeback` integration with ESS Billing.

## Overview

- **Billing classification pipeline** (`chargeback-serverless-billing`): classifies Serverless SKUs into `allocation_driver` (`indexing`, `query`, `storage`, `ai`, `synthetics`, or `none`) and `cost_category` (`data_tier`, `platform`, `transfer`, `snapshot`, `support`, or `other`).
- **Dashboards**: five linked dashboards for organization billing reconciliation, workload & data stream cost attribution, AI & Machine Learning FinOps, Synthetics FinOps, and policy/registry configuration.
- **Local currency normalization**: spend visuals convert chargeable units (ECU) to your configured currency using policy rates stamped into billing data (`conf_chargeable_unit_rate` × `conf_chargeable_unit_rate_unit`).
- **Alert rule templates**: ten prebuilt ES|QL rule templates for FinOps spend budgets, workload/project/namespace/model/monitor spend thresholds, 7-day project spend spikes, and consolidated Data Trust & Harvest Health.
- **Automated Serverless data retention (`365d`)**: built-in Data Stream Lifecycle (`data_retention: "365d"`) on `metrics-chargeback_serverless.billing-*` and `metrics-chargeback_serverless.usage-*`, paired with transform `retention_policy` (`time.field: "@timestamp"`, `max_age: 365d`) across all 7 `serverless_*_lookup` destination indices.

## Dashboards

Open **Analytics → Dashboards** and filter by the **Chargeback** tag. Use the top navigation bar on any dashboard to move between views, and use the filter controls (`Project type`, `Project name`, `Cost category`, `Cost type`, `Allocation driver`) to slice spend.

### Billing Components Overview

The **[Chargeback Serverless] Billing Components Overview** dashboard provides organization-level spend reconciliation and cost transparency:
- **Billing Summary KPIs:** Total Serverless spend, allocatable workload pool, unallocatable pass-through charges, billed project counts, days of billing data, and latest UTC billing snapshot date.
- **Daily Spend Trends:** Daily cost broken down by project and cost category (`data_tier`, `platform`, `support`, `transfer`).
- **Spend Flow & Breakdown:** Detailed multi-tier attribution flow (`cost_category → cost_type → project_type`) tracking cost origin to workload consumer.
- **Unallocatable & Pass-Through Charges:** Transparent tracking of non-workload items (support uplift, data transfer/egress, snapshots, cross-project search, and workflow executions).
- **Invoice Reconciliation Table:** Line-by-line reconciliation comparing raw billed quantities, chargeable units (ECU), and normalized local currency amounts.

![Billing Components Overview](../img/chargeback-serverless-billing-overview.png)

### Usage & Cost Allocation

The **[Chargeback Serverless] Usage & Cost Allocation** dashboard attributes allocatable data tier costs to active projects and data streams:
- **Workload Pool Summary KPIs:** Dedicated KPI tiles for Indexing pool, Search & Query pool, Storage pool, AI & ML pool, and Synthetics pool.
- **Daily Allocatable Cost by Workload Driver:** Stacked time series tracking daily spend across indexing, search, storage, AI, and synthetics drivers.
- **Per-Project Allocation Breakdown:** Detailed breakdown attributing driver spend to each individual Serverless project.
- **Data Stream Cost Attribution:** Attribution of storage and ingest spend down to namespace (`ds_namespace`) and data stream type (`ds_type` such as `logs`, `metrics`, `traces`, `.kibana`, `.alerts`).
- **Harvested Data Stream Metrics:** Inventory of data streams harvested via `_cat/indices` showing document counts, primary storage size, and index lifecycle status.

![Usage and Cost Allocation](../img/chargeback-serverless-usage-allocation.png)

### AI & Machine Learning FinOps

The **[Chargeback Serverless] AI & Machine Learning** dashboard provides dedicated FinOps visibility into AI model usage and compute allocation:
- **AI & ML FinOps KPIs:** Total AI & ML spend (`ml-vcu` compute + inference tokens), total inference volume, active deployed models (e.g. ELSER, language identification), average model execution latency, and blended unit cost per 1,000 inferences.
- **Daily Attributed AI Cost by Model:** Daily spend trends attributed to individual trained models and inference tasks.
- **Attributed AI Cost by Project:** AI compute spend allocation across projects utilizing machine learning services.
- **AI Model Compute & Spend Breakdown:** Tabular breakdown of model name, task type (`QUERY_INFERENCE`), project, compute allocation share, inference count, latency, and attributed cost.
- **Dedicated AI Billing Line Items:** Direct tracking of Serverless inference, managed LLM, and Agent Builder SKU charges.

![AI & Machine Learning FinOps](../img/chargeback-serverless-ai-ml.png)

### Synthetics FinOps

The **[Chargeback Serverless] Synthetics** dashboard delivers complete cost attribution for synthetic monitoring workloads:
- **Synthetics Billing Summary KPIs:** Direct Synthetics SKU spend, lightweight ping vs Playwright browser execution cost split, total billed check executions, blended unit economics per 1,000 checks, and billed project counts.
- **Synthetics Data Stream Attribution KPIs:** Ingest, search, and retained storage costs incurred by `synthetics-*` telemetry data streams.
- **Daily Attributed Synthetics Cost by Type:** Daily spend tracking by synthetic monitor type (`browser`, `http`, `icmp`, `tcp`, `dns`).
- **Attributed Cost by Monitor:** Spend attribution to individual synthetic monitors and multi-step browser journeys.
- **Per-Monitor Usage & Cost Attribution Table:** Monitor-level inventory with interactive filter tabs for synthetic types, check counts, execution run frequency, and attributed cost.

![Synthetics FinOps](../img/chargeback-serverless-synthetics.png)

### Configuration & Workload Registry

The **[Chargeback Serverless] Configuration** dashboard verifies end-to-end telemetry pipeline health and Fleet integration settings:
- **Telemetry Pipeline Health KPIs:** Real-time health status of Cloud Billing stream, Discovered Projects count, Data Plane API keys status, data stream telemetry count, and active currency rates.
- **API Keys, Data Streams & Lookup Status Table:** Status grid for all five collection streams and seven lookup transforms with latest UTC harvest timestamps and retention status.
- **Per-Project API Key & Status Registry:** Discovered Serverless projects table detailing project type, endpoint URL, credential authentication method, billing stream status, and harvest health across data streams, AI models, and Synthetics monitors.

![Configuration & Workload Registry](../img/chargeback-serverless-configuration.png)

## Data streams

The Chargeback Serverless integration collects the following data streams:

- `metrics-chargeback_serverless.billing`: Daily closed-day billing and SKU usage events from the Elastic Cloud Billing API. Classifies line items into cost categories and workload allocation drivers, and normalizes ECU to local currency via configured rates.
- `metrics-chargeback_serverless.usage`: Daily Serverless project metadata, index usage (`_cat/indices`), trained AI model metrics (`_ml/trained_models/_stats`), and synthetics monitor runs harvested directly from Serverless project endpoints.

{{fields "billing"}}

{{fields "usage"}}

## Configuration

### Fleet Integration Policy Settings

Organization ID, Cloud API Key, Currency Rates, and Remote Project API Keys are configured directly in **Integrations → Chargeback Serverless → Settings**. All credentials are encrypted and stored inside Fleet policies; zero credentials or plaintext secret indices exist in Elasticsearch.

| Setting | Secret | Purpose |
| --- | --- | --- |
| **Organization ID** | No | Elastic Cloud organization ID |
| **Cloud API Key** | Yes | Elastic Cloud API key with billing read access and Serverless project read access |
| **Hub Project Elasticsearch API Key** | Yes | Optional Elasticsearch API key for the local Hub project when harvesting local data streams |
| **Remote Project Elasticsearch API Keys** | Yes | Optional project-specific keys (`<project_id>:<encoded_key>`) with index `monitor` privilege |
| **Billing Lookbehind Days** | No | Historical days of billing data to backfill on initial install (default `60`) |
| **Currency Unit** | No | Currency label (e.g. `USD`, `EUR`, `ZAR`) |
| **Currency Symbol** | No | Currency symbol (e.g. `$`, `€`, `R`) |
| **Chargeable Unit Rate** | No | Multiplier from chargeable units (ECU) to configured currency |

#### Registering Remote Project API Keys

Billing data (spend per project, SKU breakdown) works with **zero** remote project keys.

To break down usage per data stream across projects outside this hub:

1. **Generate a least-privileged key on each remote project** in its Kibana Dev Tools:
   ```json
   POST _security/api_key
   {
     "name": "chargeback-usage-harvesting",
     "role_descriptors": {
       "chargeback_usage": {
         "cluster": ["monitor"],
         "indices": [
           {
             "names": ["*"],
             "privileges": ["monitor"]
           }
         ]
       }
     }
   }
   ```
   *(This key only grants permission to read `_cat/indices` metadata — it cannot read, search, or modify any data).*

2. **Register the key(s) in the Fleet Integration Policy**:
   - In **Fleet → Agent Policies → your policy → Chargeback Serverless**, enter `<project_id>:<encoded_api_key>` into **Remote Project Elasticsearch API Keys**.
   - **Adding multiple projects:** Click **Add item** (or **+**) to add an input row for each remote project in `<project_id>:<encoded_key>` format.
   - **Updating existing keys:** Because this field is stored as an encrypted Fleet Policy Secret, Kibana masks saved keys. Click **↺ Replace remote project elasticsearch api keys** and re-enter **all** keys you want to retain (both existing and new) before saving.

### Alerts

Create rules from the packaged ES|QL rule templates under **Stack Management → Rules**:

- **[Chargeback Serverless] Spend budget exceeded (rolling 30d):** Alerts when rolling 30-day spend exceeds configured currency budget.
- **[Chargeback Serverless] Daily spend threshold exceeded:** Triggers when total daily spend exceeds a fixed limit.
- **[Chargeback Serverless] Project daily spend threshold exceeded:** Monitors per-project daily spend thresholds.
- **[Chargeback Serverless] Workload pool spend threshold exceeded:** Detects abnormal spend in indexing, search, storage, AI, or synthetics drivers.
- **[Chargeback Serverless] Cost category spend threshold exceeded:** Alerts when data tier, platform, support, or transfer categories spike.
- **[Chargeback Serverless] Namespace daily spend threshold exceeded:** Flags high-cost application namespaces (`ds_namespace`).
- **[Chargeback Serverless] AI model daily spend threshold exceeded:** Identifies expensive inference models or unexpected compute spikes.
- **[Chargeback Serverless] Synthetics monitor daily spend threshold exceeded:** Triggers on runaway browser checks or ping monitor frequency.
- **[Chargeback Serverless] 7-day project spend spike:** Statistical spike detection comparing today's spend against a 7-day trailing baseline.
- **[Chargeback Serverless] Data Trust & Harvest Health:** Consolidated health check alerting on unallocated ECU, missing project registry entries, or stale usage harvests.

Thresholds are customized directly in Line 2 of each rule template's ES|QL query (`EVAL threshold = ...`).

## Supported project types

| Type | Ingest driver | Search driver | Storage driver |
| --- | --- | --- | --- |
| Elasticsearch | indexing time (`ingest-vcu`) | query time (`search-vcu`) | `dataset.size` (`retained`) |
| Elasticsearch Vector Database (`optimized_for: vector`) | indexing time (`ingest-vcu`) | query time (`search-vcu`) | `dataset.size` (`retained`) |
| Observability | indexing time (`ingest`) | — | `dataset.size` (`retained`) |
| Security | indexing time (`ingest`) | — | `dataset.size` (`retained`) |

Unallocatable / pass-through charges (shown per project on **Billing Components Overview**): support uplift, data transfer/egress, snapshots, cross-project search (CPS), and Workflows executions.
