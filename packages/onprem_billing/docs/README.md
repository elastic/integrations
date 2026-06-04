# On-Premises Billing Integration

Generates billing metrics compatible with the ESS Billing format, enabling the Chargeback integration to work on non-cloud deployments (on-premises, ECE, ECK).

## Overview

This integration uses **milli-ERUs (mERU)** as the internal cost unit, where **1 ERU = 1000 mERU**. This provides clean integer values internally while allowing flexible ERU or RAM-based configuration for deployments of any size.

The output is written to `metrics-ess_billing.billing-onprem` in ESS Billing format, enabling Chargeback 0.2.x+ to work with on-prem data.

### Why mERU?

ERUs (Elastic Resource Units) are how Elastic licenses on-premises deployments. However:
- Deployments can range from tiny (0.25 ERU) to large (10+ ERU)
- Fractional ERU values are awkward to work with
- Currency conversion requires very large rate multipliers

Using mERU solves this:
- A 0.25 ERU deployment = 250 mERU (clean integer)
- A 5 ERU deployment = 5000 mERU (clean integer)
- Rate conversion uses smaller numbers (15 EUR/mERU instead of 15,000 EUR/ERU)

### Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                     Monitoring Cluster                           │
│  ┌─────────────────┐    ┌──────────────────┐    ┌────────────┐   │
│  │ monitoring-     │───▶│ config_bootstrap │    │ Chargeback │   │
│  │ indices         │    │  → config index  │───▶│            │   │
│  │                 │    │ billing transform│    │            │   │
│  └────────▲────────┘    └──────────────────┘    └────────────┘   │
│           │                      │                               │
│           │                      ▼                               │
│           │             metrics-ess_billing.billing-onprem       │
└───────────┼──────────────────────────────────────────────────────┘
            │
    Stack Monitoring data
            │
┌───────────┴───────────┐
│   Managed Clusters    │
└───────────────────────┘
```

## Requirements

- Elastic Stack 9.2.0+
- Elasticsearch Integration (for Stack Monitoring data in indices matching `monitoring-indices*`, default `monitoring-indices`)

This integration enables the Chargeback integration (0.2.x+) to work on non-cloud deployments (on-premises, ECE, ECK).

> **Important:** Install on the **monitoring/management cluster** where Elasticsearch index-pivot output exists (names must match `monitoring-indices*`; default index name is `monitoring-indices`).

---

## Gathering Configuration Data

Before configuring the integration, gather the following information from your Elastic license and infrastructure.

### Organization-Level Data (from your Elastic License/Contract)

| Value | Where to Find It | Example |
|-------|------------------|---------|
| **Annual License Cost** | Your Elastic invoice or contract. This is the total annual cost for on-premises Elastic licenses. | 90,000 EUR |
| **Total ERUs Purchased** | Your Elastic license document or order confirmation. ERUs (Elastic Resource Units) define your licensed capacity. | 6 ERU |
| **ERU-to-RAM Ratio** | Your Elastic license terms. Typically **1 ERU = 64 GB RAM**, but verify with your contract as this may vary. | 64 GB |
| **Currency** | The currency used in your license contract. | EUR |

### Per-Deployment Data (from your Infrastructure)

You need to determine how to allocate your licensed ERUs across deployments. There are two approaches:

#### Approach 1: ERU-Based Allocation (Top-Down)

If your organization has already decided how to allocate ERUs:

| Deployment | Allocated ERUs | Calculation |
|------------|----------------|-------------|
| production | 3.0 ERU | Business decision: production gets 50% |
| staging | 1.5 ERU | Business decision: staging gets 25% |
| dev | 0.75 ERU | Business decision: dev gets 12.5% |
| monitoring | 0.75 ERU | Business decision: monitoring gets 12.5% |
| **Total** | **6.0 ERU** | Must not exceed licensed ERUs |

#### Approach 2: RAM-Based Calculation (Bottom-Up)

If you want to calculate ERUs from actual infrastructure:

| Deployment | Nodes | RAM/Node | Total RAM | ERU Calculation | ERUs |
|------------|-------|----------|-----------|-----------------|------|
| production | 3 | 64 GB | 192 GB | 192 ÷ 64 = 3.0 | 3.0 ERU |
| staging | 2 | 48 GB | 96 GB | 96 ÷ 64 = 1.5 | 1.5 ERU |
| dev | 1 | 48 GB | 48 GB | 48 ÷ 64 = 0.75 | 0.75 ERU |
| monitoring | 1 | 48 GB | 48 GB | 48 ÷ 64 = 0.75 | 0.75 ERU |
| **Total** | | | **384 GB** | | **6.0 ERU** |

**Formula:** `ERUs = (node_count × ram_per_node_gb) ÷ eru_to_ram_gb`

> **Important:** Verify that your total allocated ERUs does not exceed your licensed ERUs. If the sum exceeds your license, either reduce allocations or purchase additional ERU capacity from Elastic.

### Chargeback Rate Calculation

To convert mERU to currency in Chargeback, calculate your rate:

```
rate_per_meru = total_annual_license_cost ÷ (total_erus_purchased × 1000 × 365)
```

**Example:** For 90,000 EUR license with 6 ERU:
```
rate = 90,000 ÷ (6 × 1000 × 365)
     = 90,000 ÷ 2,190,000
     = 0.041 EUR per mERU
```

This rate ensures that if all ERUs are fully allocated for a full year, the total chargeback equals your license cost.

---

## Post-Installation Setup

After adding this integration, the bootstrap transform runs automatically and discovers existing deployments. Complete the following steps to enable billing.

### Step 1: Configure Organization Settings

Using the values gathered above, create the organization-level configuration:

```json
PUT onprem_billing_config/_doc/organization
{
  "config_type": "organization",
  "total_annual_license_cost": 90000,
  "total_erus_purchased": 6,
  "eru_to_ram_gb": 64,
  "currency_unit": "EUR"
}
```

**Organization Configuration Fields:**

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `config_type` | keyword | Must be `"organization"` | `"organization"` |
| `total_annual_license_cost` | float | Annual license cost in local currency | `90000` |
| `total_erus_purchased` | float | Total ERUs in your license | `6` |
| `eru_to_ram_gb` | integer | GB of RAM per ERU (from license terms) | `64` |
| `currency_unit` | keyword | Currency code | `"EUR"` |

### Step 2: Configure ALL Deployments

Wait a few minutes for the bootstrap transform to discover deployments, then view them:

```json
GET onprem_billing_config/_search
{
  "query": {
    "term": { "config_type": "deployment" }
  },
  "_source": ["deployment_id", "deployment_name", "deployment_erus", "daily_meru"]
}
```

For each deployment, choose **one** of two configuration methods:

#### Option A: Direct ERU Input (Recommended for Finance Teams)

If you know the ERU allocation per deployment:

```json
POST onprem_billing_config/_update/<document_id>
{
  "doc": {
    "deployment_name": "Production Cluster",
    "deployment_tags": ["chargeback_group:platform_team"],
    "deployment_erus": 3.0
  }
}
```

Set `daily_meru` to `deployment_erus × 1000` (the config bootstrap pipeline computes this on transform writes; include it on manual `_update` calls).

#### Option B: RAM-Based Input (Recommended for Ops Teams)

If you prefer to specify infrastructure details:

```json
POST onprem_billing_config/_update/<document_id>
{
  "doc": {
    "deployment_name": "Production Cluster",
    "deployment_tags": ["chargeback_group:platform_team"],
    "node_count": 3,
    "ram_per_node_gb": 64
  }
}
```

The integration will compute:
- `total_ram_gb = node_count × ram_per_node_gb` (192 GB)
- `deployment_erus = total_ram_gb / eru_to_ram_gb` (192 / 64 = 3 ERU)
- `daily_meru = deployment_erus × 1000` (3000 mERU)

**Deployment Configuration Fields:**

| Field | Type | Description | Required |
|-------|------|-------------|----------|
| `deployment_name` | keyword | Human-readable name | Yes |
| `deployment_tags` | keyword[] | Tags including `chargeback_group:team_name` | Yes |
| `deployment_erus` | float | ERUs allocated (Option A) | One of A or B |
| `node_count` | integer | Number of nodes (Option B) | One of A or B |
| `ram_per_node_gb` | integer | RAM per node in GB (Option B) | One of A or B |

### Example: Mixed Deployment Sizes

| Deployment | Input Method | Configuration | Computed mERU |
|------------|--------------|---------------|---------------|
| dev-cluster | ERU | `deployment_erus: 0.25` | 250 mERU/day |
| monitoring | RAM | `node_count: 1, ram_per_node_gb: 48` | 750 mERU/day |
| production | ERU | `deployment_erus: 5.0` | 5000 mERU/day |
| **Total** | | **6 ERU licensed** | **6000 mERU/day** |

### Step 3: Refresh `daily_meru` after deployment updates (0.3.0+)

From **0.3.0** onward, ingest pipelines ship with the integration and the billing transform reads `onprem_billing_config` directly (no enrich policies or manual `calculate_cost` pipeline).

When you change `deployment_erus` or RAM fields with `_update`, also set `daily_meru` (mERU per day = ERU × 1000), or re-index the document through the packaged config pipeline:

```json
POST onprem_billing_config/_update/<document_id>?pipeline=0.3.3-config_bootstrap
{
  "doc": {
    "deployment_erus": 3.0,
    "deployment_tags": ["chargeback_group:platform_team"]
  }
}
```

> **Upgrading from 0.3.2 to 0.3.3:** The billing transform now includes `deployment_tags` in its pivot group_by, which is required for Chargeback group assignment. After upgrading, reset and restart the `billing` transform so the lookup index is recreated with the updated pivot key. Your existing `onprem_billing_config` deployment tags are preserved; no re-configuration is needed.

> **Upgrading from 0.2.x:** Delete legacy enrich policies and the manual `calculate_cost` pipeline if you created them. Re-install the integration, then complete Steps 1–2 and start the billing transform below.

### Step 4: Start the Billing Transform

```json
POST _transform/logs-onprem_billing.billing-*/_start
```

Or via Kibana: **Stack Management → Transforms** → Find `billing` transform → **Start**

### Step 5: Verify Data

```json
GET metrics-ess_billing.billing-onprem/_search
{
  "size": 5,
  "sort": [{ "@timestamp": "desc" }]
}
```

You should see documents with `ess.billing.total_ecu` containing mERU values (e.g., 3000 for a 3 ERU deployment).

---

## Chargeback Configuration

When using this integration with Chargeback, configure the rate using the calculation from the "Gathering Configuration Data" section:

```json
POST chargeback_conf_lookup/_update/config
{
  "doc": {
    "conf_chargeable_unit_rate": 0.041,
    "conf_chargeable_unit_rate_unit": "EUR"
  }
}
```

**Rate Formula (from earlier):**
```
conf_chargeable_unit_rate = total_annual_license_cost ÷ (total_erus_purchased × 1000 × 365)
```

**Verification Example:**

For a 90,000 EUR license with 6 ERU:
- Rate: `90,000 ÷ (6 × 1000 × 365) = 0.041 EUR/mERU`

Production cluster (3 ERU = 3,000 mERU/day):
- Daily cost: `3,000 × 0.041 = 123 EUR/day`
- Annual cost: `123 × 365 = 44,895 EUR/year`
- Verification: 3 ERU is 50% of 6 ERU → 44,895 EUR ≈ 50% of 90,000 EUR ✓

---

## ERU Allocation Validation

To verify your configuration doesn't exceed licensed capacity:

```json
GET onprem_billing_config/_search
{
  "size": 0,
  "query": {
    "term": { "config_type": "deployment" }
  },
  "aggs": {
    "total_meru": {
      "sum": { "field": "daily_meru" }
    },
    "total_erus": {
      "sum": { "field": "deployment_erus" }
    }
  }
}
```

Compare `total_erus` against your licensed `total_erus_purchased`. If deployments exceed licensed ERUs, you'll need to reduce allocations or purchase additional capacity.

---

## Adding New Deployments

The bootstrap transform only runs once. For new deployments:

**1. Add the new deployment config:**

```json
PUT onprem_billing_config/_doc/<new-cluster-uuid>
{
  "config_type": "deployment",
  "deployment_id": "<new-cluster-uuid>",
  "deployment_name": "New Cluster",
  "deployment_tags": ["chargeback_group:team_name"],
  "deployment_erus": 1.5
}
```

Or using RAM-based config:

```json
PUT onprem_billing_config/_doc/<new-cluster-uuid>
{
  "config_type": "deployment",
  "deployment_id": "<new-cluster-uuid>",
  "deployment_name": "New Cluster",
  "deployment_tags": ["chargeback_group:team_name"],
  "node_count": 2,
  "ram_per_node_gb": 48
}
```

After adding the deployment, start (or restart) the billing transform so today's billing rows are emitted.

> **Warning:** Do not re-run the bootstrap transform — it would overwrite existing configurations with defaults.

---

## Troubleshooting

### No Billing Data Generated

**Check if billing transform is started** (it does NOT auto-start):

```json
GET _transform/logs-onprem_billing.billing-*/_stats
```

If `state` is `stopped`, start it:

```json
POST _transform/logs-onprem_billing.billing-*/_start
```

**Check Stack Monitoring data availability:**

```json
GET monitoring-indices*/_count
```

**0.3.0+:** Confirm deployment rows have `daily_meru` set in `onprem_billing_config`.

### Bootstrap Transform Issues

**Check if bootstrap ran:**

```json
GET onprem_billing_config/_count
```

If 0, the bootstrap transform hasn't run or found no deployments.

**Check bootstrap transform status:**

```json
GET _transform/logs-onprem_billing.config_bootstrap-*/_stats
```

### Incorrect mERU Values

**Verify deployment configuration:**

```json
GET onprem_billing_config/_search
{
  "query": { "term": { "config_type": "deployment" } },
  "_source": ["deployment_id", "deployment_name", "deployment_erus", "daily_meru", "node_count", "ram_per_node_gb"]
}
```

**Verify organization configuration:**

```json
GET onprem_billing_config/_doc/organization
```

**After config changes (0.3.0+):** Update `daily_meru` on deployment docs, then reset/start the billing transform.

### Common Errors

**"Enrich policy not found" (0.2.x only)** - Create and execute enrich policies, or upgrade to 0.3.0+.

**No billing rows (0.3.0+)** - Ensure deployment docs exist with `daily_meru` and the billing transform is started.

**mERU values seem wrong** - Check if `eru_to_ram_gb` in organization config matches your license terms.

### Getting Help

1. Check transform stats: `GET _transform/logs-onprem_billing*/_stats?human`
2. Check config: `GET onprem_billing_config/_search`
3. Open an issue at [elasticsearch-chargeback](https://github.com/elastic/elasticsearch-chargeback)
