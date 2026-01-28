# On-Premises Billing Integration

Generates billing metrics compatible with the ESS Billing format, enabling the Chargeback integration to work on non-cloud deployments (on-premises, ECE, ECK).

## Overview

This integration assigns a **fixed daily ECU** per deployment. The output is written to `metrics-ess_billing.billing-onprem` in ESS Billing format, enabling Chargeback 0.2.x+ to work with on-prem data.

### Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                     Monitoring Cluster                           │
│  ┌─────────────────┐    ┌──────────────────┐    ┌────────────┐   │
│  │ monitoring-     │───▶│ onprem_billing   │───▶│ Chargeback │   │
│  │ indices         │    │ integration      │    │            │   │
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
- Elasticsearch Integration (for Stack Monitoring data in `monitoring-indices`)

This integration enables the Chargeback integration (0.2.x+) to work on non-cloud deployments (on-premises, ECE, ECK).

> **Important:** Install on the **monitoring/management cluster** where `monitoring-indices` exists.

---

## Post-Installation Setup

After adding this integration, the bootstrap transform runs automatically and discovers existing deployments. Complete the following steps to enable billing.

### Step 1: Configure ALL Deployments (Mandatory)

Wait a few minutes for the bootstrap transform to discover deployments, then view them:

```json
GET onprem_billing_config/_search
{
  "_source": ["deployment_id", "deployment_name", "daily_ecu", "deployment_tags"]
}
```

Example response:
```json
{
  "hits": {
    "hits": [
      {
        "_id": "MzMLEk5LIfjDaG_voS3-0ivSAAAAAAAA",
        "_source": {
          "deployment_id": "3cc5a925728f480abee1f5112dd184bf",
          "deployment_name": "3cc5a925728f480abee1f5112dd184bf",
          "daily_ecu": 100
        }
      }
    ]
  }
}
```

> **Note:** The bootstrap uses cluster identifiers for both `deployment_id` and `deployment_name`. Update each deployment with a human-readable name. Use the document `_id` (not `deployment_id`) when updating.

For each discovered deployment, update using the `_id` from the search results:

```json
POST onprem_billing_config/_update/MzMLEk5LIfjDaG_voS3-0ivSAAAAAAAA
{
  "doc": {
    "deployment_name": "Production Cluster",
    "deployment_tags": ["chargeback_group:platform_team"],
    "daily_ecu": 500
  }
}
```

**Fields to set:**
- `deployment_name` - Human-readable name for the deployment
- `deployment_tags` - Array with `chargeback_group:team_name` tag for Chargeback grouping
- `daily_ecu` - Fixed daily ECU value (default is 100)

### Step 2: Create Enrich Policy and Pipeline

After ALL deployments are configured:

**2a. Create and execute the enrich policy:**

```json
PUT /_enrich/policy/onprem_billing_config_enrich_policy
{
  "match": {
    "indices": "onprem_billing_config",
    "match_field": "deployment_id",
    "enrich_fields": ["daily_ecu", "deployment_name", "deployment_tags"]
  }
}

POST /_enrich/policy/onprem_billing_config_enrich_policy/_execute
```

**2b. Create the ingest pipeline:**

> **Note:** This pipeline must be created manually because it uses the `enrich` processor, which is not supported in packaged integration pipelines.

```json
PUT _ingest/pipeline/calculate_cost
{
  "description": "On-Prem Billing: Enriches and maps to ESS Billing schema",
  "processors": [
    {
      "enrich": {
        "policy_name": "onprem_billing_config_enrich_policy",
        "field": "cluster_uuid",
        "target_field": "cost_config",
        "max_matches": 1,
        "ignore_missing": true,
        "ignore_failure": true
      }
    },
    {
      "script": {
        "lang": "painless",
        "ignore_failure": true,
        "description": "Map to ESS Billing schema with daily ECU from enrichment",
        "source": """
          String deploymentId = ctx.cluster_uuid;
          String deploymentName = ctx.cluster_name;
          double dailyEcu = 100.0;
          List deploymentTags = new ArrayList();
          
          if (ctx.cost_config != null) {
            if (ctx.cost_config.deployment_name != null) {
              deploymentName = ctx.cost_config.deployment_name;
            }
            if (ctx.cost_config.daily_ecu != null) {
              dailyEcu = ctx.cost_config.daily_ecu;
            }
            if (ctx.cost_config.deployment_tags != null) {
              deploymentTags = ctx.cost_config.deployment_tags;
            }
          }
          
          if (ctx.ess == null) ctx.ess = new HashMap();
          if (ctx.ess.billing == null) ctx.ess.billing = new HashMap();
          
          ctx.ess.billing.deployment_id = deploymentId;
          ctx.ess.billing.deployment_name = deploymentName;
          ctx.ess.billing.deployment_type = 'onprem';
          ctx.ess.billing.deployment_tags = deploymentTags;
          ctx.ess.billing.kind = 'elasticsearch';
          ctx.ess.billing.type = 'capacity';
          ctx.ess.billing.unit = 'day';
          ctx.ess.billing.zone_count = 1;
          ctx.ess.billing.name = 'On-Premises: ' + deploymentName;
          ctx.ess.billing.sku = 'onprem-daily-' + deploymentId;
          
          if (ctx['@timestamp'] != null) {
            ctx.ess.billing.from = ctx['@timestamp'];
            String ts = ctx['@timestamp'].toString();
            if (ts.length() >= 10) {
              ctx.ess.billing.to = ts.substring(0, 10) + 'T23:59:59.999Z';
            }
          }
          
          ctx.ess.billing.total_ecu = dailyEcu;
          ctx.ess.billing.put('quantity.value', 1.0);
          ctx.ess.billing.put('quantity.formatted_value', '1 day');
          ctx.ess.billing.put('display_quantity.value', 1.0);
          ctx.ess.billing.put('display_quantity.formatted_value', '1 day');
          ctx.ess.billing.put('display_quantity.type', 'default');
          
          ctx.remove('cluster_uuid');
          ctx.remove('cluster_name');
          ctx.remove('cost_config');
          ctx.remove('doc_count');
        """
      }
    },
    {
      "pipeline": {
        "description": "[Fleet] Global pipeline for all data streams",
        "ignore_missing_pipeline": true,
        "name": "global@custom"
      }
    },
    {
      "pipeline": {
        "description": "[Fleet] Pipeline for all data streams of type metrics",
        "ignore_missing_pipeline": true,
        "name": "metrics@custom"
      }
    }
  ]
}
```

**2c. Update the billing transform to use the pipeline:**

```json
POST _transform/logs-onprem_billing.billing-default-0.1.0/_update
{
  "dest": {
    "index": "metrics-ess_billing.billing-onprem",
    "pipeline": "calculate_cost"
  }
}
```

### Step 3: Start the Billing Transform

```json
POST _transform/logs-onprem_billing.billing-default-0.1.0/_start
```

Or via Kibana: **Stack Management → Transforms** → Find `billing` transform → **Start**

### Step 4: Verify Data

```json
GET metrics-ess_billing.billing-onprem/_search
{
  "size": 5,
  "sort": [{ "@timestamp": "desc" }]
}
```

You should see documents with `ess.billing.deployment_tags` and `ess.billing.total_ecu`.

---

## Fixed Cost Allocation Model

Each deployment is assigned a fixed daily cost allocation value. The field is named `daily_ecu` for compatibility with the Chargeback integration, but for on-premises deployments this represents an **arbitrary cost unit** rather than actual Elasticsearch Compute Units (which are a cloud-specific concept).

**How It Works:**
1. **Daily Aggregation**: The billing transform groups data by deployment and day
2. **ECU Lookup**: For each deployment, the configured `daily_ecu` is retrieved from `onprem_billing_config`
3. **Output**: Billing records with `total_ecu` are written to `metrics-ess_billing.billing-onprem`
4. **Currency Conversion**: Chargeback multiplies `total_ecu × conf_ecu_rate` to get currency value

**Why Fixed Cost Units?**
- **Predictable**: Costs are known in advance
- **Simple**: No complex metering required
- **Realistic**: On-prem costs are often fixed (hardware, licenses, support)

> **Note on terminology**: The `daily_ecu` and `total_ecu` field names are used for compatibility with the ESS Billing format and Chargeback integration. For on-premises, these represent arbitrary cost allocation units, not actual cloud compute units.

### Configuration Fields

| Field | Type | Description |
|-------|------|-------------|
| `deployment_id` | keyword | Cluster UUID (matches `elasticsearch.cluster.name`) |
| `deployment_name` | keyword | Human-readable deployment name |
| `deployment_tags` | keyword[] | Tags for grouping (e.g., `chargeback_group:team_name`) |
| `daily_ecu` | float | Fixed daily ECU value per deployment |

### Chargeback Group Tags

Tags are written to `ess.billing.deployment_tags`. Chargeback extracts `deployment_group` from tags matching `chargeback_group:*`:

- `chargeback_group:platform_team` → `deployment_group: "platform_team"`
- `chargeback_group:security` → `deployment_group: "security"`
- No tag → `deployment_group: ""` (unallocated)

---

## Adding New Deployments

The bootstrap transform only runs once. For new deployments:

**1. Add the new deployment config:**

```json
PUT onprem_billing_config/_doc/<new-cluster-uuid>
{
  "deployment_id": "<new-cluster-uuid>",
  "deployment_name": "New Cluster",
  "deployment_tags": ["chargeback_group:team_name"],
  "daily_ecu": 100
}
```

**2. Re-execute the enrich policy:**

```json
POST /_enrich/policy/onprem_billing_config_enrich_policy/_execute
```

> **Warning:** Do not re-run the bootstrap transform - it would overwrite existing configurations with defaults.

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
GET monitoring-indices/_count
```

**Check enrich policy exists:**

```json
GET /_enrich/policy/onprem_billing_config_enrich_policy
```

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

### Incorrect ECU Values or Tags

**Verify deployment configuration:**

```json
GET onprem_billing_config/_search
{
  "_source": ["deployment_id", "deployment_name", "daily_ecu", "deployment_tags"]
}
```

**Re-execute enrich policy after config changes:**

```json
POST /_enrich/policy/onprem_billing_config_enrich_policy/_execute
```

### Common Errors

**"Enrich policy not found"** - Create and execute the enrich policy (see Step 2).

**"Enrich policy execution failed"** - Config index is empty. Wait for bootstrap or check bootstrap transform status.

### Getting Help

1. Check transform stats: `GET _transform/logs-onprem_billing*/_stats?human`
2. Check enrich policy: `GET /_enrich/policy/onprem_billing_config_enrich_policy`
3. Open an issue at [elasticsearch-chargeback](https://github.com/elastic/elasticsearch-chargeback) (this integration is maintained as part of the Chargeback project, not the standard Integrations repository)
