# Chargeback

_Technical preview: This integration is being developed by Elastic's Customer Engineering team. Please report any issues to the Elastician who shared this integration with you._

The Chargeback integration provides FinOps visibility into Elastic usage across tenants. By integrating data from the [**Elasticsearch Service Billing**](https://www.elastic.co/docs/reference/integrations/ess_billing/) and [**Elasticsearch**](https://www.elastic.co/docs/reference/integrations/elasticsearch/) integrations, it enables the determination of value provided by each deployment, data stream, and tier across the organisation. This allows Centre of Excellence (CoE) teams to accurately allocate costs back to the appropriate tenant.

The integration creates several transforms that aggregate billing and usage data into lookup indices optimized for cost analysis and chargeback reporting.

## What is FinOps?

FinOps is an operational framework and cultural practice aimed at maximizing the business value of cloud usage. It facilitates timely, data-driven decision-making and promotes financial accountability through collaboration among engineering, finance, and business teams.

## Purpose

The Chargeback integration assists organisations in addressing a crucial question:

> **"How is my organisation consuming the Elastic solution, and to which tenants can I allocate these costs?"**

The integration provides a breakdown of Elastic Consumption Units (ECUs) per:

- Deployment
- Data tier
- Data stream
- Day

Currently, Chargeback calculations consider only Elasticsearch data nodes. Contributions from other assets, like Kibana or ML nodes, are assumed to be shared proportionally among tenants. To incorporate indexing, querying, and storage in a weighted manner, a blended value is created using the following default weights (modifiable):
- Indexing: `20` (applicable only to the hot tier)
- Querying: `20`
- Storage: `40`

This default weighting means storage contributes most to the blended cost calculation, with indexing considered only on the hot tier. Adjust these weights based on your organisation's needs and best judgment.

Chargeback costs are presented based on a configured rate and unit. These are used to display cost in your local currency, for instance `EUR`, with a rate of `0.85` per ECU.

## Configuration

Configuration values are stored in the `chargeback_conf_lookup` index. The dashboard automatically applies the correct configuration based on the billing date falling within the `conf_start_date` and `conf_end_date` range.

### Update the default configuration:

Using `_update/config` updates the document with ID `config`:

```
POST chargeback_conf_lookup/_update/config
{
  "doc": {
    "conf_ecu_rate": 0.85,
    "conf_ecu_rate_unit": "EUR",
    "conf_indexing_weight": 20,
    "conf_query_weight": 20,
    "conf_storage_weight": 40,
    "conf_start_date": "2024-01-01T00:00:00.000Z",
    "conf_end_date": "2024-12-31T23:tie"
  }
}
```

### Add a new configuration period (for time-based rate changes):

Using `_doc` creates a new document with an auto-generated ID:

```
POST chargeback_conf_lookup/_doc
{
  "conf_ecu_rate": 0.95,
  "conf_ecu_rate_unit": "EUR",
  "conf_indexing_weight": 20,
  "conf_query_weight": 20,
  "conf_storage_weight": 40,
  "conf_start_date": "2025-01-01T00:00:00.000Z",
  "conf_end_date": "2025-12-31T23:59:59.999Z"
}
```

This allows you to have different rates for different time periods (e.g., quarterly or annual rate changes).

**Configuration Options:**
- `conf_ecu_rate`: The monetary value per ECU (e.g., 0.85)
- `conf_ecu_rate_unit`: The currency code (e.g., "EUR", "USD", "GBP")
- `conf_indexing_weight`: Weight for indexing operations (default: 20, only applies to hot tier)
- `conf_query_weight`: Weight for query operations (default: 20)
- `conf_storage_weight`: Weight for storage (default: 40)
- `conf_start_date`: Start date/time for the configuration period (ISO 8601 format)
- `conf_end_date`: End date/time for the configuration period (ISO 8601 format)

## Data and Transforms

The integration creates the following transforms to aggregate cost and usage data:

1. **billing_cluster_cost** - Aggregates daily ECU usage per deployment from ESS Billing data, with support for deployment groups via `chargeback_group` tags
2. **cluster_deployment_contribution** - Calculates per-deployment usage metrics (indexing time, query time, storage) from Elasticsearch monitoring data
3. **cluster_datastream_contribution** - Aggregates usage per data stream for detailed cost attribution
4. **cluster_tier_contribution** - Aggregates usage per data tier (hot, warm, cold, frozen)
5. **cluster_tier_and_ds_contribution** - Combined view of usage by both tier and data stream

These transforms produce lookup indices that are queried by the dashboard using ES|QL LOOKUP JOINs to correlate billing costs with actual usage patterns.

### Starting the Transforms

After installing the integration, you need to manually start the four usage-related transforms:

1. Navigate to **Stack Management → Transforms**
2. Filter for `chargeback` to see all Chargeback transforms
3. Start the following transforms:
   - `cluster_deployment_contribution`
   - `cluster_datastream_contribution`
   - `cluster_tier_contribution`
   - `cluster_tier_and_ds_contribution`

The `billing_cluster_cost` transform starts automatically and does not require manual intervention.

### Transform Health Monitoring

To set up alerts that notify you when transforms are not working:

1. Navigate to **Stack Management → Transforms**
2. Filter for `chargeback` to see all Chargeback transforms
3. Select a transform and click the **Actions** menu
4. Select **Create alert rule**
5. Configure the alert rule to notify when the transform health status changes

This will create a transform health rule that monitors the selected transform and sends notifications when issues are detected.

## Dashboard

Chargeback data can be viewed in the `[Chargeback] Cost and Consumption breakdown` dashboard, which provides:

- Cost breakdown by deployment, data tier, and data stream
- Time-series cost trends
- Deployment group filtering for team/project-based analysis
- Blended cost metrics combining indexing, querying, and storage usage
- ECU consumption vs. monetary cost comparison

![Cost and Consumption breakdown](../img/chargeback.png)

## Deployment Groups

The integration supports organizing deployments into logical groups using the `chargeback_group` tag on ESS Billing deployments. This enables cost allocation and filtering by teams, projects, or any organizational structure.

To assign a deployment to a chargeback group, add a tag to your deployment in the Elastic Cloud console in the format:
```
chargeback_group:<group-name>
```

For example: `chargeback_group:team-search` or `chargeback_group:project-analytics`

The `billing_cluster_cost` transform automatically extracts these tags from the `deployment_tags` field in ESS Billing data using runtime mappings. The dashboard includes a deployment group filter to view costs by specific groups, making it easy to track expenses per team or project.

**Note:** Each deployment should have only one `chargeback_group` tag. Having multiple tags can cause issues and lead to unpredictable cost allocation.

## Observability Rules

The following are sample observability rules that can help ensure data validity by notifying you when events occur that could compromise the accuracy of your chargeback data:

### Rule 1: New Chargeback Group Detected

Detects when a new `chargeback_group` tag is added to a deployment, allowing teams to be notified when new cost allocation groups are created.

**To create this alert**, navigate to **Dev Tools** in Kibana and run:
```json
POST kbn:/api/alerting/rule/chargeback_new_group_detected
{
  "name": "[Chargeback] New chargeback group detected",
  "tags": ["Chargeback"],
  "consumer": "alerts",
  "rule_type_id": ".es-query",
  "schedule": {
    "interval": "1h"
  },
  "params": {
    "size": 100,
    "esqlQuery": {
      "esql": "FROM billing_cluster_cost_lookup | STATS count = COUNT(*) BY deployment_group | SORT deployment_group | KEEP deployment_group"
    },
    "threshold": [0],
    "timeField": "@timestamp",
    "searchType": "esqlQuery",
    "timeWindowSize": 3,
    "timeWindowUnit": "d",
    "thresholdComparator": ">",
    "excludeHitsFromPreviousRun": true
  },
  "actions": []
}
```

### Rule 2: Deployment with Chargeback Group Missing Usage Data

Detects when a deployment has a chargeback group assigned but is not sending usage/consumption data. This indicates a potential configuration issue or data collection problem.

**To create this alert**, navigate to **Dev Tools** in Kibana and run:
```json
POST kbn:/api/alerting/rule/chargeback_deployment_missing_usage_data
{
  "name": "[Chargeback] Deployment with chargeback group missing usage data",
  "tags": ["Chargeback"],
  "consumer": "alerts",
  "rule_type_id": ".es-query",
  "schedule": {
    "interval": "1h"
  },
  "params": {
    "size": 100,
    "esqlQuery": {
      "esql": """FROM billing_cluster_cost_lookup
| WHERE deployment_group != ""
| LOOKUP JOIN cluster_deployment_contribution_lookup ON composite_key
| WHERE cluster_name IS NULL
| INLINE STATS count = COUNT(*) BY deployment_id, deployment_name, deployment_group
| EVAL result = CONCAT("Deployment `", deployment_name,"` (`", deployment_id,"`) in deployment group `", deployment_group, "` did not have usage data since ", left(composite_key,10),".")
| STATS result = VALUES(result)
| MV_EXPAND result"""
    },
    "threshold": [0],
    "timeField": "@timestamp",
    "searchType": "esqlQuery",
    "timeWindowSize": 3,
    "timeWindowUnit": "d",
    "thresholdComparator": ">",
    "excludeHitsFromPreviousRun": true
  },
  "actions": []
}
```

### Alert actions

**Configure an action** with the following message template appended to the default content (keep the new lines, as it helps with legibility):

```
Details:

{{#context.hits}}
• {{_source}}

{{/context.hits}}

Total: {{context.hits.length}}
```

## Requirements

To use this integration, the following prerequisites must be met:

**Monitoring Cluster:**
- Must be on Elasticsearch version **9.2.0+** due to the use of smart [ES|QL LOOKUP JOIN](https://www.elastic.co/docs/reference/query-languages/esql/esql-lookup-join) (conditional joins) in transforms and dashboard queries
- This is where the Chargeback integration should be installed

**Required Integrations:**
- [**Elasticsearch Service Billing**](https://www.elastic.co/docs/reference/integrations/ess_billing/) integration (v1.4.1+) must be installed and collecting billing data from your Elastic Cloud organization
- [**Elasticsearch**](https://www.elastic.co/docs/reference/integrations/elasticsearch/) integration (v1.16.0+) must be installed and collecting [usage data](https://www.elastic.co/docs/reference/integrations/elasticsearch/#indices-and-data-streams-usage-analysis) from all deployments you want to include in chargeback calculations

**Required Transforms:**
- The transform `logs-elasticsearch.index_pivot-default-{VERSION}` (from the Elasticsearch integration) must be running to aggregate usage metrics per index

**Data Flow:**
1. ESS Billing data is collected into `metrics-ess_billing.billing-*`
2. Elasticsearch usage data is collected into `metrics-elasticsearch.stack_monitoring.*` (or `monitoring-indices` for Stack Monitoring)
3. Chargeback transforms process and correlate this data
4. Dashboard queries the resulting lookup indices using ES|QL

**Note:** This integration must be installed on a centralized monitoring cluster that has visibility to both billing and usage data from your deployments.