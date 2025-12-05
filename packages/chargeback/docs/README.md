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

### Transform Auto-Start

All Chargeback transforms start automatically when the integration is installed. No manual intervention is required to start the transforms.

**Performance Note:** On clusters with months of historical monitoring data for multiple deployments, the initial transform execution may process a large volume of data. This can cause temporary performance impact during the first run. The transforms will then run incrementally on their configured schedules (15-60 minute intervals), processing only new data with minimal overhead.

You can verify the transforms are running by navigating to **Stack Management → Transforms** and filtering for `chargeback`.

### Transform Health Monitoring

The integration includes a **Transform Health Monitoring** alert rule template that can be installed from the integration page. This rule monitors all Chargeback transforms and alerts when they encounter issues or failures, providing proactive notification of any problems with data processing.

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

## Observability Alerting

This integration includes 3 pre-configured alert rule templates that can be installed directly from the integration page in Kibana:

1. **Transform Health Monitoring** - Monitors the health of all Chargeback transforms and alerts when they encounter issues or failures
2. **New Chargeback Group Detected** - Notifies when a new `chargeback_group` tag is added to a deployment
3. **Deployment with Chargeback Group Missing Usage Data** - Detects when a deployment has a chargeback group assigned but is not sending usage/consumption data

**Important:** For alert rules 2 and 3, ensure that the Chargeback transforms are running before setting them up. These alerting rules query the lookup indices created by the transforms (`billing_cluster_cost_lookup`, `cluster_deployment_contribution_lookup`, etc.). If the transforms are not started, the alerts will not function correctly.

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