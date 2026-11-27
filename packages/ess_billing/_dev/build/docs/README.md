# Elasticsearch Service Billing

The Elasticsearch Service Billing integration (also known as the **Elastic Cloud billing integration**) lets you monitor usage and costs for your entire **Elastic Cloud organization**. It collects billing data from the [Elastic Cloud Billing API](https://www.elastic.co/docs/api/doc/cloud-billing/), normalizes daily cost and usage rows to the [FinOps Open Cost and Usage Specification (FOCUS) 1.4](https://focus.finops.org/docs/specification/v1-4/), and sends them to your target Elasticsearch cluster. Dashboards are provided out-of-the-box to help you visualize spending across your organization.

Using this integration, you could for instance create alerts whenever a new deployment or project is created, when your baseline spending exceeds a threshold, or export FOCUS-compliant rows directly to your FinOps platform.

## Supported Elastic Cloud products

This integration reports **organization-level** billing data. Any usage billed to your Elastic Cloud organization appears in the collected data, regardless of deployment model.

| Product | What is billed | How it appears in billing data |
| --- | --- | --- |
| **Elastic Cloud Hosted** | Deployments (Elasticsearch, Kibana, and add-on capacity), data transfer, snapshot storage, and related services | Resources with `ResourceType: deployment` |
| **Elastic Cloud Serverless** | Serverless projects (Elasticsearch, Observability, and Security), including usage-based dimensions such as ingest, retention, and search power | Resources with `ResourceType` values such as `elasticsearch`, `observability`, or `security` |
| **Cloud connected usage** | Elastic Cloud services consumed through [Cloud Connect](https://www.elastic.co/docs/deploy-manage/cloud-connect) on self-managed, ECE, or ECK clusters (for example, [Elastic Inference Service](https://www.elastic.co/docs/explore-analyze/elastic-inference/eis) token usage) | Organization-level line items for connected services |
| **Other Elastic Cloud services** | Add-on services billed to the organization (for example, Synthetics monitors) | Service-specific line items alongside deployments and projects |

Usage is metered in [Elastic Consumption Units (ECUs)](https://www.elastic.co/docs/deploy-manage/cloud-organization/billing/ecu) (`PricingCurrency: ECU`, recorded in `PricingCurrencyEffectiveCost`) and converted to USD (`BillingCurrency: USD`) across the FOCUS cost columns (`ListCost`, `ContractedCost`, `EffectiveCost`, and `BilledCost`).

## Data streams

The Elasticsearch Service Billing integration collects the following data streams:

* Your daily cost and usage in the `metrics-ess_billing.cost_and_usage` data stream, stored as FOCUS 1.4 Cost and Usage rows.
* For customers with a yearly commitment with Elastic, your credit status in the `metrics-ess_billing.credit` data stream.

By default, the last year of billing data is collected upon first execution of the integration. The data is then collected daily, and the integration automatically collects the latest data every day.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
This integration collects data at the organization level, so there is no need to target individual deployments or projects.

You will need the identifier of your Elastic Cloud **organization** (not a single deployment or project), which can be seen on the [cloud organization page](https://cloud.elastic.co/account/members).

You will also need to provision an API key with the `Billing admin` role on the [API keys page](https://cloud.elastic.co/account/keys). This key must have access to the organization whose billing data you want to collect.

For private cloud, or admin users, the cloud endpoint can be altered to match your requirements. You can change this in the "advanced settings" section of the integration configuration.

## Setup

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/docs/solutions/observability/get-started/quickstart-monitor-hosts-with-elastic-agent) guide.

If you run on Elastic Cloud (Hosted or Serverless), this integration is available as an [Elastic Managed integration](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations). When an Elastic Managed integration is available, you don't need to install an Elastic Agent to gather these metrics. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### FOCUS settings

The `cost_and_usage` stream includes the following settings to populate FOCUS 1.4 billing and pricing columns:

* **Purchase channel** (`purchase_channel`): How this organization buys Elastic Cloud (`direct`, `gcp_marketplace`, `aws_marketplace`, or `azure_marketplace`; default `direct`). For cloud marketplace purchases, the cloud provider issues the invoice, so `BilledCost` is `0` and `InvoiceIssuerName` is set to the cloud provider (`Google Cloud`, `Amazon Web Services`, or `Microsoft`). This avoids double-counting spend when combined with your cloud provider's own FOCUS dataset, while `ContractedCost`, `EffectiveCost`, and `PricingCurrencyEffectiveCost` continue to reflect your Elastic Cloud consumption.
* **Contracted price of one ECU (USD)** (`contracted_ecu_rate`, advanced): Price of one Elastic Consumption Unit in your contract in USD (default `"1.0"` for list price; invalid values are treated as `1.0`). Used to calculate `ContractedUnitPrice`, `ContractedCost`, `EffectiveCost`, and (for direct purchases) `BilledCost`. `ListUnitPrice` and `ListCost` always use the `1.00` USD list price.
* **Billing account name** (`billing_account_name`, advanced): Display name of the Elastic Cloud organization for `BillingAccountName`. When empty, `BillingAccountId` (the organization ID) is used.
* **Add deployment tags** (`add_tags`): Hosted deployments only; Serverless projects have no tags. When enabled, deployment tags are stored both as a FOCUS JSON object string in `Tags` and as `key:value` entries in `x_DeploymentTags` for filtering and Chargeback allocation.

## Upgrading from 1.x

Version `2.0.0` replaces the `metrics-ess_billing.billing` data stream and `ess.billing.*` fields with `metrics-ess_billing.cost_and_usage` using FOCUS 1.4 Cost and Usage column names:

* **Automatic backfill:** Upgrading creates `metrics-ess_billing.cost_and_usage-*` and collects historical billing data from the Elastic Cloud Billing API for your configured lookbehind period (`365d` by default).
* **Existing indices:** Old `metrics-ess_billing.billing-*` indices are not deleted automatically. Update custom saved searches, dashboards, alerts, transforms, and exports to read from `metrics-ess_billing.cost_and_usage-*` and the new fields below, then delete `metrics-ess_billing.billing-*` when no longer needed.
* **Marketplace organizations:** Set **Purchase channel** in the integration policy when upgrading. Rows collected before changing this setting carry the `direct` default (`InvoiceIssuerName: "Elastic"`).
* **Chargeback integration:** Upgrade the Chargeback integration alongside `ess_billing` `2.0.0` so its transforms query `metrics-ess_billing.cost_and_usage-*`.

| 1.x field | 2.0 field(s) | Notes |
| --- | --- | --- |
| `ess.billing.organization_id` | `BillingAccountId`, `BillingAccountName` | `BillingAccountName` uses the **Billing account name** setting, or `BillingAccountId` when empty |
| `ess.billing.deployment_id` | `ResourceId` | Elasticsearch resource ID for Hosted deployments |
| `ess.billing.deployment_name` | `ResourceName` | Omitted when the billing API returns an empty name (Serverless) |
| `ess.billing.deployment_type` | `ResourceType` | `deployment` for Hosted; project type for Serverless |
| `ess.billing.deployment_tags` | `Tags`, `x_DeploymentTags` | `Tags` is a JSON object string; `x_DeploymentTags` preserves `key:value` terms |
| `ess.billing.sku` | `SkuPriceId`, `SkuId`, `SkuPriceDetails.x_SubscriptionLevel` | `SkuId` holds the pricing-table SKU |
| `ess.billing.ram_per_zone` | `SkuPriceDetails.MemorySize` | Converted from MB per zone to GiB |
| `ess.billing.zone_count` | `SkuPriceDetails.x_ZoneCount` | Number of availability zones |
| `cloud.machine.type` | `SkuPriceDetails.InstanceType`, `cloud.machine.type` | Both populated |
| `ess.billing.type` | `SkuMeter` | Billing dimension (for example, `capacity` or `data_transfer`) |
| `ess.billing.name` | `ChargeDescription` | Line-item description from the billing API |
| `ess.billing.kind` | `ServiceName`, `ServiceCategory`, `ServiceSubcategory` | Mapped to FOCUS service taxonomy |
| `ess.billing.from` | `ChargePeriodStart`, `BillingPeriodStart`, `@timestamp` | `BillingPeriodStart` is the start of the calendar month |
| `ess.billing.to` | `ChargePeriodEnd`, `BillingPeriodEnd` | Exclusive end timestamps |
| `ess.billing.quantity.value` | `ConsumedQuantity`, `PricingQuantity` | Metered quantity |
| `ess.billing.unit` | `ConsumedUnit`, `PricingUnit` | Unit of measure as returned by the billing API |
| `ess.billing.rate.value` | `PricingCurrencyListUnitPrice`, `PricingCurrencyContractedUnitPrice`, `ListUnitPrice`, `ContractedUnitPrice` | `PricingCurrency*` in ECU; `ListUnitPrice` and `ContractedUnitPrice` in USD |
| `ess.billing.total_ecu` | `PricingCurrencyEffectiveCost`, `ListCost`, `ContractedCost`, `EffectiveCost`, `BilledCost` | `PricingCurrencyEffectiveCost` in ECU; USD cost columns (`BilledCost: 0` for marketplace) |
| `ess.billing.cloud.service.type` | `x_ServerlessServiceType` | Serverless SKUs only |
| `ess.billing.quantity.formatted_value`, `ess.billing.rate.formatted_value`, `ess.billing.display_quantity.*` | Dropped | Display strings derivable from numeric quantity, rate, and unit |

## Data streams reference

### `metrics-ess_billing.cost_and_usage` data stream

The `metrics-ess_billing.cost_and_usage` data stream collects daily billing line items from the Elastic Cloud Billing API and stores each event as a FOCUS 1.4 Cost and Usage row (`x_FocusVersion: "1.4"`). Line items represent an Elastic Cloud Hosted deployment, a Serverless project, a cloud connected service, or another organization-level service (for example, Synthetics monitors).

For Serverless projects, `ResourceType` reflects the project type (for example, `observability` or `security`). For Hosted deployments, `ResourceType` is `deployment`, and `ResourceId` contains the ID of the deployment's Elasticsearch resource, as returned by the billing API. This is not the deployment ID shown in the Elastic Cloud console. Use `ResourceName` to identify the deployment.

{{event "cost_and_usage"}}

{{fields "cost_and_usage"}}

![ESS Billing Dashboard](../img/ess_billing-billingdashboard.png)

### `metrics-ess_billing.credit` data stream

The `metrics-ess_billing.credit` data stream collects credit data from the Elastic Cloud Billing API. This is only available for customers with a direct yearly or multi-year contract with Elastic (not marketplace or monthly subscriptions). ECU credits apply to all Elastic Cloud usage in the organization, including Hosted, Serverless, and cloud connected services.

{{event "credits"}}

{{fields "credits"}}

![ESS Credits Dashboard](../img/ess_billing-creditsdashboard.png)
