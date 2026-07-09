# Elasticsearch Service Billing

The Elasticsearch Service Billing integration (also known as the **Elastic Cloud billing integration**) lets you monitor usage and costs for your entire **Elastic Cloud organization**. It collects billing data from the [Elastic Cloud Billing API](https://www.elastic.co/docs/api/doc/cloud-billing/) and sends it to your target Elasticsearch cluster. Dashboards are provided out-of-the-box to help you visualize spending across your organization.

Using this integration, you could for instance create alerts whenever a new deployment or project is created, or when your baseline spending exceeds a certain threshold.

## Supported Elastic Cloud products

This integration reports **organization-level** billing data. Any usage billed to your Elastic Cloud organization appears in the collected data, regardless of deployment model.

| Product | What is billed | How it appears in billing data |
| --- | --- | --- |
| **Elastic Cloud Hosted** | Deployments (Elasticsearch, Kibana, and add-on capacity), data transfer, snapshot storage, and related services | Instances with `deployment_type: deployment` |
| **Elastic Cloud Serverless** | Serverless projects (Elasticsearch, Observability, and Security), including usage-based dimensions such as ingest, retention, and search power | Instances with project types such as `elasticsearch`, `observability`, or `security` |
| **Cloud connected usage** | Elastic Cloud services consumed through [Cloud Connect](https://www.elastic.co/docs/deploy-manage/cloud-connect) on self-managed, ECE, or ECK clusters (for example, [Elastic Inference Service](https://www.elastic.co/docs/explore-analyze/elastic-inference/eis) token usage) | Organization-level line items for connected services |
| **Other Elastic Cloud services** | Add-on services billed to the organization (for example, Synthetics monitors) | Service-specific line items alongside deployments and projects |

All usage is metered in [Elastic Consumption Units (ECUs)](https://www.elastic.co/docs/deploy-manage/cloud-organization/billing/ecu). The integration does not distinguish between billing models (pay-as-you-go, marketplace, or prepaid consumption)—it reflects the ECU consumption recorded for your organization.

## Data streams

The Elasticsearch Service Billing integration collects the following data streams:

* Your daily spending in the `metrics-ess_billing.billing` data stream.
* For customers with a yearly commitment with Elastic, your credit status in the `metrics-ess_billing.credit` data stream.

By default, the last year of data of billing data is collected upon first execution of the integration. The data is then collected daily, the integration will automatically collect the latest data every day.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
This integration collects data at the organization level, so no need to target individual deployments or projects.

You will need the identifier of your Elastic Cloud **organization** (not a single deployment or project), which can be seen on the [cloud organization page](https://cloud.elastic.co/account/members).

You will also need to provision an API key with the `Billing admin` role on the [API keys page](https://cloud.elastic.co/account/keys). This key must have access to the organization whose billing data you want to collect.

For private cloud, or admin users, the cloud endpoint can be altered to match your requirements. You can change this in the "advanced settings" section of the integration configuration.

## Setup

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/docs/solutions/observability/get-started/quickstart-monitor-hosts-with-elastic-agent) guide.

If you run on Elastic Cloud (Hosted or Serverless), this integration is available [agentless](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) from cluster version 8.17 onward. When agentless deployment is available, you don't need to install an Elastic Agent to gather these metrics.

## Data streams reference

###  `metrics-ess_billing.billing` data stream

The `metrics-ess_billing.billing` data stream collects billing data from the Elastic Cloud Billing API. Each event represents ECU consumption for a billing line item. Line items are grouped by instance—an instance may be an Elastic Cloud Hosted deployment, a Serverless project, a cloud connected service, or another organization-level service (for example, Synthetics monitors).

Field names such as `ess.billing.deployment_id` and `ess.billing.deployment_name` are used for all instance types for backward compatibility. For Serverless projects, `ess.billing.deployment_type` reflects the project type (for example, `observability` or `security`). For Hosted deployments, it is `deployment`.

{{event "billing"}}

{{fields "billing"}}

![ESS Billing Dashboard](../img/ess_billing-billingdashboard.png)

### `metrics-ess_billing.credit` data stream

The `metrics-ess_billing.credit` data stream collects credit data from the Elastic Cloud Billing API. This is only available for customers with a direct yearly or multi-year contract with Elastic (not marketplace or monthly subscriptions). ECU credits apply to all Elastic Cloud usage in the organization, including Hosted, Serverless, and cloud connected services.

{{event "credits"}}

{{fields "credits"}}

![ESS Credits Dashboard](../img/ess_billing-creditsdashboard.png)
