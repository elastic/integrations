# Elasticsearch Service Billing

The Elasticsearch Service Billing integration allows you to monitor Elasticsearch Service usage and costs. It collects billing data from the [Elasticsearch Service billing API](https://www.elastic.co/docs/api/doc/cloud-billing/) and sends it to your target Elasticsearch cluster. Dashboards are provided out-of-the-box to help you visualize your Elasticsearch Service usage and costs.

Using this integration, you could for instance create alerts whenever a new deployment is created, or when your baseline spending exceeds a certain threshold.

## Data streams

The Elasticsearch Service Billing integration collects the following data streams:

* Your daily spending in the `metrics-ess_billing.billing` data stream.
* For customers with a yearly commitment with Elastic, your credit status in the `metrics-ess_billing.credit` data stream.

By default, the last year of data of billing data is collected upon first execution of the integration. The data is then collected daily, the integration will automatically collect the latest data every day.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

You will need to recover the identifier of your organization, which can be seen in the [cloud organization page](https://cloud.elastic.co/account/members).

You will also need to provision an API key with the `Billing admin` role in the [API keys page](https://cloud.elastic.co/account/keys).

For private cloud, or admin users, the cloud endpoint can be altered to match your requirements. You can change this in the "advanced settings" section of the integration configuration.

## Setup

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/docs/solutions/observability/get-started/quickstart-monitor-hosts-with-elastic-agent) guide.

If you run in the cloud (Cloud Hosted of Serverless), this integration is available [agentless](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) from cluster version 8.17 onward - if this criteria is met, you don't need to install an Elastic Agent to gather these metrics.

## Data streams reference

###  `metrics-ess_billing.billing` data stream

The `metrics-ess_billing.billing` data stream collects billing data from the Elasticsearch Service billing API. This exposes information about the ECU consumption for each deployment or service provided by Elastic (serverless projects, synthetics monitors).

{{event "billing"}}

{{fields "billing"}}

![ESS Billing Dashboard](../img/ess_billing-billingdashboard.png)

### `metrics-ess_billing.credit` data stream

The `metrics-ess_billing.credit` data stream collects credit data from the Elasticsearch Service billing API. This is only available for customers with a direct yearly or multi-year contract with Elastic (not marketplace or monthly subscriptions).

{{event "credits"}}

{{fields "credits"}}

![ESS Credits Dashboard](../img/ess_billing-creditsdashboard.png)
