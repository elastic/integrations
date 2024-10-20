<!-- Use this template language as a starting point, replacing {placeholder text} with details about the integration. -->
<!-- Find more detailed documentation guidelines in https://github.com/elastic/integrations/blob/main/docs/documentation_guidelines.md -->

# Elasticsearch Service Billing

The Elasticsearch Service Billing integration allows you to monitor Elasticsearch Service usage and costs. It collects billing data from the [Elasticsearch Service billing API](https://www.elastic.co/guide/en/cloud/current/Billing_Costs_Analysis.html) and sends it to your target Elasticsearch cluster. Dashboards are provided out-of-the-box to help you visualize your Elasticsearch Service usage and costs.

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

For private cloud, or admin users, the cloud endpoint can be altered to match your requirements.

## Setup

<!-- Any prerequisite instructions -->

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

<!-- Additional set up instructions -->

<!-- If applicable -->
<!-- ## Logs reference -->

<!-- Repeat for each data stream of the current type -->
<!-- ### {Data stream name}

The `{data stream name}` data stream provides events from {source} of the following types: {list types}. -->

<!-- Optional -->
<!-- #### Example

An example event for `{data stream name}` looks as following:

{code block with example} -->

<!-- #### Exported fields

{insert table} -->

<!-- If applicable -->
<!-- ## Metrics reference -->

<!-- Repeat for each data stream of the current type -->
<!-- ### {Data stream name}

The `{data stream name}` data stream provides events from {source} of the following types: {list types}. -->

<!-- Optional -->
<!-- #### Example

An example event for `{data stream name}` looks as following:

{code block with example} -->

<!-- #### Exported fields

{insert table} -->
