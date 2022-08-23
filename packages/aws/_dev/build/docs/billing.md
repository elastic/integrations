# AWS Billing

The AWS Billing integration allows you to monitor your [AWS spending](https://aws.amazon.com/aws-cost-management/aws-billing/).

Use the AWS Billing integration to collect metrics related to your monthly AWS bills. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference metrics when troubleshooting an issue.

For example, you could use this data to easily view your total estimated charges or billing by service. Then you can alert the relevant budget holder about those costs by email.

## Data streams

The AWS Billing integration collects one type of data: metrics.

**Metrics** give you insight into the state of your AWS spending, including the estimated costs for various AWS services. Metrics are gathered with the AWS [Cost Explorer API](https://docs.aws.amazon.com/cost-management/latest/userguide/ce-api.html)).

See more details in the [Metrics reference](#metrics-reference).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Before using any AWS integration you will need:

* **AWS Credentials** to connect with your AWS account.
* **AWS Permissions** to make sure the user you're using to connect has permission to share the relevant data.

For more details about these requirements, see the **AWS** integration documentation.

## Setup

Use this integration if you only need to collect billing data from AWS.

If you want to collect data from two or more AWS services, consider using the **AWS** integration. When you configure the AWS integration, you can collect data from as many AWS services as you'd like.

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Metrics reference

The `billing` data stream collects billing metrics from AWS.

An example event for `billing` looks as following:

{{event "billing"}}

{{fields "billing"}}
