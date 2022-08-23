# AWS SNS

The AWS SNS integration allows you to monitor [Amazon Simple Notification Service (Amazon SNS)](https://aws.amazon.com/sns/)—a managed messaging service.

Use the AWS SNS integration to view metrics on message delivery performance. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference metrics when troubleshooting an issue.

For example, use this integration to track your SNS SMS monthly spending. Then set alerts to post to Slack when you're approaching your budget for the month.

## Data streams

The AWS SNS integration collects one type of data: metrics.

**Metrics** give you insight into the state of AWS SNS.
Metrics collected by the AWS SNS integration include the number of messages successfully delivered, the number of messages that Amazon SNS failed to deliver, and more. See more details in the [Metrics](#metrics-reference).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Before using any AWS integration you will need:

* **AWS Credentials** to connect with your AWS account.
* **AWS Permissions** to make sure the user you're using to connect has permission to share the relevant data.

For more details about these requirements, see the **AWS** integration documentation.

## Setup

Use this integration if you only need to collect data from the AWS SNS service.

If you want to collect data from two or more AWS services, consider using the **AWS** integration.
When you configure the AWS integration, you can collect data from as many AWS services as you'd like.

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Metrics reference

{{event "sns"}}

{{fields "sns"}}