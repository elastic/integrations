# SNS

The SNS integration allows you to monitor Amazon Simple Notification Service (Amazon SNS). Amazon SNS is a managed messaging service for coordinating the delivery of push messages from software applications to subscribers. 

Use the SNS integration to view metrics on message delivery performance. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference metrics when troubleshooting an issue.

For example, you could view the total number of messages that Amazon SNS failed to deliver. Then you can alert the relevant person by email.

## Data streams

The SNS integration collects one type of data stream: metrics.

**Metrics** give you insight into the state of Amazon SNS.
Metric data streams collected by the SNS integration include the number of messages successfully delivered, the number of messages that Amazon SNS failed to deliver, and more. See more details in the [Metrics](#metrics-reference).

<!-- etc. -->

<!-- Optional notes -->

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

<!-- Other requirements -->

 Before using any AWS integration you will need:

 * **AWS Credentials** to connect with your AWS account.
 * **AWS Permissions** to make sure the user you're using to connect has permission to share the relevant data.

 For more details about these requirements, see the **AWS** integration documentation.

## Setup

<!-- Any prerequisite instructions -->

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

<!-- Additional set up instructions -->

 Use this integration if you only need to collect data from the <service name> service.

 If you want to collect data from two or more AWS services, consider using the **AWS** integration.
 When you configure the AWS integration, you can collect data from as many AWS services as you'd like.

## Metrics

{{event "sns"}}

{{fields "sns"}}