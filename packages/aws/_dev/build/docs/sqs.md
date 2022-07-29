# SQS

The SQS integration allows you to monitor Amazon Simple Queue Service (Amazon SQS). The service can be used to send messages via web service applications.

Use the SQS integration to view metrics on the messages sent, stored, and received via Amazon SQS. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference metrics when troubleshooting an issue.

For example, you could view the number of messages in the queue that are delayed and not available for reading immediately. Then you can alert the relevant project manager by email.

## Data streams

The SQS integration collects one type of data stream: metrics.

**Metrics** give you insight into the state of Amazon SQS.
Metric data streams collected by the SQS integration include the number of messages that are in flight, the number of ReceiveMessage API calls that did not return a message, and more. See more details in the [Metrics reference](#metrics-reference).

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

## Metrics reference

{{event "sqs"}}

{{fields "sqs"}}