# Amazon DynamoDB
## Overview
The Amazon DynamoDB integration allows you to monitor [Amazon DynamoDB](https://aws.amazon.com/dynamodb/). Amazon DynamoDB is a fully managed, serverless, key-value, NoSQL database.

Use the Amazon DynamoDB integration to collect metrics related to your Amazon DynamoDB databases. 
Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference metrics when troubleshooting an issue.
For example, you could use this data to view the provisioned throughput capacity for a new provisioned table in Amazon DynamoDB. Then you can alert the relevant budget holder about those throughput capacity units by email.

## Data streams
The Amazon DynamoDB integration collects one type of data: metrics.

**Metrics** give you insight into the state of Amazon DynamoDB.
Metric data streams collected by the Amazon DynamoDB integration include the maximum number of read and write capacity units that can be used by an account, and more. See more details in the [Metrics](#metrics-reference).

## Requirements
You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Before using any AWS integration you will need:

 * **AWS Credentials** to connect with your AWS account.
 * **AWS Permissions** to make sure the user you're using to connect has permission to share the relevant data.

For more details about these requirements, see the **AWS** integration documentation.

## Setup
Use this integration if you only need to collect data from the Amazon DynamoDB service.
If you want to collect data from two or more AWS services, consider using the **AWS** integration.
When you configure the AWS integration, you can collect data from as many AWS services as you'd like.
For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Metrics reference
The `dynamodb` data stream collects DynamoDB metrics from AWS.
An example event for `dynamodb` looks as following:

{{event "dynamodb"}}

{{fields "dynamodb"}}