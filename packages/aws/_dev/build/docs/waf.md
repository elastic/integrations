# AWS WAF

The AWS WAF integration allows you to monitor [AWS Web Application Firewall (WAF)](https://aws.amazon.com/waf/)—a web application firewall for protecting against common web exploits.

Use the AWS WAF integration to collect and parse logs related to firewall activity across your AWS infrastructure.
Then visualize that data in Kibana, create alerts to notify you if something goes wrong,
and reference logs when troubleshooting an issue.

For example, you could use the data from this integration to spot unusual SQL injection and cross-site scripting attempts on your AWS-hosted websites and web applications, in a given time period. You could also use the data to review or troubleshoot the rules that have been set up to block these web exploits. You can do this by looking at additional context in the logs, such as the source of the requests, and more.

## Data streams

The AWS WAF integration collects one type of data: logs.

**Logs** help you keep a record of events happening in AWS WAF.
Logs collected by the AWS WAF integration include information on the rule that terminated a request, the source of the request, and more. See more details in the [Logs reference](#logs-reference).

> Note: The `waf` data stream is specifically for WAF logs.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Before using any AWS integration you will need:

* **AWS Credentials** to connect with your AWS account.
* **AWS Permissions** to make sure the user you're using to connect has permission to share the relevant data.

For more details about these requirements, see the **AWS** integration documentation.

## Setup

Use this integration if you only need to collect data from the AWS WAF service.

If you want to collect data from two or more AWS services, consider using the **AWS** integration.
When you configure the AWS integration, you can collect data from as many AWS services as you'd like.

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Logs reference

The `waf` dataset is specifically for WAF logs. Export logs from Kinesis Data Firehose to Amazon S3 bucket which has SQS notification setup already.

{{fields "waf"}}

{{event "waf"}}