# CloudFront

The AWS CloudFront integration allows you to monitor your [AWS CloudFront](https://aws.amazon.com/cloudfront/) usage.

Use the AWS CloudFront integration to collect and parse logs related to content delivery via CloudFront.
Visualize that data in Kibana, create alerts to notify you if something goes wrong,
and reference logs when troubleshooting an issue.

For example, if you wanted to know when there are more than 25 failed requests for a single
piece of content in a given time period, you could search the logs for that time period, find all
requests for that unique piece of content, and filter by response type.
Then you could troubleshoot the issue by looking at additional context in the logs like the
number of _unique_ users (by IP address) who experienced the issue, where the request is coming from,
or whether there are patterns related to the operating system or browser used when the request failed.

## Data types

The AWS CloudFront integration collects one type of data: logs.

**Logs** help you keep a record of every user request that CloudFront receives.
These logs are useful for many scenarios, including security and access audits.
See more details in the [Logs reference](#logs-reference).

## Requirements

Before using any AWS integration you will need:

* **AWS Credentials** to connect with your AWS account.
* **AWS Permissions** to make sure the user you're using to connect has permission to share the relevant data.

For more details about these requirements, see the **AWS** integration documentation.

## Setup

Use this integration if you only need to collect data from the AWS CloudFront service.

If you want to collect data from two or more AWS services, consider using the
**AWS** integration. When you configure the AWS integration,
you can collect data from as many AWS services as you'd like.

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Logs reference

The `cloudfront` dataset collects standard logs (also called access logs) from AWS CloudFront.
CloudFront standard logs provide detailed records about every request that’s made to a distribution.

{{fields "cloudfront_logs"}}

{{event "cloudfront_logs"}}