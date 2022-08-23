# AWS CloudTrail

The AWS CloudTrail integration allows you to monitor [AWS CloudTrail](https://aws.amazon.com/cloudtrail/).

Use the AWS CloudTrail integration to collect and parse logs related to account activity across your AWS infrastructure.
Then visualize that data in Kibana, create alerts to notify you if something goes wrong,
and reference logs when troubleshooting an issue.

For example, you could use the data from this integration to spot unusual activity in your AWS accounts—like excessive failed AWS console sign in attempts.

## Data streams

The AWS CloudTrail integration collects one type of data: logs.

**Logs** help you keep a record of every event that CloudTrail receives.
These logs are useful for many scenarios, including security and access audits.
See more details in the [Logs reference](#logs-reference).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Before using any AWS integration you will need:

* **AWS Credentials** to connect with your AWS account.
* **AWS Permissions** to make sure the user you're using to connect has permission to share the relevant data.

For more details about these requirements, see the **AWS** integration documentation.

## Setup

Use this integration if you only need to collect data from the AWS CloudTrail service.

If you want to collect data from two or more AWS services, consider using the **AWS** integration.
When you configure the AWS integration, you can collect data from as many AWS services as you'd like.

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Logs reference

The `cloudtrail` data stream collects AWS CloudTrail logs. CloudTrail monitors events like
user activity and API usage in AWS services. If a user creates a trail, it delivers those events as log
files to a specific Amazon S3 bucket.

> Note: Use the *CloudTrail Digest Logs regex* setting to define regex to match the path
of the CloudTrail Digest S3 Objects you'd like to read.
If blank, CloudTrail Digest logs will be skipped.

{{fields "cloudtrail"}}

{{event "cloudtrail"}}
