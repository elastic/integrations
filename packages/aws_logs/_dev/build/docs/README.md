# Custom AWS Log Integration

The custom AWS logs integration offers users two ways to collect logs from AWS. These are from: 

* An [S3 bucket](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html) (with or without SQS notification)
* [CloudWatch](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/WhatIsCloudWatchLogs.html)

You can add custom ingest pipelines by adding the name to the pipeline configuration option. Creating custom ingest pipelines can be done either through the API or the [Ingest Node Pipeline UI](/app/management/ingest/ingest_pipelines/).

Use the AWS logs integration to collect logs on the operational health of your AWS resources, applications, and services running on AWS and on-premises. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference the logs when troubleshooting an issue.

For example, you could use the data from this integration to detect anomalous behavior in your environments. You could also use the data to troubleshoot the underlying issue by looking at additional context in the logs, such as the source of the behavior, and more.

## Data streams

The custom AWS logs integration collects one type of data stream: logs.

**Logs** help you keep a record of events happening in AWS CloudWatch and your S3 buckets.
Log data streams collected by the custom AWS logs enable you to:

* Retrieve logs from an S3 bucket
  * From S3 objects that are pointed to by S3 notification events read from an SQS queue, or
  * Directly polling a list of S3 objects in an S3 bucket. 
* Retrieve logs from CloudWatch
  * You can retrieve logs from all log streams in a specific log group. 
  * Amazon CloudWatch logs can be used to store log files from Amazon Elastic Compute Cloud(EC2), AWS CloudTrail, Route53, and other sources.



The log data streams includes the log message, along with contextual information.

See more details in the [Logs reference](#logs-reference).

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

<!-- Repeat for both Logs and Metrics if applicable -->

## Logs reference

### Collecting logs from S3 bucket
> Note: The `queue_url` and `bucket_arn` cannot be both set at the same time. 
> At least one of the two values must be set.

#### Using SQS notification
**We recommend you use SQS notification.** This is because polling list of S3 objects is expensive in terms of performance and costs. This input integration also supports S3 notification from SNS to SQS.

Use the `queue_url` configuration value setting to enable the SQS notification method.
#### Using polling notification
We recommend polling should only be used when no SQS notification can be attached to the S3 buckets. 

Use the `bucket_arn` and `number_of_workers` configuration value settings to enable the S3 bucket list polling method.

### Collecting logs from CloudWatch

When collecting logs from CloudWatch is enabled, users can retrieve logs from 
all log streams in a specific log group.

Use the `filterLogEvents` AWS API to list log events from the specified log group. 
