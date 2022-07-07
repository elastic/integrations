# Amazon EC2

The Amazon EC2 integration allows you to monitor [Amazon Elastic Compute Cloud (Amazon EC2)](https://aws.amazon.com/ec2/). Amazon EC2 is a web service that allows you to use virtual computers, or "instances", operated by AWS to perform computing for your own applications.

Use the Amazon EC2 integration to collect logs and metrics related to your EC2 instances. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference the logs and metrics when troubleshooting an issue.

For example, you could use this data to view Amazon EC2 error messages. Then you can alert the relevant person about that error message by email.

## Data streams

The Amazon EC2 integration collects two types of data streams: logs and metrics.

**Logs** help you keep a record of events happening in Amazon EC2.
Log data streams collected by the Amazon EC2 integration include the region in which an instance  is running, the operating system architecture, and more. See more details in the [Logs reference](#logs-reference).

**Metrics** give you insight into the state of Amazon EC2 and its instances.
Metric data streams collected by the Amazon EC2 integration include the Amazon EC2 instance ID, the number of earned CPU credits that an instance has accrued since it was launched or started, and more. See more details in the [Metrics reference](#metrics-reference).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Before using any AWS integration you will need:

 * **AWS Credentials** to connect with your AWS account.
 * **AWS Permissions** to make sure the user you're using to connect has permission to share the relevant data.

For more details about these requirements, see the **AWS** integration documentation.
## Setup
For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

Use this integration if you only need to collect data from the Amazon EC2 service.

If you want to collect data from two or more AWS services, consider using the **AWS** integration.
When you configure the AWS integration, you can collect data from as many AWS services as you'd like.

## Logs reference

The `ec2` dataset is specifically for EC2 logs stored in AWS CloudWatch. Export logs
from log groups to Amazon S3 bucket which has SQS notification setup already.
With this dataset, EC2 logs will be parsed into fields like  `ip_address`
and `process.name`. For logs from other services, please use `cloudwatch` dataset.

{{fields "ec2_logs"}}

{{event "ec2_logs"}}

## Metrics reference

{{event "ec2_metrics"}}

{{fields "ec2_metrics"}}