# AWS CloudWatch

The AWS CloudWatch integration allows you to monitor [AWS CloudWatch](https://aws.amazon.com/cloudwatch/). AWS CloudWatch is a service that provides data and insights for monitoring applications and changes to system performance.

Use the AWS CloudWatch integration to collect metrics and logs on the operational health of your AWS resources, applications, and services running on AWS and on-premises. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference logs and metrics when troubleshooting an issue.

For example, you could use the data from this integration to detect anomalous behavior in your environments. You could also use the data to troubleshoot the underlying issue by looking at additional context in the logs and metrics, such as the source of the behavior, and more.

## Data streams

The AWS CloudWatch integration collects two types of data: logs and metrics.

**Logs** help you keep a record of different services in AWS, like EC2, RDS, and S3.
The log data stream includes the CloudWatch log message along with contextual information. See more details in the [Logs reference](#logs-reference).

**Metrics** give you insight into the state of different services in AWS, like EC2, RDS, and S3.
The metric data stream includes the metrics that are returned from a CloudWatch API query along with contextual information. See more details in the [Metrics reference](#metrics-reference).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Before using any AWS integration you will need:

* **AWS Credentials** to connect with your AWS account.
* **AWS Permissions** to make sure the user you're using to connect has permission to share the relevant data.

For more details about these requirements, see the **AWS** integration documentation.

## Setup

Use this integration if you only need to collect data from the AWS CloudWatch service.

If you want to collect data from two or more AWS services, consider using the **AWS** integration.
When you configure the AWS integration, you can collect data from as many AWS services as you'd like.

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Logs reference

The `cloudwatch` data stream collects CloudWatch logs. Users can use Amazon
CloudWatch logs to monitor, store, and access log files from different sources.

{{fields "cloudwatch_logs"}}

{{event "cloudwatch_logs"}}

## Metrics

{{event "cloudwatch_metrics"}}

{{fields "cloudwatch_metrics"}}