# Amazon EBS
The Amazon EBS integration allows you to monitor [Amazon Elastic Block Store (EBS)](https://aws.amazon.com/ebs/). Amazon EBS is a block-storage service designed for Amazon Elastic Compute Cloud (Amazon EC2).
Use the Amazon EBS integration to collect metrics related to your Amazon EBS storage.
Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference metrics when troubleshooting an issue.
For example, you could use this data to view the total number of seconds spent by all write operations that completed in a specified period of time for an EBS volume. Then you can alert the relevant budget holder about that throughput data by email.

## Data streams
The Amazon EBS integration collects one type of data: metrics.

**Metrics** give you insight into the state of Amazon EBS.
Metric data streams collected by the Amazon EBS integration include the number of read and write operation requests waiting to be completed in a specified period of time, and more. See more details in the [Metrics](#metrics-reference)

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Before using any AWS integration you will need:

 * **AWS Credentials** to connect with your AWS account.
 * **AWS Permissions** to make sure the user you're using to connect has permission to share the relevant data.

For more details about these requirements, see the **AWS** integration documentation.
## Setup
Use this integration if you only need to collect data from the Amazon EBS service.
If you want to collect data from two or more AWS services, consider using the **AWS** integration.
When you configure the AWS integration, you can collect data from as many AWS services as you'd like.
For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Metrics reference 
The `ebs` data stream collects EBS metrics from AWS.
An example event for `ebs` looks as following:

{{event "ebs"}}

{{fields "ebs"}}