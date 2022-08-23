# Amazon S3 Storage Lens

The Amazon S3 Storage Lens integration allows you to monitor [Amazon S3 Storage Lens](https://aws.amazon.com/s3/storage-analytics-insights/)—an analytics service for Amazon S3.

Use the Amazon S3 Storage Lens integration to view metrics on object storage usage and activity trends. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference metrics when troubleshooting an issue.

For example, you could track your total storage and object count by region—allowing you more easily visualize trends and anticipate problems before they happen.

## Data streams

The Amazon S3 Storage Lens integration collects one type of data: metrics.

**Metrics** give you insight into the state of Amazon S3 Storage Lens.
Metrics collected by the S3 Storage Lens integration include usage data for total storage, object counts, average object sizes, and more. See more details in the [Metrics reference](#metrics-reference).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Before using any AWS integration you will need:

* **AWS Credentials** to connect with your AWS account.
* **AWS Permissions** to make sure the user you're using to connect has permission to share the relevant data.

For more details about these requirements, see the **AWS** integration documentation.

## Setup

Use this integration if you only need to collect data from the Amazon S3 Storage Lens service.

If you want to collect data from two or more AWS services, consider using the **AWS** integration.
When you configure the AWS integration, you can collect data from as many AWS services as you'd like.

For step-by-step instructions on how to set up an integration, see the [Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Metrics reference

{{event "s3_storage_lens"}}

{{fields "s3_storage_lens"}}