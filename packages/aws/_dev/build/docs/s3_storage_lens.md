# S3 Storage Lens

The S3 Storage Lens integration allows you to monitor Amazon S3 Storage Lens. Amazon S3 Storage Lens is a cloud storage analytics service for Amazon S3. 

Use the S3 Storage Lens integration to view metrics on object storage usage and activity trends, as well as contextual recommendations for reducing costs and keeping data protected. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference metrics when troubleshooting an issue.

For example, you could view the total number of GET requests made to your Amazon S3 buckets. Then you can alert the relevant project manager by email.

## Data streams

The S3 Storage Lens integration collects one type of data stream: metrics.

**Metrics** give you insight into the state of Amazon S3 Storage Lens.
Metric data streams collected by the S3 Storage Lens integration include usage data for total storage, object counts, average object sizes, and more. See more details in the [Metrics reference](#metrics-reference).

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

 Use this integration if you only need to collect data from the Amazon S3 Storage Lens service.

 If you want to collect data from two or more AWS services, consider using the **AWS** integration.
 When you configure the AWS integration, you can collect data from as many AWS services as you'd like.

## Metrics reference

{{event "s3_storage_lens"}}

{{fields "s3_storage_lens"}}