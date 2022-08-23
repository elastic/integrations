# Amazon Redshift

This integration is used to fetch metrics from [Amazon Redshift](https://aws.amazon.com/redshift/)—a cloud data warehouse.

Use the Amazon Redshift integration to collect and parse metrics related to the health status, resource usage, and query performance of Amazon Redshift. Then visualize that data in Kibana, create alerts to notify you if something goes wrong,
and reference metrics when troubleshooting an issue.

For example, you could use the data from this integration to track the health status of your clusters. Then create an alert that notifies a team if health status changes unexpectedly.

## Data streams

The Amazon Redshift integration collects one type of data: metrics.

**Metrics** give you insight into the state of Amazon Redshift.
Metrics collected by the Amazon Redshift integration include disk read throughput, storage read latency, query latency, and more. See more details in the [Metrics reference](#metrics-reference).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Before using any AWS integration you will need:

* **AWS Credentials** to connect with your AWS account.
* **AWS Permissions** to make sure the user you're using to connect has permission to share the relevant data.

For more details about these requirements, see the **AWS** integration documentation.

## Setup

Use this integration if you only need to collect data from the Amazon Redshift.

If you want to collect data from two or more AWS services, consider using the **AWS** integration.
When you configure the AWS integration, you can collect data from as many AWS services as you'd like.

For step-by-step instructions on how to set up an integration, see the [Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Metrics

{{event "redshift" }}

{{fields "redshift"}}