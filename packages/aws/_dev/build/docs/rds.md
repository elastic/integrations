# Amazon RDS

The Amazon RDS integration allows you to monitor [Amazon Relational Database Service (Amazon RDS)](https://aws.amazon.com/rds)—a collection of cloud database services.

Use the Amazon RDS integration to collect metrics related to your Amazon databases. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference the metrics when troubleshooting an issue.

For example, you could use this integration to track the latency and throughput on your databases. Then create an alert that posts a message in Slack if your write latency spikes.

## Data streams

The Amazon RDS integration collects one type of data: metrics.

**Metrics** give you insight into the state of Amazon RDS.
Metrics collected by the Amazon RDS integration include database dimensions, the lag between database instances, and more. See more details in the [Metrics reference](#metrics-reference).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Before using any AWS integration you will need:

* **AWS Credentials** to connect with your AWS account.
* **AWS Permissions** to make sure the user you're using to connect has permission to share the relevant data.

For more details about these requirements, see the **AWS** integration documentation.

## Setup

Use this integration if you only need to collect data from the Amazon RDS service.

If you want to collect data from two or more AWS services, consider using the **AWS** integration.
When you configure the AWS integration, you can collect data from as many AWS services as you'd like.

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Metrics reference

{{event "rds"}}

{{fields "rds"}}