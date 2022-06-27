# AWS Billing

## Overview

The AWS Billing integration allows you to monitor your [AWS costs](https://aws.amazon.com/aws-cost-management/aws-billing/).

Use the AWS Billing Console integration to collect and parse logs related to your monthly AWS bills. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference logs when troubleshooting an issue.

For example, you could use this data to view your your monthly chargeable costs for each AWS account you have. Then you can alert the relevant budget holder about those costs by email.

## Data streams

The AWS Billing Console integration collects one type of data: logs.

**Logs** help you keep a record of events happening in Billing.
Log data streams collected by the AWS Billing Console integration include your monthly chargeable costs, along with details of your AWS services and purchases made through AWS Marketplace, and more. See more details in the [Logs](#logs-reference).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

 Before using any AWS integration you will need:

 * **AWS Credentials** to connect with your AWS account.
 * **AWS Permissions** to make sure the user you're using to connect has permission to share the relevant data.

 For more details about these requirements, see the **AWS** integration documentation.

## Setup

Use this integration if you only need to collect data from the AWS Billing service.

If you want to collect data from two or more AWS services, consider using the **AWS** integration. When you configure the AWS integration, you can collect data from as many AWS services as you'd like.

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Logs reference

The `billing` data stream collects standard logs (also called access logs) from AWS Billing. Billing standard logs provide detailed records about every request that’s made to the AWS Billing console.

{{event "billing"}}

{{fields "billing"}}
