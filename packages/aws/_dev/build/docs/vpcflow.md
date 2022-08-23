# AWS VPC Flow

The AWS VPC Flow integration allows you to monitor [Amazon Virtual Private Cloud (Amazon VPC)](https://aws.amazon.com/vpc/) flow logs. Flow logs capture information about the IP traffic going to and from network interfaces in a VPC.

Use the AWS VPC Flow integration to collect logs related to your Amazon VPCs. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference logs when troubleshooting an issue.

For example, you could use this data to:

* Diagnose overly restrictive security group rules
* Monitor the traffic that is reaching your instance
* Determine the direction of the traffic to and from the network interfaces

Then you can alert the relevant project manager about those events by email.

## Data streams

The AWS VPC Flow integration collects one type of data: logs.

**Logs** help you keep a record of events happening in your VPCs.
Logs collected by the vpcflow integration include the packet-level (original) source and destination IP addresses for the traffic, accepted traffic, rejected traffic, and more. See more details in the [Logs reference](#logs-reference).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Before using any AWS integration you will need:

* **AWS Credentials** to connect with your AWS account.
* **AWS Permissions** to make sure the user you're using to connect has permission to share the relevant data.

For more details about these requirements, see the **AWS** integration documentation.

## Setup

Use this integration if you only need to collect IP traffic data for your VPCs.

If you want to collect data from two or more AWS services, consider using the **AWS** integration.
When you configure the AWS integration, you can collect data from as many AWS services as you'd like.

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

For more information on implementation, see the Amazon documentation on:

* [Default Flow Log Format](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
* [Custom Format with Traffic Through a NAT Gateway](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-records-examples.html)
* [Custom Format with Traffic Through a Transit Gateway](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-records-examples.html)

This integration supports various plain text VPC flow log formats:

* The default pattern of 14 version 2 fields
* A custom pattern including all 29 fields, version 2 though 5:

```
${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status} ${vpc-id} ${subnet-id} ${instance-id} ${tcp-flags} ${type} ${pkt-srcaddr} ${pkt-dstaddr} ${region} ${az-id} ${sublocation-type} ${sublocation-id} ${pkt-src-aws-service} ${pkt-dst-aws-service} ${flow-direction} ${traffic-path}
```

## Logs reference

> Note: The Parquet format is not supported.

{{fields "vpcflow"}}

{{event "vpcflow"}}
