# AWS Transit Gateway

The AWS Transit Gateway integration allows you to monitor AWS Transit Gateway. AWS Transit Gateway is a service for connecting Amazon Virtual Private Clouds (VPCs) and on-premises networks.

Use the AWS Transit Gateway integration collect metrics related to traffic routed between VPCs and on-premises networks. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference metrics when troubleshooting an issue.

For example, you could use this data to view the number of packets dropped because they did not match a route. Then you can alert the relevant project manager about those by email.

## Data streams

The AWS Transit Gateway integration collects one type of data stream: metrics.

**Metrics** give you insight into the state of AWS Transit Gateway.
Metric data streams collected by the AWS Transit Gateway integration include the number of bytes sent from the transit gateway, the number of bytes received from the transit gateway, the number of packets dropped because they did not match a route, and more. See more details in the [Metrics reference](#metrics-reference).

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

 Use this integration if you only need to collect data from the AWS Transit Gateway service.

 If you want to collect data from two or more AWS services, consider using the **AWS** integration.
 When you configure the AWS integration, you can collect data from as many AWS services as you'd like.

## Metrics reference

{{event "transitgateway"}}

{{fields "transitgateway"}}
