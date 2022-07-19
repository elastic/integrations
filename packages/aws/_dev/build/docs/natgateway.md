# natgateway

The natgateway integration allows you to monitor [NAT gateways](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-nat-gateway.html) on Amazon Virtual Private Cloud. 

A NAT gateway enables cloud resources without public IP addresses (for example, EC2 instances) to have outbound access to the internet, in a way that doesn't expose them to inbound internet connections. It replaces the source IP address of the instances with the IP address of the NAT gateway.

Amazon Virtual Private Cloud also supports private NAT gateways. In this situation, the NAT gateways allows instances in private subnets to connect to other Amazon Virtual Private Clouds or to your on-premises network.

Use the natgateway integration to to collect metrics related to your NAT gateways. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference metrics when troubleshooting an issue.

For example, you could use this data to view the total number of concurrent active TCP connections through the NAT gateway. Then you can alert the relevant project manager about those connections by email.

## Data streams

The natgateway integration collects one type of data streams: metrics.

**Metrics** give you insight into the state of the NAT gateway.
Metric data streams collected by the natgateway integration include the number of connection attempts made through the NAT gateway, the total number of concurrent active TCP connections through the NAT gateway, the number of times the NAT gateway could not allocate a source port, and more. See more details in the [Metrics reference](#metrics-reference).

<!-- etc. -->

<!-- Optional notes -->
## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

 Before using any AWS integration you will need:

 * **AWS Credentials** to connect with your AWS account.
 * **AWS Permissions** to make sure the user you're using to connect has permission to share the relevant data.

 For more details about these requirements, see the **AWS** integration documentation.

<!-- Other requirements -->

## Setup

<!-- Any prerequisite instructions -->

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

Use this integration if you only need to collect data from the NAT gateway service.

 If you want to collect data from two or more AWS services, consider using the **AWS** integration.
 When you configure the AWS integration, you can collect data from as many AWS services as you'd like.

## Metrics reference 

{{event "natgateway"}}

{{fields "natgateway"}}