# Amazon VPN

The Amazon VPN integration allows you to monitor the Virtual Private Network (VPN) solutions you have hosted by AWS. AWS VPN comprises both AWS Site-to-Site VPN and AWS Client VPN services. 

Use the Amazon VPN integration to collect metrics related to your AWS-hosted VPNs. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference metrics when troubleshooting an issue.

You could use this data to view the state of each secure VPN tunnels you have. For example: static VPNs can have a state of DOWN or UP. Then you can alert the relevant project manager to any significant changes by email.

## Data streams

The Amazon VPN integration collects one type of data stream: metrics.

**Metrics** give you insight into the state of your AWS-hosted VPNs.
Metric data streams collected by the Amazon VPN integration include the unique host ID, the host IP addresses, the name of the domain of which the host is a member, and more. See more details in the [Metrics reference](#metrics-reference).

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

 Use this integration if you only need to collect VPN data from AWS.

 If you want to collect data from two or more AWS services, consider using the **AWS** integration.
 When you configure the AWS integration, you can collect data from as many AWS services as you'd like.

## Metrics reference

{{event "vpn"}}

{{fields "vpn"}}
