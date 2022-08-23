# AWS VPN

The AWS VPN integration allows you to monitor your [AWS Virtual Private Network solutions](https://aws.amazon.com/vpn/).

Use the AWS VPN integration to collect metrics related to your AWS-hosted VPNs. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference metrics when troubleshooting an issue.

You could use this data to view the state of each secure VPN tunnel that you have. For example: static VPNs can have a state of DOWN or UP. Then you can alert the relevant project manager to any significant changes by email.

## Data streams

The AWS VPN integration collects one type of data: metrics.

**Metrics** give you insight into the state of your AWS-hosted VPNs.
Metrics collected by the Amazon VPN integration include the unique host ID, the host IP addresses, the name of the domain of which the host is a member, and more. See more details in the [Metrics reference](#metrics-reference).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Before using any AWS integration you will need:

* **AWS Credentials** to connect with your AWS account.
* **AWS Permissions** to make sure the user you're using to connect has permission to share the relevant data.

For more details about these requirements, see the **AWS** integration documentation.

## Setup

Use this integration if you only need to collect VPN data from AWS.

If you want to collect data from two or more AWS services, consider using the **AWS** integration.
When you configure the AWS integration, you can collect data from as many AWS services as you'd like.

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Metrics reference

{{event "vpn"}}

{{fields "vpn"}}