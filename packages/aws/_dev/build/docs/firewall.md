# AWS Network Firewall

This integration is used to fetch logs and metrics from [AWS Network Firewall](https://aws.amazon.com/network-firewall/).

The AWS Network Firewall integration allows you to monitor [AWS Network Firewall](https://aws.amazon.com/network-firewall/). AWS Network Firewall is a service for deploying firewalls and other network protection measures to Amazon Virtual Private Clouds.

Use the AWS Network Firewall integration to monitor the traffic entering and passing through the AWS Network Firewall. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference logs and metrics when troubleshooting an issue.

For example, you could use this data to view when a firewall rule was triggered. Then you can alert the relevant person about those triggers by email.

## Data streams

The AWS Network Firewall  integration collects two types of data streams: logs and metrics.

**Logs** help you keep a record of events happening in AWS Network Firewall.
Log data streams collected by the AWS Network Firewall integration include the event timestamp, event type, and more. See more details in the [Logs reference](#logs-reference).

**Metrics** give you insight into the state of Network Firewall.
Metric data streams collected by the AWS Network Firewall integration include the number of packets received, passed, and blocked by the AWS Network Firewall, and more. See more details in the [Metrics reference](#metrics-reference).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

 Before using any AWS integration you will need:

 * **AWS Credentials** to connect with your AWS account.
 * **AWS Permissions** to make sure the user you're using to connect has permission to share the relevant data.

 For more details about these requirements, see the **AWS** integration documentation.

<!-- Other requirements -->

## Setup

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

Use this integration if you only need to collect data from the AWS Network Firewall service.

If you want to collect data from two or more AWS services, consider using the **AWS** integration.
When you configure the AWS integration, you can collect data from as many AWS services as you'd like.

## Logs and Metrics reference

### Logs reference

The `firewall_logs` dataset collects AWS Network Firewall logs. Users can use these logs to
monitor network activity.

{{event "firewall_logs" }}

{{fields "firewall_logs"}}

### Metrics reference

The `firewall_metrics` dataset collects AWS Network Firewall metrics.

{{event "firewall_metrics" }}

{{fields "firewall_metrics"}}
