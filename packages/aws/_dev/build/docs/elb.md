# Amazon ELB

The Amazon ELB integration allows you to monitor [Amazon Elastic Load Balancing (ELB)](https://aws.amazon.com/elasticloadbalancing/)—a tool that distributes application traffic to multiple targets.

Use the Amazon ELB integration to collect logs and metrics with detailed information about requests sent to the load
balancer. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference those logs and metrics when troubleshooting an issue.

For example, you could use this data to analyze traffic patterns, view healthy and unhealthy hosts, and track connection and backend errors.

## Data streams

The Amazon ELB integration collects two types of data: logs and metrics.

**Logs** help you keep a record of events happening in Amazon ELB.
Logs collected by the Amazon ELB integration include the time a request was received, the client's IP address, latencies, request paths, server responses, and more. See more details in the [Logs reference](#logs-reference).

**Metrics** give you insight into the state of Amazon ELB.
Metrics collected by the Amazon ELB integration include the host name, IP address, average latency, and more. See more details in the [Metrics reference](#metrics-reference).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Before using any AWS integration you will need:

* **AWS Credentials** to connect with your AWS account.
* **AWS Permissions** to make sure the user you're using to connect has permission to share the relevant data.

For more details about these requirements, see the **AWS** integration documentation.

## Setup

Use this integration if you only need to collect data from the Amazon ELB service.

If you want to collect data from two or more AWS services, consider using the **AWS** integration.
When you configure the AWS integration, you can collect data from as many AWS services as you'd like.

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

To send classic ELB access logs to an S3 bucket, see [enable access logs for classic load balancer](https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/enable-access-logs.html).

For an application load balancer, see [enable access log for application load balancer](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html#enable-access-logging).

For a network load balancer, see [enable access log for network load balancer](https://docs.aws.amazon.com/elasticloadbalancing/latest//network/load-balancer-access-logs.html).

## Logs reference

The `elb` dataset collects logs from AWS ELBs.

{{fields "elb_logs"}}

{{event "elb_logs"}}

## Metrics reference

{{event "elb_metrics"}}

{{fields "elb_metrics"}}