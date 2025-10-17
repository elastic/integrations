# AWS ELB Access Logs OpenTelemetry Assets

The AWS ELB Access Logs OpenTelemetry Assets allow you to collect and monitor ELB access logs. ELB access logs provides a visual representation of ELB traffic and request data, enabling you to monitor performance, security, and troubleshoot issues in real time.

The EDOT Cloud Forwarder for AWS enables you to collect **Application Load Balancer (ALB)**, **Network Load Balancer (NLB)** and **Classic Load Balancer** access logs from Amazon S3 and forward them directly into Elastic Observability (serverless).

## What do I need to use this integration?

You need an Elastic Observability project (**Serverless only**) for storing, analyzing, and visualizing your ELB logs.

From the AWS side, to collect ELB access logs, you need:

- An S3 bucket for storing the logs
- A load balancer configured to export access logs to the S3 bucket. Check the [official AWS docs](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/enable-access-logging.html) on how to export access logs

## Compatibility

The EDOT Cloud Forwarder for AWS supports collecting logs from:

* Application Load Balancers
* Network Load Balancers
* Classic Load Balancers

For the full documentation on how to set up the EDOT Cloud Forwarder, follow this link: [EDOT Cloud Forwarder for AWS](https://www.elastic.co/docs/reference/opentelemetry/edot-cloud-forwarder/aws).

## Logs reference

### AWS ELB access logs

AWS ELB access logs provide detailed information about requests sent to your load balancer, including:

* Client IP address
* Target IP address
* Request processing times
* HTTP method, URL, and protocol
* Target status code
* Bytes received/sent

Please refer to [the Elastic AWS extension docs](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/extension/encoding/awslogsencodingextension#elb-access-log-fields) for details on log format and fields.