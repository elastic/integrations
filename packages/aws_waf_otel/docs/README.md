# AWS Web Application Firewall (WAF) Logs OpenTelemetry Assets

## Overview

The AWS WAF OpenTelemetry Assets allow you to monitor [Amazon WAF logs](https://aws.amazon.com/waf/). With AWS WAF, you can protect your web applications from common exploits and monitor detailed logs of each web request inspected, including its action (allow, block, count), source, and matching rules.

The [EDOT Cloud Forwarder for AWS](https://www.elastic.co/docs/reference/opentelemetry/edot-cloud-forwarder/aws) enables you to collect **WAF Logs** from Amazon S3 and forward them directly into Elastic Observability. Use this integration to visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference logs when troubleshooting an issue.

## What do I need to use this integration?

You need an Elastic Observability project (**Serverless only**) for storing, analyzing, and visualizing your WAF logs.

From the AWS side, to collect WAF logs, you need:

- An S3 bucket for storing logs
- AWS WAF logging enabled on your Web ACL to send logs to the S3 bucket

## How do I deploy this integration?

For step-by-step instructions on how to set up an EDOT Cloud Forwarder for AWS, see the
[EDOT Cloud Forwarder for AWS](https://www.elastic.co/docs/reference/opentelemetry/edot-cloud-forwarder/aws) guide.

## Logs Reference

For a complete list of all available logs and their detailed descriptions, refer to:
- [AWS WAF Logging Fields documentation](https://docs.aws.amazon.com/waf/latest/developerguide/logging-fields.html)
- [OpenTelemetry AWS Logs encoding extension](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/extension/encoding/awslogsencodingextension#aws-waf-log-record-fields)