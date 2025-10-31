# AWS CloudTrail Logs OpenTelemetry Assets

## Overview

The AWS CloudTrail OpenTelemetry Assets allow you to monitor [Amazon CloudTrail logs](https://docs.aws.amazon.com/cloudtrail/). With AWS CloudTrail, you can monitor your AWS deployments in the cloud by getting a history of AWS API calls for your account, including API calls made by using the AWS Management Console, the AWS SDKs, the command line tools, and higher-level AWS services.

The [EDOT Cloud Forwarder for AWS](https://www.elastic.co/docs/reference/opentelemetry/edot-cloud-forwarder/aws) enables you to collect **CloudTrail Logs** from Amazon S3 and forward them directly into Elastic Observability. Use this integration to visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference logs when troubleshooting an issue.

## What do I need to use this integration?

You need an Elastic Observability project (**Serverless only**) for storing, analyzing, and visualizing your CloudTrail logs.

From the AWS side, to collect CloudTrail logs, you need:

- An S3 bucket for storing logs
- CloudTrail trail configured with S3 bucket as log storage destination

## How do I deploy this integration?

For step-by-step instructions on how to set up an EDOT Cloud Forwarder for AWS, see the
[EDOT Cloud Forwarder for AWS](https://www.elastic.co/docs/reference/opentelemetry/edot-cloud-forwarder/aws) guide.

## Logs Reference

For a complete list of all available logs and their detailed descriptions, refer to the [OpenTelemetry AWS Logs encoding extension](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/extension/encoding/awslogsencodingextension#cloudtrail-log-record-fields)