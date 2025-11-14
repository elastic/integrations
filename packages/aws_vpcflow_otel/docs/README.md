# AWS VPC Flow Logs OpenTelemetry Assets

## Overview

The AWS VPC Flow OpenTelemetry Assets allow you to monitor Amazon Virtual Private Cloud (Amazon VPC) flow logs. Flow logs capture information about the IP traffic going to and from network interfaces in a VPC.

The [EDOT Cloud Forwarder for AWS](https://www.elastic.co/docs/reference/opentelemetry/edot-cloud-forwarder/aws) enables you to collect **VPC Flow Logs** from Amazon S3 and forward them directly into Elastic Observability. Use this integration to visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference logs when troubleshooting an issue.

## What do I need to use this integration?

You need an Elastic Observability project (**Serverless only**) for storing, analyzing, and visualizing your ELB logs.

From the AWS side, to collect VPC Flow logs, you need:

- A Virtual Private Cloud (VPC)
- An S3 bucket for storing flow logs
- A flow log configured with the S3 bucket as the destination

## How do I deploy this integration?

For step-by-step instructions on how to set up an EDOT Cloud Forwarder for AWS, see the
[EDOT Cloud Forwarder for AWS](https://www.elastic.co/docs/reference/opentelemetry/edot-cloud-forwarder/aws) guide.

## Alternative setup using [AWS S3 receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/awss3receiver)

The alternative setup allows you to bypass the "Serverless only" limitation.

### Prerequisites

- A Virtual Private Cloud (VPC)
- An S3 bucket for storing flow logs
- A flow log configured with the S3 bucket as the destination
- An SQS queue receiving notifications on object creation in the S3 bucket
- `awss3receiver` and `awslogsencodingextension`

### Configuration example

For details on configuration refer to the following documentation: [awss3receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/awss3receiver#aws-s3-receiver), [awslogsencodingextension](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/extension/encoding/awslogsencodingextension#aws-logs-encoding-extension), [elasticsearchexporter](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/exporter/elasticsearchexporter#configuration-options)

```yaml
extensions:
  awslogs_encoding/vpcflow:
    format: vpcflow
    vpcflow:
      file_format: plain-text

receivers:
  awss3:
    sqs:
      queue_url: "<sqs-url>"
      region: "<region>"
    s3downloader:
      region: "<region>"
      s3_bucket: '<bucket_name>'
      s3_prefix: 'AWSLogs/<account-id>'
    encodings:
      - extension: awslogs_encoding/vpcflow

exporters:
  debug:
    verbosity: detailed
  elasticsearch/otel:
    endpoints: https://<host>:<port>
    user: elastic
    password: <password>
    mapping:
      mode: otel
    metrics_dynamic_index:
      enabled: true

service:
  extensions: [awslogs_encoding/vpcflow]
  pipelines:
    logs:
      exporters: [debug, elasticsearch/otel]
      receivers: [awss3]
```

## Logs Reference

For a complete list of all available logs and their detailed descriptions, refer to the [OpenTelemetry AWS Logs encoding extension](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/extension/encoding/awslogsencodingextension#vpc-flow-log-record-fields)
