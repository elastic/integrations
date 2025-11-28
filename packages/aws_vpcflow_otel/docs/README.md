# AWS VPC Flow Logs OpenTelemetry Assets

This package contains Kibana assets for monitoring [Amazon Virtual Private Cloud (Amazon VPC) flow logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html).

## Supported data sources

### EDOT Cloud Forwarder (ECF) for AWS

ECF is the simplest way to configure AWS ELB log collection. Consult the documentation [here](https://www.elastic.co/docs/reference/opentelemetry/edot-cloud-forwarder/aws) for full setup instructions.

### Standalone OTel Collector

Any OTel-supported collection method is supported provided the required extension is included. A sample configuration which uses the [awss3receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/awss3receiver#aws-s3-receiver) and [awslogsencodingextension](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/extension/encoding/awslogsencodingextension#aws-logs-encoding-extension) is given below:


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
  elasticsearch/otel:
    endpoints: https://<host>:<port>
    api_key: <api_key>

service:
  extensions: [awslogs_encoding/vpcflow]
  pipelines:
    logs:
      exporters: [elasticsearch/otel]
      receivers: [awss3]
```
