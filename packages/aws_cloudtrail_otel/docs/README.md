# AWS CloudTrail Logs OpenTelemetry Assets

This package contains Kibana assets for monitoring [AWS CloudTrail Logs](https://aws.amazon.com/cloudtrail/).

## Supported data sources

### EDOT Cloud Forwarder (ECF) for AWS

ECF is the simplest way to configure AWS CloudTrail log collection. Refer to the [ECF for AWS documentation](https://www.elastic.co/docs/reference/opentelemetry/edot-cloud-forwarder/aws) for full setup instructions.

### Standalone OTel Collector

Any OTel-supported collection method is supported provided the required extension is included.

#### Compatibility

OpenTelemetry components version tested against is `0.138.0`. Components used are [awss3receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/awss3receiver#aws-s3-receiver), [awslogsencodingextension](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/extension/encoding/awslogsencodingextension#aws-logs-encoding-extension), and [elasticsearchexporter](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/exporter/elasticsearchexporter#elasticsearch-exporter)

#### Sample configuration

```yaml
extensions:
  awslogs_encoding/cloudtrail:
    format: cloudtrail

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
      - extension: awslogs_encoding/cloudtrail

exporters:
  elasticsearch/otel:
    endpoints: https://<host>:<port>
    api_key: <api_key>

service:
  extensions: [awslogs_encoding/cloudtrail]
  pipelines:
    logs:
      exporters: [elasticsearch/otel]
      receivers: [awss3]
```
