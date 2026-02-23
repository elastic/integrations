# Azure Activity Logs OpenTelemetry Assets

This package contains Kibana assets for monitoring [Azure Activity Logs](https://learn.microsoft.com/azure/azure-monitor/platform/activity-log) collected with OpenTelemetry.

## Supported data sources

### EDOT Cloud Forwarder (ECF) for Azure

ECF is the simplest way to configure Azure Activity Log collection. Refer to the [ECF for Azure documentation](https://www.elastic.co/docs/reference/opentelemetry/edot-cloud-forwarder/azure) for full setup instructions.

### Standalone OTel Collector

Any OTel-supported collection method is supported, provided Azure Activity Logs are collected by a compatible OpenTelemetry pipeline and exported to Elasticsearch.

#### Compatibility

This package has been tested with OpenTelemetry Collector version `0.138.0`. The OpenTelemetry components used are [azurefunctionsreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/azurefunctionsreceiver#azure-functions-receiver), [azureresourcelogsencodingextension](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/extension/encoding/azureresourcelogsencodingextension#azure-resource-logs-encoding-extension), [azureauthextension](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/extension/azureauthextension#azure-auth-extension), and [otlpexporter](https://github.com/open-telemetry/opentelemetry-collector/tree/main/exporter/otlpexporter#otlp-exporter).

#### Sample configuration

```yaml
receivers:
  azurefunctions:
    auth: azureauth
    http:
      endpoint: :${env:FUNCTIONS_CUSTOMHANDLER_PORT:-9090}
    logs:
      encoding: azureresourcelogs_encoding
    metrics:
      decoder: ${env:METRICS_DECODER:-ds}
      settings:
        time_format:
          - "2006-01-02T15:04:05.0000000Z"
    include_invoke_metadata: true

exporters:
  debug:
    verbosity: detailed
  otlp_grpc/elastic:
    endpoint: ${env:ELASTICSEARCH_OTLP_ENDPOINT}
    headers:
      authorization: ApiKey ${env:ELASTICSEARCH_API_KEY}
    sending_queue:
      enabled: ${env:EXPORTER_SENDING_QUEUE_ENABLED:-false}
      # num_consumers: 10
      # queue_size: 5000
      # storage: memory
    retry_on_failure:
      enabled: ${env:EXPORTER_RETRY_ON_FAILURE_ENABLED:-true}
      initial_interval: 5s
      max_interval: 10s # default: 30s
      max_elapsed_time: 30s # default: 5m

extensions:
  azureresourcelogs_encoding:
    destination: event_hub
  azureauth:
    managed_identity: {}

service:
  extensions: [azureresourcelogs_encoding, azureauth]
  pipelines:
    logs:
      receivers: [azurefunctions]
      # PIPELINE_EXPORTERS env; in Azure set by Bicep param pipelineExporters (infra/ecf.bicep) -> app setting.
      exporters: ["${env:PIPELINE_EXPORTERS:-otlp_grpc/elastic}"]
```
