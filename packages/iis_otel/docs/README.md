# IIS metrics for OpenTelemetry Collector

The IIS metrics from IIS OTel receiver allow you to monitor [Internet Information Services (IIS) for Windows® Server](https://www.iis.net), a flexible, secure and manageable Web server for hosting anything on the Web. From media streaming to web applications, IIS's scalable and open architecture is ready to handle the most demanding tasks.

The IIS OpenTelemetry assets provide a visual representation of IIS metrics collected via OpenTelemetry ([IIS receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/iisreceiver)).

## Compatibility

The content pack has been tested with [OpenTelemetry IIS receiver v0.130.0](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.130.0/receiver/iisreceiver/README.md) and Windows 10 Pro N.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Setup

1. Install and configure the EDOT Collector or upstream OTel Collector to export metrics to ElasticSearch, as shown in the following example:

```yaml
receivers:
  iis:
    collection_interval: 10s
    initial_delay: 1s
exporters:
  debug:
    verbosity: detailed
  elasticsearch/otel:
    endpoints: https://elasticsearch:9200
    user: <userid>
    password: <pwd>
    mapping:
      mode: otel
    metrics_dynamic_index:
      enabled: true
service:
  pipelines:
    metrics:
      exporters: [debug, elasticsearch/otel]
      receivers: [iis]
```

Use this configuration to run the collector.

## Metrics reference

### IIS metrics

Please refer to [the documentation of the OpenTelemetry's IIS receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/iisreceiver/documentation.md).

The following IIS receiver metrics are used in the dashboard:

| Field | Description | Type | Metric Type |
|---|---|---|---|
| iis.connection.active | Number of active connections. | long | gauge |
| iis.connection.anonymous | Total number of connections established anonymously. | long | counter |
| iis.connection.attempt.count | Total number of attempts to connect to the server. | long | counter |
| iis.network.blocked | Number of bytes blocked due to bandwidth throttling. | long | counter |
| iis.network.file.count | Number of transmitted files. | long | counter |
| iis.network.io | Total amount of bytes sent and received. | long | counter |
| iis.request.count | Total number of requests of a given type. | long | counter |
| iis.request.queue.age.max | Age of oldest request in the queue. | long | gauge |
| iis.request.queue.count | Current number of requests in the queue. | long | gauge |
| iis.request.rejected | Total number of requests rejected. | long | counter |
| iis.thread.active | Current number of active threads. | long | gauge |
| iis.uptime | The amount of time the server has been up. | long | gauge |

Resource attribute `iis.site` can be used to filter data by site.
