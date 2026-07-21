# OpenTelemetry internal telemetry Assets

## Overview

This package contains dashboards that visualize the internal metrics from OpenTelemetry components.

### Compatibility

The OTel collector dashboards are compatible with the metrics defined [here in the OpenTelemetry collector documentation](https://opentelemetry.io/docs/collector/internal-telemetry/). The oldest tested version of the OpenTelemetry Collector in combination with this package is v1.44.0.

Furthermore, the package also contains dashboards to visualize metrics from the `tailsamplingprocessor`. Those metrics are documented [here](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/processor/tailsamplingprocessor/documentation.md).

The dashboards query metrics from the `collectortelemetry` dataset. Set the resource attribute `data_stream.dataset` to `collectortelemetry` on the collector that emits internal telemetry (see below).

**Note**: The dashboards expect metrics without postfixes. In particular, Prometheus-format metrics—which apply unit suffixes by default—are not supported. The dashboards are designed for metrics exported via OTLP. If you use the Prometheus exporter, set `without_type_suffix` and `without_units` to `true`. For more information, see [the upstream documentation](https://opentelemetry.io/docs/collector/internal-telemetry/#metric-views).

### How it works

The dashboards rely on field names defined in above documentations.

## What do I need to use this integration?

You need to follow [the documentation](https://opentelemetry.io/docs/collector/internal-telemetry/) of the OpenTelemetry collector to setup and send internal telemetry to your cluster.

The most important prerequisite is to define the `telemetry` section under `service` and to set `data_stream.dataset` to `collectortelemetry`. 

```
service:
  telemetry:
    resource:
      data_stream.dataset: 'collectortelemetry'
    metrics:
      readers:
        - periodic:
            exporter:
              otlp:
                protocol: http/protobuf
                endpoint: https://backend:4318
```

With this, you'll have internal telemetry on `normal` verbosity level.

The above configuration defines an OTLP endpoint that sends internal telemetry to a target collector over an OTLP connection. This target collector then exports the internal telemetry data to Elasticsearch using the `elasticsearch` exporter. The integration subsequently reads this internal telemetry data from Elasticsearch.

For all the other config, refer to the upstream documentation.