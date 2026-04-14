# OTel Collector tailsamplingprocessor Integration for Elastic

## Overview
This package contains dashboards that visualize the internal metrics from the tailsampling processor OpenTelemetry collector component.

### Compatibility

The OTel collector dashboards are compatible with the metrics defined [here in the OpenTelemetry collector contrib documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/processor/tailsamplingprocessor/documentation.md).

### How it works

The dashboards rely on field names defined in above documentation.


## What do I need to use this integration?

You need to follow [the documentation](https://opentelemetry.io/docs/collector/internal-telemetry/) of the OpenTelemetry collector to setup and send internal telemetry to your cluster.

The most important prerequisite is to define the `telemetry` section under `service`:

```
service:
  telemetry:
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