# OpenTelemetry internal telemetry Assets

## Overview

This package contains dashboards that visualize the internal metrics from OpenTelemetry components.

### Compatibility

The OTel collector dashboards are compatible with the metrics defined [here in the OpenTelemetry collector documentation](https://opentelemetry.io/docs/collector/internal-telemetry/). The oldest tested version of the OpenTelemetry Collector in combination with this package is v1.44.0.

### How it works

The dashboards rely on field names defined in above documentation.

## What do I need to use this integration?

You need to follow [the documentation](https://opentelemetry.io/docs/collector/internal-telemetry/) of the OpenTelemetry collector to setup and send internal telemetry to your cluster.

An most important prerequisite is to define the `telemetry` section under `service`:

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

For all the other config, refer to the upstream documentation.