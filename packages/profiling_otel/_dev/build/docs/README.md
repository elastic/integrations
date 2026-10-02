{{- generatedHeader }}
{{/*
This template can be used as a starting point for writing documentation for your new integration. For each section, fill in the details
described in the comments.

Find more detailed documentation guidelines in https://www.elastic.co/docs/extend/integrations/documentation-guidelines
*/}}
# OpenTelemetry Profiling Integration for Elastic

## Overview

The OpenTelemetry Profiling integration collects continuous profiling data using eBPF on Linux systems. It provides insights into CPU usage without requiring code instrumentation or application restarts. This integration facilitates the OpenTelemetry eBPF profiling receiver and enables deep visibility into your applications runtime characteristics.

### Compatibility

This integration is supported on Linux systems with amd64 or arm64 architecture. It requires a minimum kernel version of 5.10 with eBPF support enabled. The host must have appropriate capabilities.

## Prerequisites

Before installing this integration, ensure:

- **Linux kernel 5.10 or later** with eBPF support enabled
- **Appropriate permissions**
- **Elastic Agent 9.4.0 or later** with OpenTelemetry support
- **amd64 or arm64 architecture**


## What data does this integration collect?

The OpenTelemetry Profiling integration collects the following profiling data:

- **CPU profiling**: Stack traces of CPU-bound functions with sampling frequency control

### Supported use cases

- **Performance optimization**: Identify performance bottlenecks and hotspots in your applications
- **Resource monitoring**: Track CPU and memory usage across your infrastructure
- **Continuous observability**: Maintain always-on profiling for production environments with minimal overhead
- **Root cause analysis**: Understand application behavior during incidents and errors
- **Capacity planning**: Analyze resource consumption trends over time

## Run the profiling receiver with a standalone EDOT Collector

As an alternative to running this integration through Fleet, you can run the profiling receiver directly with the [Elastic Distribution of OpenTelemetry (EDOT) Collector](https://www.elastic.co/docs/reference/edot-collector) and send the profiles to Elasticsearch using the Elasticsearch exporter.

Before you start, make sure that [Universal Profiling](https://www.elastic.co/docs/solutions/observability/infra-and-hosts/get-started-with-universal-profiling#profiling-configure-data-ingestion) is configured for ingestion in your Elasticsearch cluster.

Save the following configuration as `otel.yml`, replacing `<ELASTICSEARCH_ENDPOINT>` with your Elasticsearch URL (for example, `https://my-deployment.es.us-central1.gcp.cloud.es.io:443`) and `<ELASTICSEARCH_API_KEY>` with an encoded Elasticsearch API key:

```yaml
receivers:
  profiling:
    # Optional: sampling frequency, equivalent to the integration's
    # "samples_per_second" setting.
    samples_per_second: 19

exporters:
  elasticsearch:
    endpoint: <ELASTICSEARCH_ENDPOINT>
    api_key: <ELASTICSEARCH_API_KEY>
    # Profiles are only supported in the OTel mapping mode.
    mapping:
      mode: otel

service:
  pipelines:
    profiles:
      receivers: [ profiling ]
      exporters: [ elasticsearch ]
```

Profiles support in the Collector is protected by a feature gate. Start the EDOT Collector with the `service.profilesSupport` feature gate enabled and with elevated privileges (for example, root or `CAP_SYS_ADMIN`), which the eBPF profiler requires.

For more details, refer to [Configure profiles collection](https://www.elastic.co/docs/reference/edot-collector/config/configure-profiles-collection) in the EDOT Collector documentation.
