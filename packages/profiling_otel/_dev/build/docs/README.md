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
