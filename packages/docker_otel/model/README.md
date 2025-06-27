# Docker OpenTelemetry Semantic Conventions

This directory contains semantic conventions registry files for Docker container monitoring using OpenTelemetry.

## Files

- `registry.yaml` - Main registry file that includes all semantic conventions
- `registry_manifest.yaml` - Comprehensive manifest with all groups in a single file
- `container-resource.yaml` - Container resource attributes semantic conventions
- `container-metrics.yaml` - Container metrics semantic conventions

## Semantic Conventions Covered

### Resource Attributes

These attributes identify and describe the container:

- `container.id` - Unique container identifier
- `container.name` - Human-readable container name
- `container.hostname` - Container hostname
- `container.image.name` - Container image name with optional registry and tag
- `container.runtime` - Container runtime (e.g., docker, containerd)

### Metrics

#### CPU Metrics

- `container.cpu.utilization` - CPU usage percentage (0.0-1.0)
- `container.cpu.usage.usermode` - CPU time in user mode (nanoseconds)
- `container.cpu.usage.kernelmode` - CPU time in kernel mode (nanoseconds)

#### Memory Metrics

- `container.memory.percent` - Memory usage percentage (0.0-1.0)
- `container.memory.usage.total` - Total memory used (bytes)
- `container.memory.usage.limit` - Memory limit (bytes)

#### Block I/O Metrics

- `container.blockio.io_service_bytes_recursive` - Total bytes transferred to/from block devices

#### Network I/O Metrics

- `container.network.io.usage.rx_bytes` - Bytes received
- `container.network.io.usage.tx_bytes` - Bytes transmitted

### Attributes

Additional attributes used with metrics:

- `device_major` - Major device number for block devices
- `interface` - Network interface name

## Usage with Weaver

These files are designed to be used with the OpenTelemetry Weaver tool for generating documentation, validation, and code artifacts.

Example weaver command:

```bash
weaver registry generate --registry=model/registry.yaml --output=generated/
```

## Compatibility

These semantic conventions are based on:

- OpenTelemetry Semantic Conventions v1.29.0
- Docker container runtime metrics
- Standard system resource monitoring patterns
