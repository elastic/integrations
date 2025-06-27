# Docker OpenTelemetry Semantic Conventions

This directory contains semantic conventions registry files for Docker container monitoring using OpenTelemetry.

## Files

- `registry.yaml` - Main registry file that imports OpenTelemetry semantic conventions
- `registry_manifest.yaml` - Alternative registry format with imports
- `weaver.yaml` - Weaver configuration file

## Design Approach

Instead of redefining semantic conventions that already exist in OpenTelemetry, this registry imports the official semantic conventions from:
- `https://opentelemetry.io/otelcol/semconv/v1.29.0`

This ensures compatibility and avoids duplication while only defining what's specific to our Docker integration.

## Imported Semantic Conventions

### From OpenTelemetry Resource Conventions
- `container.id` - Unique container identifier  
- `container.name` - Human-readable container name
- `container.hostname` - Container hostname
- `container.image.name` - Container image name with optional registry and tag
- `container.runtime` - Container runtime (e.g., docker, containerd)

### From OpenTelemetry Container Metrics Conventions
- Container CPU metrics
- Container memory metrics  
- Container block I/O metrics
- Container network I/O metrics

## Docker Integration Group

The `docker_otel_integration` group defines:
- Required and recommended attributes for Docker monitoring
- Requirement levels for each attribute
- Integration-specific documentation

## Usage with Weaver

These files are designed to be used with the OpenTelemetry Weaver tool for generating documentation, validation, and code artifacts.

Example weaver command:

```bash
weaver registry generate --registry=model/registry.yaml --output=generated/
```

## Compatibility

These semantic conventions are based on:
- OpenTelemetry Semantic Conventions v1.29.0
- Official OpenTelemetry container resource and metric conventions
- Docker container runtime monitoring patterns
