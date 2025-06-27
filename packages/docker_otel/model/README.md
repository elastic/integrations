# Docker OpenTelemetry Semantic Conventions

This directory contains semantic conventions registry files for Docker container monitoring using OpenTelemetry.

## Files

- `registry_manifest.yaml` - Manifest file defining the registry metadata and dependencies
- `registry.yaml` - Main semantic conventions file with imports from OpenTelemetry
- `weaver.yaml` - Weaver configuration file

## Design Approach

This registry follows the official Weaver pattern with:
1. A `registry_manifest.yaml` defining metadata and dependencies on OpenTelemetry v1.34.0
2. A `registry.yaml` file that imports semantic conventions from the dependency
3. Minimal custom definitions, primarily importing from official OpenTelemetry conventions

## Imported Semantic Conventions

### Container Resource Conventions
- `container.id` - Unique container identifier  
- `container.name` - Human-readable container name
- `container.hostname` - Container hostname
- `container.image.name` - Container image name with optional registry and tag
- `container.runtime` - Container runtime (e.g., docker, containerd)

### Container Metrics Conventions
- Container CPU metrics (utilization, usage)
- Container memory metrics (usage, limits)
- Container block I/O metrics
- Container network I/O metrics

## Usage with Weaver

These files are designed to be used with the OpenTelemetry Weaver tool for generating documentation, validation, and code artifacts.

Example weaver commands:
```bash
# Check registry validity
weaver registry check -r model/

# Generate documentation
weaver registry generate --registry=model/ --output=generated/
```

## Compatibility

These semantic conventions are based on:
- OpenTelemetry Semantic Conventions v1.34.0
- Official OpenTelemetry container resource and metric conventions
- Docker container runtime monitoring patterns
