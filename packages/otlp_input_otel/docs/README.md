# OTLP Receiver OpenTelemetry Input Package

## Overview

The OTLP Receiver OpenTelemetry Input Package enables Elastic Agent to receive logs, metrics, traces, and profiling data via the [OpenTelemetry Protocol (OTLP)](https://opentelemetry.io/docs/specs/otlp/) over gRPC and HTTP. This allows Elastic Agent to function as a managed OpenTelemetry Collector, accepting telemetry from any OTLP-compatible SDK or collector.

The package uses the upstream [OTLP Receiver](https://github.com/open-telemetry/opentelemetry-collector/tree/main/receiver/otlpreceiver) from the OpenTelemetry Collector.

## How it works

This package configures the OTLP receiver in the EDOT (Elastic Distribution of OpenTelemetry) Collector managed by Elastic Agent. The receiver listens for incoming OTLP data on two endpoints:

- **gRPC** on `0.0.0.0:4317` (default)
- **HTTP** on `0.0.0.0:4318` (default)

Incoming telemetry is processed and forwarded to Elasticsearch for indexing and analysis.

When trace acceptance is enabled, the `elasticapm` processor enriches trace data with additional attributes for Elastic Observability UIs. Optionally, the `elasticapm` connector generates pre-aggregated APM metrics from trace data.

## Supported signal types

| Signal   | Default  | Description                                      |
|----------|----------|--------------------------------------------------|
| Logs     | Enabled  | Log records from applications and infrastructure |
| Metrics  | Enabled  | Metric data points and time series               |
| Traces   | Enabled  | Distributed traces and spans                     |
| Profiles | Enabled  | Profiling data (hidden until generally available) |

## Configuration

### Endpoints

| Setting          | Default          | Description                         |
|------------------|------------------|-------------------------------------|
| gRPC Endpoint    | `0.0.0.0:4317`  | Address and port for gRPC traffic   |
| HTTP Endpoint    | `0.0.0.0:4318`  | Address and port for HTTP traffic   |

Default listen addresses bind to all interfaces since the default configuration includes authentication requirements.

### Authentication

Authentication follows the [OpenTelemetry configauth Server Authenticators](https://github.com/open-telemetry/opentelemetry-collector/blob/main/config/configauth/README.md). One of the following may be enabled at a time:

| Setting                          | Default    | Description                                                      |
|----------------------------------|------------|------------------------------------------------------------------|
| Enable Basic Auth                | `false`    | Require Basic Auth (username/password via htpasswd) for requests |
| Basic Auth htpasswd File         | (none)     | Path to htpasswd file for validation                             |
| Basic Auth htpasswd Inline       | (none)     | Inline htpasswd content (e.g. from `htpasswd -nb user pass`)      |
| Enable Bearer Token Auth         | `false`    | Require bearer token for incoming OTLP requests                  |
| Bearer Token                     | (none)     | The token value to validate against                              |
| Bearer Token File                | (none)     | Path to file containing bearer token(s)                          |
| Enable OIDC Auth                 | `false`    | Require OIDC-based authentication                               |
| OIDC Issuer URL                  | (none)     | Base URL for the OIDC provider                                   |
| OIDC Audience                    | (none)     | Audience of the token for verification                           |

### APM processing

| Setting                          | Default | Description                                                  |
|----------------------------------|---------|--------------------------------------------------------------|
| Produce Aggregated APM Metrics   | `true`  | Generate pre-aggregated APM metrics from trace data          |

The `elasticapm` processor is always active when traces are accepted, enriching trace data for Elastic Observability.

### TLS

TLS can be configured for both gRPC and HTTP endpoints by providing certificate, key, and optional CA files.

| Setting              | Default | Description                                              |
|----------------------|---------|----------------------------------------------------------|
| TLS Certificate File | (none)  | Path to the TLS certificate file                         |
| TLS Key File         | (none)  | Path to the TLS private key file                         |
| TLS CA File          | (none)  | Path to the CA certificate file for client verification  |

For the full list of upstream configuration options, refer to the [OTLP Receiver documentation](https://github.com/open-telemetry/opentelemetry-collector/tree/main/receiver/otlpreceiver).
