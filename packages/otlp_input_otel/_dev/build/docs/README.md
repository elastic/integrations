# OTLP Receiver OpenTelemetry Input Package

## Overview

The OTLP Receiver OpenTelemetry Input Package enables Elastic Agent to receive logs and metrics via the [OpenTelemetry Protocol (OTLP)](https://opentelemetry.io/docs/specs/otlp/) over gRPC and HTTP. This allows Elastic Agent to function as a managed OpenTelemetry Collector, accepting telemetry from any OTLP-compatible SDK or collector.

The package uses the upstream [OTLP Receiver](https://github.com/open-telemetry/opentelemetry-collector/tree/main/receiver/otlpreceiver) from the OpenTelemetry Collector.

## How it works

This package configures the OTLP receiver in the EDOT (Elastic Distribution of OpenTelemetry) Collector managed by Elastic Agent. The receiver listens for incoming OTLP data on two endpoints:

- **gRPC** on `localhost:4317` (default)
- **HTTP** on `localhost:4318` (default)

Incoming telemetry is processed and forwarded to Elasticsearch for indexing and analysis.

## Supported signal types

| Signal   | Default  | Description                                      |
|----------|----------|--------------------------------------------------|
| Logs     | Enabled  | Log records from applications and infrastructure |
| Metrics  | Enabled  | Metric data points and time series               |
| Traces   | Disabled | Distributed traces (configuration commented out) |
| Profiles | Disabled | Profiling data (configuration commented out)     |

> **Note:** Traces and profiles are defined in the manifest but their pipeline configuration is currently commented out in the input template. When binding to all interfaces (`0.0.0.0`) for production use, consider enabling authentication or TLS.

## Configuration

Configuration maps to the [OTLP Receiver protocols](https://github.com/open-telemetry/opentelemetry-collector/tree/main/receiver/otlpreceiver): `protocols.grpc` and `protocols.http`. Upstream defaults are `localhost:4317` (gRPC) and `localhost:4318` (HTTP).

### Endpoints

| Setting          | Default          | Description                         |
|------------------|------------------|-------------------------------------|
| gRPC Endpoint    | `localhost:4317` | Address and port for gRPC traffic   |
| HTTP Endpoint    | `localhost:4318` | Address and port for HTTP traffic   |

### Signal toggles

| Setting         | Default | Description                     |
|-----------------|---------|---------------------------------|
| Accept Logs     | `true`  | Enable acceptance of log data   |
| Accept Metrics  | `true`  | Enable acceptance of metric data|

### Authentication

Authentication follows the [OpenTelemetry configauth Server Authenticators](https://github.com/open-telemetry/opentelemetry-collector/blob/main/config/configauth/README.md). One of the following may be enabled at a time.

#### Basic Auth (basicauthextension)

| Setting                   | Default | Description                                                      |
|---------------------------|---------|------------------------------------------------------------------|
| Enable Basic Auth         | `false` | Require Basic Auth (username/password via htpasswd) for requests |
| Basic Auth htpasswd File  | (none)  | Path to htpasswd file for validation                             |
| Basic Auth htpasswd Inline| (none)  | Inline htpasswd content (e.g. from `htpasswd -nb user pass`)     |

#### Bearer Token (bearertokenauthextension)

| Setting             | Default       | Description                                              |
|---------------------|---------------|----------------------------------------------------------|
| Enable Bearer Token Auth | `false`   | Require bearer token for incoming OTLP requests          |
| Bearer Token        | (none)        | The token value to validate against                      |
| Bearer Token File   | (none)        | Path to file containing bearer token(s)                  |
| Bearer Token Header | `Authorization`| HTTP header name for the token                           |
| Bearer Token Scheme | `Bearer`      | Auth scheme for the token                                |

#### OIDC (oidcauthextension)

| Setting             | Default | Description                                              |
|---------------------|---------|----------------------------------------------------------|
| Enable OIDC Auth    | `false` | Require OIDC-based authentication                       |
| OIDC Issuer URL     | (none)  | Base URL for the OIDC provider                           |
| OIDC Audience       | (none)  | Audience of the token for verification                   |
| OIDC Ignore Audience| `false` | Skip validating the audience field                       |
| OIDC Issuer CA Path | (none)  | Local path for the issuer CA's TLS server cert           |
| OIDC Username Claim | (none)  | Claim to use as username if token 'sub' is not suitable   |
| OIDC Groups Claim   | (none)  | Claim holding subject's group membership information     |

### TLS

TLS can be configured for both gRPC and HTTP endpoints. Maps to [configtls ServerConfig](https://github.com/open-telemetry/opentelemetry-collector/blob/main/config/configtls/README.md): `cert_file`, `key_file`, and `client_ca_file` (mTLS).

| Setting              | Default | Description                                              |
|----------------------|---------|----------------------------------------------------------|
| TLS Certificate File | (none)  | Path to the TLS certificate file                         |
| TLS Key File         | (none)  | Path to the TLS private key file                         |
| TLS CA File          | (none)  | Path to the CA certificate file for client verification  |

## Upstream reference

For additional configuration options (URL paths per signal, CORS, compression, keepalive, etc.), see:

- [OTLP Receiver](https://github.com/open-telemetry/opentelemetry-collector/tree/main/receiver/otlpreceiver)
- [gRPC settings](https://github.com/open-telemetry/opentelemetry-collector/blob/main/config/configgrpc/README.md)
- [HTTP settings](https://github.com/open-telemetry/opentelemetry-collector/blob/main/config/confighttp/README.md)
- [TLS and mTLS settings](https://github.com/open-telemetry/opentelemetry-collector/blob/main/config/configtls/README.md)
- [Auth settings](https://github.com/open-telemetry/opentelemetry-collector/blob/main/config/configauth/README.md)
