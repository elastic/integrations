# OTLP Receiver OpenTelemetry Input Package

## Overview

The OTLP Receiver OpenTelemetry Input Package enables Elastic Agent to receive logs, metrics, and traces using the [OpenTelemetry Protocol (OTLP)](https://opentelemetry.io/docs/specs/otlp/) over gRPC and HTTP. This allows Elastic Agent to function as a managed OpenTelemetry Collector, accepting telemetry from any OTLP-compatible SDK or collector.

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
| Traces   | Enabled  | Distributed traces and spans                     |

## Configuration

For a complete list of configurations refer to the [OTLP Receiver documentation](https://github.com/open-telemetry/opentelemetry-collector/tree/main/receiver/otlpreceiver).

## Sample event

An example event looks as following:

```json
{
    "@timestamp": "2026-04-29T08:15:50.031Z",
    "agent": {
        "name": "otlp",
        "version": "unknown"
    },
    "attributes": {
        "event": {
            "outcome": "success",
            "success_count": 1
        },
        "processor": {
            "event": "transaction"
        },
        "timestamp": {
            "us": 1777450550031642
        },
        "transaction": {
            "duration": {
                "us": 8
            },
            "id": "aa1541e794f13aac",
            "name": "span-0",
            "representative_count": 1,
            "result": "Success",
            "root": true,
            "sampled": true,
            "type": "unknown"
        }
    },
    "data_stream": {
        "dataset": "generic.otel",
        "namespace": "22675",
        "type": "traces"
    },
    "duration": 8334,
    "event": {
        "agent_id_status": "missing",
        "dataset": "generic.otel",
        "ingested": "2026-04-29T08:16:00Z",
        "outcome": "success",
        "success_count": 1
    },
    "host": {
        "name": "elastic-agent-22408",
        "os": {
            "platform": "linux"
        }
    },
    "kind": "Internal",
    "name": "span-0",
    "os": {
        "type": "linux"
    },
    "processor": {
        "event": "transaction"
    },
    "resource": {
        "attributes": {
            "agent": {
                "name": "otlp",
                "version": "unknown"
            },
            "host": {
                "name": "elastic-agent-22408"
            },
            "os": {
                "type": "linux"
            },
            "service": {
                "instance": {
                    "id": "elastic-agent-22408"
                },
                "name": "generator"
            }
        },
        "schema_url": "https://opentelemetry.io/schemas/1.40.0"
    },
    "scope": {
        "attributes": {
            "service": {
                "framework": {
                    "name": "generator",
                    "version": ""
                }
            }
        },
        "name": "generator"
    },
    "service": {
        "framework": {
            "name": "generator",
            "version": ""
        },
        "instance": {
            "id": "elastic-agent-22408"
        },
        "name": "generator",
        "node": {
            "name": "elastic-agent-22408"
        }
    },
    "span": {
        "id": "aa1541e794f13aac",
        "name": "span-0"
    },
    "span_id": "aa1541e794f13aac",
    "timestamp": {
        "us": 1777450550031642
    },
    "trace": {
        "id": "3e8478e6b5cb7b2a52649ae2c37eae10"
    },
    "trace_id": "3e8478e6b5cb7b2a52649ae2c37eae10",
    "transaction": {
        "duration": {
            "us": 8
        },
        "id": "aa1541e794f13aac",
        "name": "span-0",
        "representative_count": 1,
        "result": "Success",
        "root": true,
        "sampled": true,
        "type": "unknown"
    }
}
```
