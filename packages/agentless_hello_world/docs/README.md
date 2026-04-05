# Agentless Hello World

This is a sample integration designed to exercise the Agentless infrastructure. It periodically fetches data from `https://epr.elastic.co` every minute to demonstrate basic agentless functionality.

## Overview

The Agentless Hello World integration is a minimal example that:
- Fetches data from the Elastic Package Registry (EPR) endpoint
- Runs every 1 minute
- Requires no user configuration

It also includes an optional **Mock counter metrics** data stream for generating synthetic metric data at a configurable rate, useful for testing rate limiting and ingestion throughput.

## Configuration

### Generic logs (enabled by default)

This data stream requires no configuration from the user. All settings are pre-configured:
- **Endpoint**: `https://epr.elastic.co`
- **Interval**: 1 minute
- **Deployment mode**: Agentless by default

### Mock counter metrics (disabled by default)

This data stream generates mock counter metrics entirely within the agent. No external endpoint is called. Enable it and configure the following settings:

- **Interval**: Time between each batch of events (default: `1s`)
- **Mode**: Rate pattern, either `Constant` or `Spike` (default: `Constant`)
- **Events per interval**: Number of events to generate per interval (default: `10`). In spike mode this is the baseline rate between spikes.

#### Constant mode

Produces a steady stream of events at the configured rate.

```
events_per_interval: 10, interval: 1s → 10 events/sec, steady
```

#### Spike mode

Same as constant mode, but periodically produces a burst of events. Two additional settings become available under advanced options:

- **Spike events per interval**: Number of events during a spike burst (default: `100`)
- **Spike every N seconds**: How often a spike occurs (default: `60`)

```
events_per_interval: 10, spike_events: 100, spike_every_seconds: 30

 100 |              █                 █
     |              █                 █
  10 |██████████████████████████████████████████
     +--------+--------+--------+--------+------> time
     0s      10s      20s      30s      40s
```

Each event contains a `counter.value` field with an incrementing integer that persists across agent restarts.

## Data Collection

### Generic logs

Makes HTTP GET requests to `https://epr.elastic.co` and stores:
- **status_code**: HTTP Status Code for the response.

### Mock counter metrics

Generates synthetic events containing:
- **counter.value**: An incrementing integer (1, 2, 3, ...).

## Requirements

### Agentless-enabled integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

## Logs

### Generic

The generic data stream collects responses from the EPR endpoint.

**ECS Field Reference**

Please refer to the following document for detailed information on ECS fields:
- [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html)

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| http.response.status_code | HTTP response status code. | long |

## Metrics

### Mock counter

The mock counter data stream generates synthetic counter metrics.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| counter.value | Incrementing counter value. | long |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
