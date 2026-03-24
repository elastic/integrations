# Agentless Hello World

This is a sample integration designed to exercise the Agentless infrastructure. It periodically fetches data from `https://epr.elastic.co` every minute to demonstrate basic agentless functionality.

## Overview

The Agentless Hello World integration is a minimal example that:
- Fetches data from the Elastic Package Registry (EPR) endpoint
- Runs every 1 minute
- Requires no user configuration

## Configuration

This integration requires no configuration from the user. All settings are pre-configured:
- **Endpoint**: `https://epr.elastic.co`
- **Interval**: 1 minute
- **Deployment mode**: Agentless by default

## Data Collection

The integration makes HTTP GET requests to `https://epr.elastic.co` and stores:
- **status_code**: HTTP Status Code for the response.

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
| agentless_hello_world.generic.status_code | The HTTP Status Code of the response. | long |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
