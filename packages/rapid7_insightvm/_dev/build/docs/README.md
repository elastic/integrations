# Rapid7 InsightVM

## Overview

The [Rapid7 InsightVM](https://www.rapid7.com/products/insightvm/) integration allows users to monitor Asset and Vulnerability Events. Rapid7 InsightVM discovers risks across all your endpoints, cloud, and virtualized infrastructure. Prioritize risks and provide step-by-step directions to IT and DevOps for more efficient remediation. View your risk in real-time right from your dashboard. Measure and communicate progress on your program goals.

Use the Rapid7 InsightVM integration to collect and parse data from the REST APIs. Then visualize that data in Kibana.

## Data streams

The Rapid7 InsightVM integration collects two type of events: Asset and Vulnerability.

**Asset** is used to get details related to inventory, assessment, and summary details of assets that the user has access to. See more details in the API documentation [here](https://help.rapid7.com/insightvm/en-us/api/integrations.html#operation/searchIntegrationAssets).

**Vulnerability** is used to retrieve all vulnerabilities that can be assessed. See more details in the API documentation [here](https://help.rapid7.com/insightvm/en-us/api/integrations.html#operation/searchIntegrationVulnerabilities).

**Asset Vulnerability** is used to gather and aggregate data on assets and vulnerabilities to support Native CDR Workflows. 

## Requirements

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

### Agentless-enabled integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

This module uses **InsightVM Cloud Integrations API v4**.

## Setup

### To collect data from the Rapid7 InsightVM APIs, follow the below steps:

1. Generate the platform API key to access all Rapid7 InsightVM APIs. For more details, see [Documentation](https://docs.rapid7.com/insight/managing-platform-api-keys).

## Logs Reference

### asset

This is the `asset` dataset.

#### Example

{{event "asset"}}

{{fields "asset"}}

### asset_vulnerability

This is the `asset_vulnerability` dataset.

#### Example

{{event "asset_vulnerability"}}

{{fields "asset_vulnerability"}}

### vulnerability

This is the `vulnerability` dataset.

#### Example

{{event "vulnerability"}}

{{fields "vulnerability"}}