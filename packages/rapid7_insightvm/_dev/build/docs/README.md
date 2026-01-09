# Rapid7 InsightVM

## Overview

The [Rapid7 InsightVM](https://www.rapid7.com/products/insightvm/) integration allows users to monitor Asset and Vulnerability Events. Rapid7 InsightVM discovers risks across all your endpoints, cloud, and virtualized infrastructure. Prioritize risks and provide step-by-step directions to IT and DevOps for more efficient remediation. View your risk in real-time right from your dashboard. Measure and communicate progress on your program goals.

Use the Rapid7 InsightVM integration to collect and parse data from the REST APIs. Then visualize that data in Kibana.

## Data streams

The Rapid7 InsightVM integration collects two type of events: Asset and Vulnerability.

**Asset (Deprecated)** is used to get details related to inventory, assessment, and summary details of assets that the user has access to. See more details in the API documentation [here](https://help.rapid7.com/insightvm/en-us/api/integrations.html#operation/searchIntegrationAssets). It is deprecated in version `2.0.0`. Instead, use the `Asset Vulnerability` data stream for enriched vulnerability documents and improved mappings.

**Asset Vulnerability** is used to gather and aggregate data on assets and vulnerabilities to support Native CDR Workflows.

**Vulnerability** is used to retrieve all vulnerabilities that can be assessed. See more details in the API documentation [here](https://help.rapid7.com/insightvm/en-us/api/integrations.html#operation/searchIntegrationVulnerabilities).

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

## Troubleshooting

### Breaking Changes

#### Support for Elastic Vulnerability Findings page.

Version `2.0.0` of the Rapid7 InsightVM integration adds support for [Elastic Cloud Security workflow](https://www.elastic.co/docs/solutions/security/cloud/ingest-third-party-cloud-security-data#_ingest_third_party_security_posture_and_vulnerability_data). The enhancement enables the users of Rapid7 InsightVM integration to ingest their enriched asset vulnerabilities from Rapid7 InsightVM platform into Elastic and get insights directly from Elastic [Vulnerability Findings page](https://www.elastic.co/docs/solutions/security/cloud/findings-page-3).
This update adds [Elastic Latest Transform](https://www.elastic.co/docs/explore-analyze/transforms/transform-overview#latest-transform-overview) which copies the latest vulnerability findings from source indices matching the pattern `logs-rapid7_insightvm.asset_vulnerability-*` into new destination indices matching the pattern `security_solution-rapid7_insightvm.vulnerability_latest-*`. The Elastic Vulnerability Findings page will display vulnerabilities based on the destination indices.

For existing users of Rapid7 InsightVM integration, before upgrading to `2.0.0` please ensure following requirements are met:

1. Users need [Elastic Security solution](https://www.elastic.co/docs/solutions/security) which has requirements documented [here](https://www.elastic.co/docs/solutions/security/get-started/elastic-security-requirements).
2. To use transforms, users must have:
   - at least one [transform node](https://www.elastic.co/docs/deploy-manage/distributed-architecture/clusters-nodes-shards/node-roles#transform-node-role),
   - management features visible in the Kibana space, and
   - security privileges that:
     - grant use of transforms, and
     - grant access to source and destination indices
   For more details on Transform Setup, refer to the link [here](https://www.elastic.co/docs/explore-analyze/transforms/transform-setup)
3. Because the latest copy of vulnerabilities is now indexed in two places, i.e., in both source and destination indices, users must anticipate storage requirements accordingly.

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