# Proofpoint Insider Threat Management (ITM)

[Proofpoint Insider Threat Management (ITM)](https://www.proofpoint.com/us/products/insider-threat-management) is a people-centric SaaS solution that helps you protect sensitive data from insider threats and data loss at the endpoint. It combines context across content, behavior and threats to provide you with deep visibility into user activities. Proofpoint ITM helps security teams tackle the challenges of detecting and preventing insider threats. It can streamline their responses to insider-led incidents and provide insights that help prevent further damage.

Use this integration to collect and parse data from your Proofpoint ITM instance.

## Compatibility

This module has been tested against the Proofpoint ITM API version **v2**.

## Data streams

This integration collects the following logs:

- **Reports** - This data stream enables users to retrieve reports from Proofpoint ITM, including the following log types:

- User activity
- DBA activity
- System events
- Alerts activity
- Audit activity
- In-App elements

## Requirements

### Agentless-enabled integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

## Setup

Follow the [ITM On-Prem (ObserveIT) API Portal](https://prod.docs.oit.proofpoint.com/configuration_guide/observeit_api_portal.htm) guide to setup the Proofpoint ITM On-Prem API Portal.

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search top bar, type **Proofpoint ITM**.
3. Select the **Proofpoint ITM** integration and add it.
4. Add all the required integration configuration parameters: URL, Token URL, Client ID, and Client type.
5. Save the integration.

## Logs reference

### Report

This is the `report` dataset.

#### Example

{{event "report"}}

{{fields "report"}}
