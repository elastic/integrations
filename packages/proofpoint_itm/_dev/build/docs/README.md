# Proofpoint Insider Threat Management (ITM)

[Proofpoint Insider Threat Management (ITM)](https://www.proofpoint.com/us/products/insider-threat-management) is a people-centric SaaS solution that helps you protect sensitive data from insider threats and data loss at the endpoint. It combines context across content, behavior and threats to provide you with deep visibility into user activities. Proofpoint ITM helps security teams tackle the challenges of detecting and preventing insider threats. It can streamline their responses to insider-led incidents and provide insights that help prevent further damage.

Use this integration to collect and parse data from your Proofpoint ITM instance.

## Compatibility

This module has been tested against the Proofpoint ITM API version **v2**.

## Data streams

This integration collects the following logs:

- **Reports** - This data stream enables users to retrieve reports from Proofpoint ITM, encompassing the below log types:
    1. User activity
    2. DBA activity
    3. System events
    4. Alerts activity
    5. Audit activity
    6. In-App elements

## Requirements

### Agentless Enabled Integration
Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent Based Installation
- Elastic Agent must be installed
- You can install only one Elastic Agent per host.
- Elastic Agent is required to stream data from the GCP Pub/Sub or REST API and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

#### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

#### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

#### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

#### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

## Setup

Follow the [ITM On-Prem (ObserveIT) API Portal](https://prod.docs.oit.proofpoint.com/configuration_guide/observeit_api_portal.htm) guide to setup the Proofpoint ITM On-Prem API Portal.

### Enabling the integration in Elastic:

1. In Kibana navigate to Management > Integrations.
2. In "Search for integrations" top bar, search for `Proofpoint ITM`.
3. Select the "Proofpoint ITM" integration from the search results.
4. Select "Add Proofpoint ITM" to add the integration.
5. Add all the required integration configuration parameters, including the URL, Token URL, Client ID, and Client type, to enable data collection.
6. Select "Save and continue" to save the integration.

## Logs reference

### Report

This is the `report` dataset.

#### Example

{{event "report"}}

{{fields "report"}}
