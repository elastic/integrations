# Qualys Global AssetView (GAV)

## Overview

[Qualys GAV](https://docs.qualys.com/en/gav/latest/) helps you to accurately assess complex IT infrastructure and quickly identify and remediate risk. Using a combination of Qualys sensors — Cloud Agents, scanners and passive network sensors — GAV collects and analyzes data about assets across hybrid environments, and delivers up-to-date, comprehensive and continuous information about those assets as well as their security and compliance posture.

The Qualys GAV integration collect assets via REST API.

## Data streams

The Qualys GAV integration collects logs of the following type:

1. **Asset:** This data stream will collect details of all assets.

>**Note**: For the **Asset** Dashboard, ensure that the time range is aligned with the configured interval parameter to display accurate and consistent data.

## Requirements

### Agentless-enabled integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

## Compatibility

For Rest API, this module has been tested against the **2.0** API version.

## Setup

### Collect data from the Qualys GAV API:

- The base URL corresponds to the API Gateway URL of the respective Qualys GAV instance. For reference, see: [Qualys Platform Identification](https://www.qualys.com/platform-identification/#:~:text=apps.qualysksa.com-,API%20URLs,-Use%20API%20Gateway).
- The same username and password used for logging into the Qualys instance are required for authentication when fetching logs through the integration.

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search top bar, type **Qualys GAV**.
3. Select the **Qualys GAV** integration and add it.
4. Add all the required integration configuration parameters: URL, Username and Password.
5. Save the integration.

## Logs reference

### Asset

This is the `Asset` dataset.

#### Example

{{event "asset"}}

{{fields "asset"}}