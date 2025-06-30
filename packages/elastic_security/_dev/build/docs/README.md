# Elastic Security

## Overview

Elastic Security Alerts are triggered when detection rules identify suspicious or malicious activity. They provide detailed context like rule name, impacted entities, timestamps, and other necessary details. Alerts can be investigated in Kibana using tools like Timeline. They support custom actions such as notifications or automated responses. These alerts help prioritize and manage security threats efficiently.

## Data streams

This integration collects the following logs:

`alert`: - Retrieve alerts from Elastic Instance.

## Requirements

### Agentless-enabled integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

## Setup

### To collect data from the Elastic API:

To collect data from the Elastic API, you will need the following information:

1. The URL for the Elasticsearch instance.
2. Authentication credentials such as username, password, API key, or bearer token depend on the selected authentication type.

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search top bar, type **Elastic Security**.
3. Select the **Elastic Security** integration and add it.
4. Add all the required integration configuration parameters such as username, password, API key, or bearer token depend on the selected authentication type to enable data collection.
5. Select "Save and continue" to save the integration.

## Logs reference

### Alert

This is the `alert` dataset.

#### Example

{{event "alert"}}

{{fields "alert"}}