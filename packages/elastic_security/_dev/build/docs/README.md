# Elastic Security

## Overview

[Elastic Security](https://www.elastic.co/security) is a free and open solution that helps detect, investigate, and respond to threats using data from endpoints, cloud, and network sources. It offers SIEM and endpoint protection with powerful search, correlation, and visualization features in Kibana.
It enables security teams to streamline investigations and strengthen their overall security posture.

## Data streams

The Elastic Security integration collects the following events:

`alert`: - Retrieve alerts from Elasticsearch Instance using Elasticsearch [_search](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-search-2) API.

## Requirements

### Agentless-enabled integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

## Setup

### To collect data from the Elastic API:

You will need the following information:

1. The URL for the Elasticsearch instance.
2. Authentication credentials such as username, password, API key, or bearer token depending on the selected authentication type.

Note:
1. Users must have `read` index privileges on the `.alerts-security.alerts-<space_id>` indices to access and query security alerts.
2. To learn how to create authentication credentials and use the appropriate authentication type, refer to the Elasticsearch Authentication [Documentation](https://www.elastic.co/docs/deploy-manage/users-roles/cluster-or-deployment-auth/user-authentication).

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search top bar, type **Elastic Security**.
3. Select the **Elastic Security** integration and add it.
4. Add all the required integration configuration parameters such as username, password, API key, or bearer token depending on the selected authentication type to enable data collection.
5. Select "Save and continue" to save the integration.

## Logs reference

### Alert

This is the `alert` dataset.

#### Example

{{event "alert"}}

{{fields "alert"}}