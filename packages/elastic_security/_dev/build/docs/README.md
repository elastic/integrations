# Elastic Security

## Overview

[Elastic Security](https://www.elastic.co/security) is a free and open solution that helps detect, investigate, and respond to threats using data from endpoints, cloud, and network sources. It offers SIEM and endpoint protection with powerful search, correlation, and visualization features in Kibana.
It enables security teams to streamline investigations and strengthen their overall security posture.

## Data streams

The Elastic Security integration collects the following events:

`alert`: - Retrieve alerts from Elasticsearch Instance using Elasticsearch [_search](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-search-2) API.

## Requirements

### Elastic Managed enabled integration

Elastic Managed integrations are only supported on Elastic Cloud Serverless and Elastic Cloud Hosted deployments. An Elastic Managed integration lets you ingest data from a cloud source while avoiding the orchestration, management, and maintenance associated with standard ingest infrastructure. Elastic runs the collector for you, so you can focus on your data instead of the infrastructure that collects it.

For more information, refer to [Elastic Managed integrations](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations) and the [Elastic Managed integrations FAQ](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations-faq).

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

1. In the top search bar in Kibana, search for **Integrations**.
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