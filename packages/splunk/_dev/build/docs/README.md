# Splunk

[Splunk](https://www.splunk.com/) is a powerful platform that enables organizations to search, monitor, and analyze machine-generated data from various systems, applications, and security devices. It provides real-time insights to improve operations and detect issues quickly. Splunk Alerts are automated notifications triggered when specific conditions or thresholds are met within the data, such as performance anomalies or security threats. These alerts help organizations respond proactively by notifying users via email, webhooks, or other channels. Overall, Splunk enhances visibility and supports efficient troubleshooting and monitoring.

## Compatibility

This module has been tested against the Splunk [API](https://docs.splunk.com/Documentation/Splunk/9.4.0/RESTREF/RESTsearch) version **v2** and instance version **9.4.0**.

## Data streams

This integration collects the following logs:

- **Alerts** - Retrieve alerts from Splunk.

## Requirements

### Elastic Managed enabled integration

Elastic Managed integrations are only supported on Elastic Cloud Serverless and Elastic Cloud Hosted deployments. An Elastic Managed integration lets you ingest data from a cloud source while avoiding the orchestration, management, and maintenance associated with standard ingest infrastructure. Elastic runs the collector for you, so you can focus on your data instead of the infrastructure that collects it.

For more information, refer to [Elastic Managed integrations](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations) and the [Elastic Managed integrations FAQ](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations-faq).

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

## Setup

### Collect data from the Splunk API

To collect data from the Splunk API, you need the following information:

- The username and password for the Splunk instance.
- The name of the search index from which you want to retrieve alerts, and the user should have permission to access that index.

### Enable the integration in Elastic

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search top bar, type **Splunk**.
3. Select the **Splunk** integration and add it.
4. Add all the required integration configuration parameters, including the URL, username, password, and Splunk Search String, to enable data collection.
5. Save the integration.

NOTE:
- Fetching alerts is only supported from the Splunk 'notable' index, which stores security findings.
- Enable SSL for the Splunk REST API to ensure secure communication when interacting with the API.

## Logs reference

### Alert

This is the `alert` dataset.

#### Example

{{event "alert"}}

{{fields "alert"}}

### Search

This is the `search` dataset.

#### Example

{{event "search"}}

{{fields "search"}}
