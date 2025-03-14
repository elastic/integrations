# Splunk

[Splunk](https://www.splunk.com/) is a powerful platform that enables organizations to search, monitor, and analyze machine-generated data from various systems, applications, and security devices. It provides real-time insights to improve operations and detect issues quickly. Splunk Alerts are automated notifications triggered when specific conditions or thresholds are met within the data, such as performance anomalies or security threats. These alerts help organizations respond proactively by notifying users via email, webhooks, or other channels. Overall, Splunk enhances visibility and supports efficient troubleshooting and monitoring.

## Compatibility

This module has been tested against the Splunk API version **v2** and instance version **9.4.0**.

## Data streams

This integration collects the following logs:

- **Alerts** - This method enables users to retrieve alerts from the Splunk.

## Requirements

### Agentless Enabled Integration
Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based deployment

- Elastic Agent must be installed
- You can install only one Elastic Agent per host.
- Elastic Agent is required to stream data from the GCP Pub/Sub or REST API and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

#### Installing and managing an Elastic Agent:

There are several options for installing and managing Elastic Agent:

#### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

#### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

#### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

Please note, there are minimum requirements for running Elastic Agent. For more information, refer to the [Elastic Agent Minimum Requirements](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html#elastic-agent-installation-minimum-requirements).

## Setup

### To collect data from the Splunk API:

To collect data from the Splunk API, you will need the following information:

1. The username and password for the Splunk instance.
2. The name of the search index from which you want to retrieve the alerts.



### Enabling the integration in Elastic:

1. In Kibana navigate to Management > Integrations.
2. In "Search for integrations" top bar, search for `Splunk`.
3. Select the "Splunk" integration from the search results.
4. Select "Add Splunk" to add the integration.
5. Add all the required integration configuration parameters, including the URL, Username, Password, and Search Index, to enable data collection.
6. Select "Save and continue" to save the integration.

NOTE:
- The default search index for pulling data from Splunk is set to "notable".
- Enable SSL for the Splunk REST API to ensure secure communication when interacting with the API.

## Logs reference

### Alert

This is the `alert` dataset.

#### Example

{{event "alert"}}

{{fields "alert"}}
