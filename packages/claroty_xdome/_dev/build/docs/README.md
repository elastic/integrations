# Claroty xDome

[Claroty xDome](https://claroty.com/industrial-cybersecurity/xdome) is a modular, SaaS-powered industrial cybersecurity platform designed to protect cyber-physical systems (CPS) in industrial, healthcare, and commercial environments, offering features like asset discovery, exposure management, network protection, threat detection, and secure access.

Use this integration to collect and parse data from your Claroty xDome instance.

## Compatibility

This module has been tested against the Claroty xDome API version **v1**.

## Data streams

The Claroty xDome integration collects three types of logs.

- **Alerts** - Retrieves alerts and their affected devices from Claroty xDome.

- **Events** - Collects events related to Operational Technology activities.

- **Vulnerabilities** - Retrieves vulnerabilities and their affected devices from Claroty xDome.

**Note** :

1. The **alert data stream** combines data from the alerts and affected devices endpoints using a chain call. It first retrieves all alerts and then fetches affected devices for each alert ID.

2. The **vulnerability data stream** follows the same approach, retrieving vulnerabilities first and then fetching affected devices for each vulnerability ID.

3. A **data count mismatch** may appear in the **Discover** page for the vulnerability data stream. This occurs because the API retrieves data beyond the current date, while the **Elastic Agent** fetches only up-to-date data during the initial call. The missing data will appear in **Kibana** after the next interval's call.

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

### To collect logs through REST API, follow the below steps:

- Login to your Claroty xDome portal, create an API user from Admin Settings > User Management, and generate an API token.

### Enabling the integration in Elastic:

1. In Kibana navigate to Management > Integrations.
2. In "Search for integrations" top bar, search for `Claroty xDome`.
3. Select the "Claroty xDome" integration from the search results.
4. Select "Add Claroty xDome" to add the integration.
5. Add all the required integration configuration parameters, including the URL, API token to enable data collection.
6. Select "Save and continue" to save the integration.

## Logs reference

### Alert

This is the `alert` dataset.

#### Example

An example event for `alert` looks as following:

{{event "alert"}}

#### Exported fields

{{fields "alert"}}

### Event

This is the `event` dataset.

#### Example

An example event for `event` looks as following:

{{event "event"}}

#### Exported fields

{{fields "event"}}

### Vulnerability

This is the `vulnerability` dataset.

#### Example

An example event for `vulnerability` looks as following:

{{event "vulnerability"}}

#### Exported fields

{{fields "vulnerability"}}
