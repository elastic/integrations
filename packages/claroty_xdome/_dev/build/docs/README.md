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

**NOTE:**

1. The **alert data stream** combines data from the alerts and affected devices endpoints using a chain call. It first retrieves all alerts and then fetches affected devices for each alert ID.

2. The **vulnerability data stream** follows the same approach, retrieving vulnerabilities first and then fetching affected devices for each vulnerability ID.

3. A **data count mismatch** may appear in the **Discover** page for the vulnerability data stream. This occurs because the API retrieves data beyond the current date, while the **Elastic Agent** fetches only up-to-date data during the initial call. The missing data will appear in **Kibana** after the next interval's call.

## Requirements

### Agentless-enabled integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

## Setup

### Collect logs through REST API

Login to your Claroty xDome portal, create an API user from **Admin Settings** > **User Management**, and generate an API token.

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search bar, type **Claroty xDome**.
3. Select the **Claroty xDome** integration and add it.
4. Add all the required integration configuration parameters, including the URL, API token to enable data collection.
5. Save the integration.

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
