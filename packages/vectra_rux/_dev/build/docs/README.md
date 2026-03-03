# Vectra RUX

## Overview

[Vectra AI](https://www.vectra.ai/) is a provider of cybersecurity solutions, including threat detection and response solutions. Vectra AI also provides cloud security, detects ransomware, secures remote workplaces, hunts and investigates threats, and offers investigations, risk and compliance services.

This integration enables to collect, parse Audit, Detection Event, Entity Event, Health and Lockdown data via [Vectra RUX REST API](https://support.vectra.ai/vectra/article/KB-VS-1835), then visualise the data in Kibana.

## Data streams

The Vectra RUX integration collects logs for five types of events.

**Audit:** Audit allows collecting Audit Log Events, which are recorded whenever a user performs an action on the system. These events are sequential and provide a reliable audit trail of user activity.

**Detection Event:** Detection Event allows collecting Detection Events, which are generated upon the initial detection and each subsequent update.

**Entity Event:** Entity Event allows collecting Entity scoring events, which are generated whenever an entity's score changes, such as during initial threat detection, the discovery of additional detections, or updates to existing ones.

**Health:** Health allows collecting system health data, with API responses that may vary based on product subscriptions such as Network, AWS, or M365.

**Lockdown:** Lockdown allows collecting entities lockdown status for accounts and hosts type, that are currently in lockdown mode.

## Requirements

### Agentless enabled integration
Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent based installation
Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).
You can install only one Elastic Agent per host.
Elastic Agent is required to stream data from the GCP Pub/Sub or REST API and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

## Compatibility

For Rest API, this module has been tested against the **v3.4** version.  

## Setup

### To collect data from the Vectra RUX API:  

1. Navigate to **Manage > API Clients** in Vectra Console.
2. Click on **Add API Client**.
3. Add **Client Name**, **Description** and select the appropriate **Role** based on the endpoint, as outlined in the below table:
    | Endpoint               | Role               |
    | -----------------------| -------------------|
    | Audit                  | Auditor            |
    | Detection Event        | Read-Only          |
    | Entity Event           | Read-Only          |
    | Health                 | Auditor            |
    | Lockdown               | Read-Only          |  
4. Click **Generate Credentials**.
5. Copy **Client ID** and **Secret Key**.

For more details, see [Documentation](https://support.vectra.ai/vectra/article/KB-VS-1572).

### Enabling the integration in Elastic:

1. In Kibana navigate to Management > Integrations.
2. In "Search for integrations" top bar, search for `Vectra RUX`.
3. Select the "Vectra RUX" integration from the search results.
4. Select "Add Vectra RUX" to add the integration.
5. Add all the required integration configuration parameters, including the URL, Client ID, Client Secret, Interval, and Initial Interval, to enable data collection for REST API input type.
6. Select "Save and continue" to save the integration.

## Logs reference

### Audit

This is the `Audit` dataset.

#### Example

{{event "audit"}}

{{fields "audit"}}

### Detection Event

This is the `Detection Event` dataset.

#### Example

{{event "detection_event"}}

{{fields "detection_event"}}

### Entity Event

This is the `Entity Event` dataset.

#### Example

{{event "entity_event"}}

{{fields "entity_event"}}

### Health

This is the `Health` dataset.

#### Example

{{event "health"}}

{{fields "health"}}

### Lockdown

This is the `Lockdown` dataset.

#### Example

{{event "lockdown"}}

{{fields "lockdown"}}