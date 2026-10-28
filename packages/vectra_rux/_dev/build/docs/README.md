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

## Data retention

The data streams below collect a full snapshot of Vectra RUX health status on every polling interval, so their backing indices hold one copy of each record per interval.

The package bounds the growth of these source data streams with a retention that depends on the deployment type:

| Data stream | Self-managed and Elastic Cloud Hosted (ILM policy) | Serverless (data stream lifecycle) |
|---|---|---|
| `logs-vectra_rux.health-*` | `logs-vectra_rux.health-default_policy`: roll over after 30d, delete 30d after rollover | delete 30d after rollover |

On self-managed and Elastic Cloud Hosted deployments the ILM policy applies. The data stream lifecycle shipped with the package is not used there. ILM counts the delete age from the rollover of a backing index, so a document can remain for up to the rollover age plus the delete age. On Serverless, ILM is not available and the data stream lifecycle applies instead. It also works per backing index: Elasticsearch [rolls the write index over automatically](https://www.elastic.co/docs/reference/elasticsearch/configuration-reference/data-stream-lifecycle-settings#cluster-lifecycle-default-rollover) on age, size, or document count, and [deletes a backing index once the retention has passed since it rolled over](https://www.elastic.co/docs/manage-data/lifecycle/data-stream#data-streams-lifecycle-how-it-works). A document therefore stays for the retention plus up to one rollover interval. The rollover age is derived from the retention and is an implementation detail that Elasticsearch may change. Where the package installs a transform, the transform's destination indices are not affected by either.

To keep data for a different period:

- Self-managed and Elastic Cloud Hosted: edit the ILM policy in Kibana under **Stack Management → Index Lifecycle Policies**, or with `PUT _ilm/policy/<policy name>`. A package upgrade reinstalls the package's ILM policies, so check your change after upgrading.
- Serverless: set the retention on the data stream, for example `PUT _data_stream/logs-vectra_rux.health-default/_lifecycle` with the body `{"data_retention": "90d"}`. Replace `default` with your namespace.

## Requirements

### Elastic Managed enabled integration
Elastic Managed integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Elastic Managed integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Elastic Managed integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Elastic Managed deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

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